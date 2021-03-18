//!  Non interactive zero knowledge proof for Paillier and square-free N, as described in *"Efficient Noninteractive Certification
//!  of RSA Moduli and Beyond"*, chapter 3.2, [`link`](https://eprint.iacr.org/2018/057.pdf) .
//!
//!  The Paillier cryptosystem requires a modulus $`N`$ to be relatively prime to $`\phi(N)`$, which is proven in ZK by taking $`N`$th roots of several random points.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NIZKError {
    #[error("NIZK proof: wrong size")]
    WrongSizeOFProof,
    #[error("NIZK proof: incorrect rho")]
    IncorrectRho,
    #[error("NIZK proof: failer")]
    FailedProof,
    #[error("NIZK proof: N can be too small: {0} ")]
    WrongSizeOfN(usize),
}

use std::ops::Shl;

use crate::algorithms::sha::HSha512Trunc256;
use crate::ecdsa::PRIME_BIT_LENGTH_IN_PAILLIER_SCHEMA;
use curv::cryptographic_primitives::hashing::traits::Hash;
use paillier::{extract_nroot, BigInt, DecryptionKey, EncryptionKey};
use std::borrow::Borrow;
use std::convert::TryFrom;

/// Initializes the PRNG used for random sampling of points in the algorithm
/// with the sequence of decimal digits found somewhere in Pi:
///
/// 459561513849871375704710178795731042296906667021449863746459528082436944578977
///
///
const SALT: &str = "459561513849871375704710178795731042296906667021449863746459528082436944578977";

/// Parameters are as suggested in 6.2.3 of [link](https://eprint.iacr.org/2018/987.pdf)
pub(crate) const M2: usize = 11;

/// Corresponds to $`\alpha = 6370 `$ (as in the whitepaper)
const PRIMORIAL: &str = r#"448716517440091362481155430816405474137858544178420501606558338757929148338527
6920583142497936871998688951925693423945243825110873867021729854218098254742100790101940815596194014
2468907900676141149633188172029947498666222471142795699128314649438784106402197023949268047384343715
9460067676713193884639223667035857084601354532406794210613048646099158279088960623501386338495149058
5837333952808600614537371243175674690546793523293539895122685207132377541227876337108940154492087381
3490290672436809231516731065356763193493525160238868779310055137922174496115680527519932793977258424
4792539736701036340700288635912076146492164927808919610542874218310282292669896970583856120035578253
9820254865791098393148418019329361517559492589592935910872367121263136889168946248696802202948241391
2928883488902454913524492340322599922718890878760895105937402913873414377276608236656947832307175090
5053966756235059556073636838691946836356897012383115779539949007344984067031769543244946944745455708
3936060792661024809345273981761409719703160782041772900984746513838839888786193512778538530956452564
8905444610640901769290645369888935446477559073843982605496992468605588284307311971153579731703863970
6744666668448173363193906175513548450251163502950418400936278360673701003848618208887523585202760410
0045660805633937757348591744510475798780010165968818315032044230809183597418280918429947256826068277
4683272697993855730500061223160274918361373258473553412704497335663924406111413972911417644029226449
6024171351160119689462326231540087102712961833502155639460035475610564562859396768386233113700872382
2563099450611342292284657261653863772305422216615938947561721468128287437318528356851260388775084607
2033376432252677883915884203823739988948315257311383912016966925295975180180438969999175030785077627
4588874111464869026132912020081939029798002796375097895648075022396867557270633670757584928237317246
6970244245050266781089060880709144868898520308497203519777087422325942064905545038272535516273849035
5628688943706634905982449810389530661328557381850782677221561924983234877936783136471890539395124220
9659828317788824002241566894871372271980304616245428727742177715942159072037256823157141992495888742
7166123392971366026988327340476464832745579669936690002234517103056474721054239828507880431075206385
2249740561571105640741618793118627170070315410588646442647771802031066589341358879304845579387079972
4043864342382739042396046035119257083770084671295906362572879652325763275800090184752713642376658361
8680602733120842625645142954964198838658594930025448764739522278527412056129931807094453009697007656
0461229486504018773252771360855091191876004370694539453020462096690084476681253865429278552786361828
508910022714749051734108364178374765700925133405508684883070"#;

/// The output size of the hash function used in the algorithm
const DIGEST_SIZE: usize = 256;

///the lower bound for the bit size of modulo N
///
/// Paillier crate generates primes with both MSB and LSB set to 1,
/// hence lower bound of the product of primes  is $` (2^{(prime\_size-1)} + 1)^2 `$ ,  where small terms can be ignored
/// so that resulting bit size is in $`[( 2 * prime\_size -1 ).. (2 * prime\_size) ] `$
pub(crate) const N_MIN_SIZE: usize = 2 * PRIME_BIT_LENGTH_IN_PAILLIER_SCHEMA - 1;

/// generates the vector of $` \rho_{i} `$ of size M2
///
/// implements rejection sampling algorithm for $`\rho`$ as described in the [whitepaper](https://eprint.iacr.org/2018/057.pdf) , section C.4
pub fn get_rho_vec(n: &BigInt) -> Vec<BigInt> {
    let one = BigInt::one();
    let key_length = n.bit_length();
    let salt = BigInt::from_str_radix(SALT, 10).expect("not a decimal number");

    (0..M2 as u64)
        .map(|i| {
            (1u64..1000) // this upper limit should be never hit normally, unless gen_mask() is changed to return numbers too big
                .map(|j| {
                    let s = hash(&[&n, &salt, &BigInt::from(i), &BigInt::from(j)]);
                    gen_mask(key_length, &s)
                })
                .find(|rho| !rho.is_zero() && rho < n && rho.gcd(n) == one)
                .expect("cant find rho")
        })
        .collect::<Vec<_>>()
}

/// generates non-interactive proof of correctness of public Paillier key
pub fn gen_proof(dk: &DecryptionKey) -> Vec<BigInt> {
    let n = dk.q.borrow() * dk.p.borrow();

    let result = get_rho_vec(&n)
        .into_iter()
        .map(|rho| extract_nroot(&dk, &rho))
        .collect();
    result
}

/// Verifies non-interactive proof of correctness of public Paillier key.
/// Checks also whether given public key has expected bit size
pub fn verify(encryption: &EncryptionKey, sigmas: &[BigInt]) -> Result<(), NIZKError> {
    if sigmas.len() != M2 {
        return Err(NIZKError::WrongSizeOFProof);
    }

    let n = &encryption.n;
    let bit_length_of_n = n.bit_length();

    if bit_length_of_n < N_MIN_SIZE {
        return Err(NIZKError::WrongSizeOfN(bit_length_of_n));
    }

    let rho_correct = sigmas
        .iter()
        .zip(get_rho_vec(n).into_iter())
        .all(|(sigma, rho)| rho == sigma.powm_sec(n, n));
    if !rho_correct {
        return Err(NIZKError::IncorrectRho);
    }
    check_divisibility(&n)
}

pub fn check_divisibility(n: &BigInt) -> Result<(), NIZKError> {
    let alpha_primorial = str::parse::<BigInt>(&PRIMORIAL).unwrap();
    let gcd_test = alpha_primorial.gcd(&n);
    if gcd_test == BigInt::one() {
        Ok(())
    } else {
        Err(NIZKError::FailedProof)
    }
}
/// produces the hash value of the concatenation of `BigInt` numbers
fn hash(bigints: &[&BigInt]) -> BigInt {
    HSha512Trunc256::create_hash(bigints)
}

/// Mask generation function, as described in [rfc8017](https://tools.ietf.org/html/rfc8017/#appendix-B.2.1), section B.2.1
///
/// For counter from 0 to $` \lceil \frac{mask\_length}{DIGEST\_SIZE} \rceil - 1`$, and output T as empty string, do T = T || Hash(seed || counter)
///
/// Note that $` \lceil \frac{mask\_length}{DIGEST\_SIZE} \rceil - 1 = \lfloor \frac{mask\_length-1}{DIGEST\_SIZE} \rfloor `$
fn gen_mask(mask_length: usize, seed: &BigInt) -> BigInt {
    let counter =
        u64::try_from((mask_length - 1) / DIGEST_SIZE).expect("gen_mask: parameters too large");

    (0..=counter)
        .map(|i| hash(&[&seed, &BigInt::from(i)]))
        .fold(BigInt::zero(), |acc, v| acc.shl(DIGEST_SIZE) + v)
}

#[cfg(test)]
mod tests {
    use paillier::KeyGeneration;
    use paillier::Paillier;

    use super::*;
    use crate::ecdsa::PRIME_BIT_LENGTH_IN_PAILLIER_SCHEMA;

    #[test]
    fn test_correct_zk_proof() -> Result<(), NIZKError> {
        let (encryption, decryption) =
            Paillier::keypair_with_modulus_size(2 * PRIME_BIT_LENGTH_IN_PAILLIER_SCHEMA).keys();
        for _ in 0..=10 {
            let proof = gen_proof(&decryption);
            verify(&encryption, &proof)?
        }
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_key_size() {
        for _ in 0..10 {
            let (encryption, _) =
                Paillier::keypair_with_modulus_size(2 * PRIME_BIT_LENGTH_IN_PAILLIER_SCHEMA).keys();
            let x = encryption.n.bit_length();
            assert!(x >= N_MIN_SIZE);
        }
    }
}
