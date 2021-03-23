//!  Multiparty threshold signature scheme
//!
//!  MPC TS scheme, as defined in ["Fast multiparty threshold ECDSA with Fast trustless setup"](https://eprint.iacr.org/2019/114.pdf)
//!
//!  The module implements following algorithms:
//! * Key generation
//! * Signing
//! * key refresh or re-sharing
//!
use crate::ecdsa::keygen::KeygenError;
use crate::protocol::PartyIndex;
use curv::arithmetic::traits::{Samplable, ZeroizeBN};
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};
use paillier::{
    is_prime, Decrypt, DecryptionKey, EncryptionKey, KeyGeneration, Paillier, RawCiphertext,
    RawPlaintext,
};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::sync::atomic;
use trace::trace;
use zeroize::Zeroize;

pub mod keygen;
pub mod messages;
pub mod resharing;
pub mod signature;

/// Parameters associated with shared key in threshold schema
///
/// # Key Attributes
///
/// * `share count` - number of parties which hold shards of the key
/// * `threshold` - number of parties required to produce a signature minus 1 so that $` \min N_{required} = threshold + 1 `$  
#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
pub struct Parameters {
    threshold: usize,   //t
    share_count: usize, //n
}

impl Parameters {
    /// Constructs new Parameters conditioned they satisfy `2 <= min_signers <= share_count`.
    ///
    /// Parameters are used for Shamir secret sharing, so that the threshold sharing parameter
    /// is equal to the degree of the polynomial used in sharing.
    ///
    /// That is, `threshold` = `min_signers` - 1
    /// Refer to <https://eprint.iacr.org/2019/114.pdf>
    pub fn new(min_signers: usize, share_count: usize) -> Result<Self, KeygenError> {
        if share_count < 2 {
            return Err(KeygenError::IncorrectParameters(format!(
                "Number of shares must be at least 2, got {}",
                share_count
            )));
        }
        // share_count >= 2

        if min_signers < 2 {
            return Err(KeygenError::IncorrectParameters(format!(
                "Number of signers must be at least 2, got: {}",
                min_signers
            )));
        }
        // min_signers >= 2

        if min_signers > share_count {
            return Err(KeygenError::IncorrectParameters(format!(
                "Number of signers {} cannot be greater than number of shares {}",
                min_signers, share_count
            )));
        }

        //
        // 1 <= min_signers - 1 = threshold < share_count

        Ok(Parameters {
            threshold: min_signers - 1,
            share_count,
        })
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn share_count(&self) -> usize {
        self.share_count
    }

    pub fn signers(&self) -> usize {
        self.threshold + 1
    }
}

impl fmt::Display for Parameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{threshold: {}, share_count: {}}}",
            self.threshold, self.share_count
        )
    }
}

pub type MessageHashType = FE;

///  Initial values for signing algorithm
///
///  The signing algorithm starts knowing `PartyIndexes` of participants and the hash of the message
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SigningParameters {
    pub keygen_params: Parameters,
    pub signing_parties: BTreeSet<PartyIndex>,
    pub message_hash: MessageHashType,
}

impl SigningParameters {
    pub fn signing_party_count(&self) -> usize {
        self.signing_parties.len()
    }
}

/// Public/private key pairs used by a party during key generation for one given shared key
///
/// Public/private key pair `u_i,y_i` for the EC schema, and Public/private `paillier_keys` for homomorphic encryption schema.
///
/// Note that EC schema keys $` u_{i}, y_{i} `$ become obsolete after the round of Shamir's sharing so that they have to be erased.
/// Unlike these keys, Paillier keys will be used later in the signing protocol, therefore if the struct `InitialKeys` is about to be dropped or erased explicitly, Paillier keys must be copied to another location beforehand.  
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct InitialKeys {
    pub u_i: FE,
    pub y_i: GE,
    pub paillier_keys: PaillierKeys,
}

impl Display for InitialKeys {
    /// hides private key `u_i`
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitialKeys")
            .field("u_i", &"[***]".to_owned())
            .field("y_i", &self.y_i)
            .field("paillier keys", &self.paillier_keys)
            .finish()
    }
}

impl Debug for InitialKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// Truncated version of `InitialKeys`, without secret part of each key
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct InitialPublicKeys {
    pub y_i: GE,
    pub paillier_encryption_key: EncryptionKey,
}

impl InitialPublicKeys {
    pub fn from(keys: &InitialKeys) -> Self {
        Self {
            y_i: keys.y_i,
            paillier_encryption_key: keys.paillier_keys.ek.clone(),
        }
    }
}

fn is_valid_curve_point(pk: curv::PK) -> bool {
    curv::PK::from_slice(&pk.serialize_uncompressed()).is_ok()
}

fn from_secp256k1_pk(pk: curv::PK) -> Result<GE, curv::ErrorKey> {
    let bytes = pk.serialize_uncompressed();
    GE::from_bytes(&bytes[1..])
}

/// Public/private key pair for additive homomorphic encryption schema
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PaillierKeys {
    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
}

impl Zeroize for PaillierKeys {
    fn zeroize(&mut self) {
        self.dk.p.zeroize_bn();
        self.dk.q.zeroize_bn();
        self.ek.n.zeroize_bn();
        self.ek.nn.zeroize_bn();
    }
}

impl Drop for PaillierKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl PaillierKeys {
    /// initializes with zeros
    pub fn zero() -> Self {
        Self {
            dk: DecryptionKey {
                p: BigInt::zero(),
                q: BigInt::zero(),
            },
            ek: EncryptionKey {
                n: BigInt::zero(),
                nn: BigInt::zero(),
            },
        }
    }

    /// produces new Paiiliier key pair    
    pub fn random() -> Self {
        let (ek, dk) =
            Paillier::keypair_with_modulus_size(2 * PRIME_BIT_LENGTH_IN_PAILLIER_SCHEMA).keys();
        Self { ek, dk }
    }

    /// decrypts given value `c`
    pub fn decrypt(&self, c: BigInt) -> RawPlaintext {
        Paillier::decrypt(&self.dk, &RawCiphertext::from(c))
    }

    /// checks whether Paillier's setup is valid and consistent
    #[trace(pretty, prefix = "PaillierKeys::")]
    pub fn is_valid(ek: &EncryptionKey, dk: &DecryptionKey) -> bool {
        // TODO : report back specific errors
        is_prime(&dk.p)
            && is_prime(&dk.q)
            && ek.n == dk.p.borrow() * dk.q.borrow()
            && ek.nn == ek.n.pow(2)
    }
}

impl Display for PaillierKeys {
    /// hides private key of the schema
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaillierKeys")
            .field("dk", &"[***]".to_owned())
            .field("ek", &self.ek)
            .finish()
    }
}

impl Debug for PaillierKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

struct ManagedPaillierDecryptionKey(Box<DecryptionKey>);

impl Drop for ManagedPaillierDecryptionKey {
    fn drop(&mut self) {
        self.0.p = BigInt::zero();
        self.0.q = BigInt::zero();
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

struct ManagedSecretKey(Box<FE>);

impl Drop for ManagedSecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

///current recommended bit size for the primes in Paillier schema
pub(crate) const PRIME_BIT_LENGTH_IN_PAILLIER_SCHEMA: usize = 1024;

/// The result of ECDSA signing algorithm
///
/// The signature the schema with
///
/// * cyclic group $` \mathcal{G} `$ of prime order $`q`$ and generator $` g `$
/// * message $` m `$ , private key $` x `$
/// * mapping $` F : \mathcal{G} \to \mathbb{Z}_q `$, hash function $` H(t) `$
/// * random  $` k \in \mathbb{Z}_{q} `$
///
/// The signature contains
/// ```math
///    r = F(g^k) , \space s = k^{-1}(H(m) + x r) \mod q
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub r: FE,
    pub s: FE,
}

impl Signature {
    /// verifies the signature using public key and the hash of the message
    pub fn verify(&self, pubkey: &GE, message: &MessageHashType) -> bool {
        if self.s == FE::zero() || self.r == FE::zero() {
            false
        } else {
            let g: GE = ECPoint::generator();

            let s_invert = self.s.invert();
            let u1 = (*message) * s_invert;
            let u2 = self.r * s_invert;

            self.r
                == ECScalar::from(
                    &(g * u1 + pubkey * &u2)
                        .x_coor()
                        .unwrap()
                        .mod_floor(&FE::q()),
                )
        }
    }
}

///  Non-malleable commitment scheme
///
/// Commitment scheme based on hash commitment
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommitmentScheme {
    pub comm: BigInt,
    pub decomm: BigInt,
}

impl CommitmentScheme {
    /// creates commitment scheme from EC group element
    #[allow(non_snake_case)]
    fn from_GE(elem: &GE) -> Self {
        let decomm = BigInt::sample(256);
        let comm = HashCommitment::create_commitment_with_user_defined_randomness(
            &elem.bytes_compressed_to_big_int(),
            &decomm,
        );
        CommitmentScheme { comm, decomm }
    }

    /// creates commitment scheme from `BigInt`
    #[allow(non_snake_case)]
    fn from_BigInt(message: &BigInt) -> Self {
        let decomm = BigInt::sample(256);
        let comm = HashCommitment::create_commitment_with_user_defined_randomness(message, &decomm);
        CommitmentScheme { comm, decomm }
    }

    /// verifies commitment using EC group element
    fn verify_commitment(&self, elem: GE) -> bool {
        is_valid_curve_point(elem.get_element())
            && HashCommitment::create_commitment_with_user_defined_randomness(
                &elem.bytes_compressed_to_big_int(),
                &self.decomm,
            ) == self.comm
    }

    /// verifies commitment using `BigInt` value
    fn verify_hash(&self, hash: &BigInt) -> bool {
        HashCommitment::create_commitment_with_user_defined_randomness(&hash, &self.decomm)
            == self.comm
    }
}

/// returns true if all elements of the collections are equal or the collection is empty
///
/// Service function used to verify that each public key in key generation schema is the same.
pub fn all_equal<It>(mut it: It) -> bool
where
    It: Iterator + Sized,
    It::Item: PartialEq,
{
    match it.next() {
        None => true,
        Some(a) => it.all(|x| a == x),
    }
}
/// returns true if all elements of a collection mapped through f() are equal
pub fn all_mapped_equal<It, F, V>(mut it: It, f: F) -> bool
where
    It: Iterator + Sized,
    F: Fn(It::Item) -> V,
    V: PartialEq,
{
    match it.next() {
        None => true,
        Some(item) => {
            let v = f(item);
            it.map(f).all(|vv| v == vv)
        }
    }
}

/// return true if every element of the collection beta is in the collection alpha  ( beta is subset of alpha  )
/// both collection have to be sorted beforehand
/// returns true if beta is empty
pub fn is_beta_subset_of_alpha<It>(mut alpha_it: It, mut beta_it: It) -> bool
where
    It: Iterator,
    It::Item: Copy + PartialOrd,
{
    if let Some(b) = beta_it.next() {
        while let Some(a) = alpha_it.next() {
            if a > b {
                return false;
            }
            if a == b {
                return is_beta_subset_of_alpha(alpha_it, beta_it);
            }
        }
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use crate::ecdsa::{is_beta_subset_of_alpha, is_valid_curve_point};
    use curv::arithmetic::traits::Converter;
    use curv::arithmetic::traits::Samplable;
    use curv::elliptic::curves::traits::ECPoint;
    use curv::elliptic::curves::traits::ECScalar;
    use curv::{BigInt, FE, GE};

    fn xy_to_key_slice(x: &BigInt, y: &BigInt) -> Vec<u8> {
        let mut v = vec![4 as u8];
        let mut raw_x: Vec<u8> = Vec::new();
        let mut raw_y: Vec<u8> = Vec::new();

        let x_vec = BigInt::to_vec(x);
        let y_vec = BigInt::to_vec(y);
        raw_x.extend(vec![0u8; 32 - x_vec.len()]);
        raw_x.extend(x_vec);

        raw_y.extend(vec![0u8; 32 - y_vec.len()]);
        raw_y.extend(y_vec);

        v.extend(raw_x);
        v.extend(raw_y);
        v
    }

    #[test]
    fn pk_utilities() {
        let pk = GE::random_point().get_element();

        let bytes = pk.serialize_uncompressed();
        let ppk = curv::PK::from_slice(&bytes);
        assert!(ppk.is_ok());
        let ppk = ppk.unwrap();
        assert_eq!(pk, ppk);

        assert!(is_valid_curve_point(GE::random_point().get_element()));

        let xpk = xy_to_key_slice(
            &BigInt::sample_below(&FE::q()),
            &BigInt::sample_below(&FE::q()),
        );

        let xppk = curv::PK::from_slice(xpk.as_slice());
        assert!(xppk.is_err());
    }

    #[test]
    fn pk_conversion() {
        let pk = GE::random_point().get_element();
        let bytes = pk.serialize_uncompressed();
        let ge = GE::from_bytes(&bytes[1..]);
        assert!(ge.is_ok());
        let ge = ge.unwrap();
        assert_eq!(pk, ge.get_element());
    }

    #[test]
    fn test_subsets() {
        let alpha = vec![1, 2, 3, 5, 6, 7];

        assert!(is_beta_subset_of_alpha(alpha.iter(), vec![].iter()));
        assert!(is_beta_subset_of_alpha(alpha.iter(), vec![1].iter()));
        assert!(is_beta_subset_of_alpha(alpha.iter(), vec![2].iter()));
        assert!(is_beta_subset_of_alpha(alpha.iter(), vec![1, 2, 3].iter()));
        assert!(is_beta_subset_of_alpha(
            alpha.iter(),
            vec![1, 2, 3, 5].iter()
        ));
        assert!(is_beta_subset_of_alpha(
            alpha.iter(),
            vec![2, 3, 5, 6].iter()
        ));
        assert!(is_beta_subset_of_alpha(
            alpha.iter(),
            vec![3, 5, 6, 7].iter()
        ));
        assert!(!is_beta_subset_of_alpha(
            alpha.iter(),
            vec![0, 1, 2, 3].iter()
        ));
        assert!(!is_beta_subset_of_alpha(
            alpha.iter(),
            vec![1, 2, 3, 4].iter()
        ));
        assert!(!is_beta_subset_of_alpha(
            alpha.iter(),
            vec![2, 3, 4, 5].iter()
        ));
        assert!(!is_beta_subset_of_alpha(alpha.iter(), vec![4].iter()));
        assert!(!is_beta_subset_of_alpha(alpha.iter(), vec![4, 5].iter()));
    }
}
