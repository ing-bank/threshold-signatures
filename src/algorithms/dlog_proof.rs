use crate::algorithms::sha::HSha512Trunc256;
use curv::arithmetic::traits::Samplable;

use crate::algorithms::BigInt;

use crate::Modulo;
use crate::{BasicOps, Converter};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use zeroize::Zeroize;

pub const DIGEST_BIT_LENGTH: u32 = HSha512Trunc256::DIGEST_BIT_LENGTH as u32;
pub const ING_TSS_DLOG: &str = "ING TS dlog proof sub-protocol v1.0";
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlogProof {
    y: BigInt,
    c: BigInt,
}

/// Signature scheme for DL proof in a composite group with unknown modulo
///
/// "Composite discrete logarithm and secure authentication" , D. Pointcheval , pp 3.2
#[allow(clippy::many_single_char_names)]
impl DlogProof {
    pub fn create(
        N: &BigInt,
        g: &BigInt,
        V: &BigInt,
        s: &BigInt,
        max_secret_length: u32,
        security_param: u32,
    ) -> Self {
        let log_r = max_secret_length + DIGEST_BIT_LENGTH + security_param;
        let R = BigInt::from(2i32).pow(log_r);
        let mut r = BigInt::sample_below(&R);
        let x = BigInt::mod_pow(g, &r, N);
        let salt = BigInt::from_bytes(ING_TSS_DLOG.as_bytes());
        let c = HSha512Trunc256::create_hash(&[&salt, N, g, V, &x]);

        let y = r.borrow() - c.borrow() * s;
        r.zeroize();
        Self { y, c }
    }

    pub fn verify(&self, N: &BigInt, g: &BigInt, V: &BigInt) -> bool {
        let x = BigInt::mod_pow(g, &self.y, N) * BigInt::mod_pow(V, &self.c, N) % N;
        let salt = BigInt::from_bytes(ING_TSS_DLOG.as_bytes());
        let c = HSha512Trunc256::create_hash(&[&salt, N, g, V, &x]);

        c == self.c
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithms::dlog_proof::{DlogProof, DIGEST_BIT_LENGTH};
    use crate::algorithms::zkp::{ZkpSetup, DEFAULT_GROUP_ORDER_BIT_LENGTH};
    use curv::arithmetic::BitManipulation;

    #[test]
    fn check_bitness() {
        let setup = ZkpSetup::random(DEFAULT_GROUP_ORDER_BIT_LENGTH);

        let security_param = 64u32;
        let max_secret_length = setup.phi().bit_length() as u32;

        let proof = DlogProof::create(
            &setup.N_tilde,
            &setup.h1,
            &setup.h2,
            setup.alpha(),
            max_secret_length,
            security_param,
        );

        assert!(
            proof.y.bit_length()
                <= (max_secret_length + security_param + DIGEST_BIT_LENGTH) as usize
        );
        assert!(proof.c.bit_length() <= DIGEST_BIT_LENGTH as usize);
    }
    #[test]
    fn validate() {
        (0..10).for_each(|_| {
            let setup = ZkpSetup::random(DEFAULT_GROUP_ORDER_BIT_LENGTH);

            let security_param = 64u32;
            let max_secret_length = setup.phi().bit_length() as u32;

            let proof = DlogProof::create(
                &setup.N_tilde,
                &setup.h1,
                &setup.h2,
                setup.alpha(),
                max_secret_length,
                security_param,
            );
            assert!(proof.verify(&setup.N_tilde, &setup.h1, &setup.h2))
        });
    }
}
