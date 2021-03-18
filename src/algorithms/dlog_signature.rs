use crate::algorithms::sha::HSha512Trunc256;
use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::BigInt;
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;

pub const DIGEST_BIT_LENGTH: u32 = HSha512Trunc256::DIGEST_BIT_LENGTH as u32;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlogSignature {
    security_param: u32,
    y: BigInt,
    c: BigInt,
}

/// Signature scheme for DL proof in a composite group with unknown modulo
///
/// "Composite discrete logarithm and secure authentication" , D. Pointcheval , pp 3.2
#[allow(clippy::many_single_char_names)]
impl DlogSignature {
    pub fn sign(
        N: &BigInt,
        g: &BigInt,
        V: &BigInt,
        s: &BigInt,
        max_secret_length: u32,
        security_param: u32,
    ) -> Self {
        let log_r = max_secret_length + DIGEST_BIT_LENGTH + security_param;
        let R = BigInt::from(2).pow(log_r);
        let r = BigInt::sample_below(&R);
        let x = g.powm_sec(&r, N);
        let c = HSha512Trunc256::create_hash(&[N, g, V, &x]);

        let y = r - c.borrow() * s;
        Self {
            security_param,
            y,
            c,
        }
    }

    pub fn verify(&self, N: &BigInt, g: &BigInt, V: &BigInt, security_param: u32) -> bool {
        let x = g.powm_sec(&self.y, N) * V.powm_sec(&self.c, N) % N;
        let c = HSha512Trunc256::create_hash(&[N, g, V, &x]);

        c == self.c && self.security_param == security_param
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithms::dlog_signature::{DlogSignature, DIGEST_BIT_LENGTH};
    use crate::algorithms::zkp::{ZkpSetup, DEFAULT_GROUP_ORDER_BIT_LENGTH};

    #[test]
    fn check_bitness() {
        let setup = ZkpSetup::random(DEFAULT_GROUP_ORDER_BIT_LENGTH);

        let security_param = 64u32;
        let max_secret_length = setup.phi().bit_length() as u32;

        let signature = DlogSignature::sign(
            &setup.N_tilde,
            &setup.h1,
            &setup.h2,
            setup.alpha(),
            max_secret_length,
            security_param,
        );

        assert!(
            signature.y.bit_length()
                <= (max_secret_length + security_param + DIGEST_BIT_LENGTH) as usize
        );
        assert!(signature.c.bit_length() <= DIGEST_BIT_LENGTH as usize);
        assert_eq!(signature.security_param, security_param);
    }
    #[test]
    fn validate() {
        (0..10).for_each(|_| {
            let setup = ZkpSetup::random(DEFAULT_GROUP_ORDER_BIT_LENGTH);

            let security_param = 64u32;
            let max_secret_length = setup.phi().bit_length() as u32;

            let signature = DlogSignature::sign(
                &setup.N_tilde,
                &setup.h1,
                &setup.h2,
                setup.alpha(),
                max_secret_length,
                security_param,
            );
            assert!(signature.verify(&setup.N_tilde, &setup.h1, &setup.h2, security_param))
        });
    }
}
