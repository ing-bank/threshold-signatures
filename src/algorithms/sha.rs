//! Implements Hash trait for Sha512-256 algorithm
use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha512Trunc256};
use std::convert::TryFrom;

pub struct HSha512Trunc256;

impl HSha512Trunc256 {
    const MAX_ITERATIONS_IN_REJECTION_SAMPLING: usize = 256;
    const DIGEST_BIT_LENGTH: usize = 256;

    pub fn can_handle_curve_modulo(q: &BigInt) -> bool {
        Self::DIGEST_BIT_LENGTH == q.bit_length()
    }

    pub fn create_hash_with_random_nonce(big_ints: &[&BigInt]) -> (BigInt, BigInt) {
        let mut nonce = [0u8; 8];
        let mut hasher = Sha512Trunc256::new();
        thread_rng().fill(&mut nonce[..]);

        hasher.input(nonce);
        for value in big_ints {
            let as_vec = BigInt::to_vec(value);
            let vec_length = u16::try_from(as_vec.len()).expect("BigInt: bit length too big");
            hasher.input(vec_length.to_le_bytes());
            hasher.input(&as_vec);
        }

        let result_hex = hasher.result();
        (BigInt::from(&result_hex[..]), BigInt::from(&nonce[0..8]))
    }

    pub fn create_hash_with_nonce(big_ints: &[&BigInt], nonce: &BigInt) -> (BigInt, BigInt) {
        let mut hasher = Sha512Trunc256::new();

        hasher.input(BigInt::to_vec(nonce));
        for value in big_ints {
            let as_vec = BigInt::to_vec(value);
            let vec_length = u16::try_from(as_vec.len()).expect("BigInt: bit length too big");
            hasher.input(vec_length.to_le_bytes());
            hasher.input(&as_vec);
        }
        let result_hex = hasher.result();
        (BigInt::from(&result_hex[..]), nonce.clone())
    }

    pub fn create_hash_bounded_by_q(big_ints: &[&BigInt], q: &BigInt) -> (BigInt, BigInt) {
        for _ in 0..Self::MAX_ITERATIONS_IN_REJECTION_SAMPLING {
            let (hash, nonce) = Self::create_hash_with_random_nonce(big_ints);
            let hash = hash.abs();
            if hash < *q {
                return (hash, nonce);
            }
        }
        // If the condition in can_handle_curve_modulo() is true,
        // the probability of hitting next statement is no more than approx. 1/2^(MAX_ITERATIONS)
        unreachable!(
            "rejection sampling exceeded {} iterations in create_hash_bounded_by_q()",
            Self::MAX_ITERATIONS_IN_REJECTION_SAMPLING
        )
    }
}

impl Hash for HSha512Trunc256 {
    fn create_hash(big_ints: &[&BigInt]) -> BigInt {
        let mut hasher = Sha512Trunc256::new();

        for value in big_ints {
            let as_vec = BigInt::to_vec(value);
            let vec_length = u16::try_from(as_vec.len()).expect("BigInt: bit length too big");
            hasher.input(vec_length.to_le_bytes());
            hasher.input(&as_vec);
        }

        let result_hex = hasher.result();
        BigInt::from(&result_hex[..])
    }

    fn create_hash_from_slice(_: &[u8]) -> BigInt {
        unimplemented!()
    }

    fn create_hash_from_ge(ge_vec: &[&GE]) -> FE {
        let mut hasher = Sha512Trunc256::new();
        for value in ge_vec {
            hasher.input(&value.pk_to_key_slice());
        }

        let result_hex = hasher.result();
        let result = BigInt::from(&result_hex[..]);
        ECScalar::from(&result)
    }
}
