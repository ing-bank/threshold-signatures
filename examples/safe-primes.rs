#![allow(non_snake_case)]

use ecdsa_mpc::algorithms::primes::{random_safe_prime, PairOfSafePrimes};
use ecdsa_mpc::algorithms::zkp::DEFAULT_SAFE_PRIME_BIT_LENGTH;
use std::env;
use std::time::Instant;

fn main() {
    let args: Vec<String> = env::args().collect();
    let _ = env_logger::builder().try_init();

    let mut n_iter = 1usize;

    if args.len() > 1 {
        let n = args[1]
            .parse::<usize>()
            .expect("use int argument larger than 1");
        if n > 1 {
            n_iter = n;
        }
    }

    let now = Instant::now();

    let mut result = Vec::new();

    for _ in 0..n_iter {
        let bit_length = DEFAULT_SAFE_PRIME_BIT_LENGTH;
        let (p, p_prim) = random_safe_prime(bit_length);
        let (q, q_prim) = random_safe_prime(bit_length);
        result.push(PairOfSafePrimes {
            p,
            p_prim,
            q,
            q_prim,
        });
    }
    println!("{}", serde_json::to_string_pretty(&result).unwrap());

    log::info!("generated in {} secs", now.elapsed().as_secs_f32());
}
