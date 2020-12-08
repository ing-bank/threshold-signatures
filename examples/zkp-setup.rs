#![allow(non_snake_case)]

use ecdsa_mpc::algorithms::zkp::{ZkpPublicSetup, ZkpSetup};
use std::env;
use std::time::Instant;

const DEFAULT_GROUP_ORDER_BIT_LENGTH: usize = 2048;

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

    for _ in 0..n_iter {
        let setup = ZkpSetup::random(DEFAULT_GROUP_ORDER_BIT_LENGTH);
        let setup_in_json = serde_json::to_string_pretty(&setup).unwrap();
        let public_setup = ZkpPublicSetup::from_private_zkp_setup(&setup);
        let verified = public_setup.verify();
        assert!(
            verified.is_ok(),
            format!("invalid public zkp setup: {:?}", verified.err())
        );

        println!(">>>private version \n{}", setup_in_json);
        println!(
            ">>>public version \n{}",
            serde_json::to_string_pretty(&public_setup).unwrap()
        );
    }

    log::info!("generated in {} secs", now.elapsed().as_secs_f32());
}
