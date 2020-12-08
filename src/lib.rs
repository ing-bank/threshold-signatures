//! The crate contains the implementation of a multiparty threshold signature scheme
//! based on the work of Rosario Gennaro and Steven Goldfeder
//! ["Fast multiparty threshold ECDSA with Fast trustless setup"](https://eprint.iacr.org/2019/114.pdf).
//!
//! The scheme comprises
//!  * key generation performed in the distributed setup with `N` players
//!  * message signing carried out by subgroup of `(t+1, N)` players
//!  * the key resharing performed by `t+1` players resulting in a new group of `M` players holding
//! new shares of the same signing key.
//! The scheme is based on ECDSA standard with the elliptic curve secp256k1 , which can be substituted by other curves.
//!
//! Cryptographic protocols are implemented by [`ecdsa`](./ecdsa/index.html) module.
//! Additional algorithms can be found in [`algorithms`](./algorithms/index.html) module.
//! The general purpose state machine is implemented in [`state_machine`](./state_machine/index.html) module.
#![allow(
    clippy::must_use_candidate,
    clippy::items_after_statements,
    clippy::module_name_repetitions,
    clippy::unseparated_literal_suffix,
    //
    clippy::missing_errors_doc, // remove at some point
    clippy::used_underscore_binding // if turned on, seems to generate a lot of false positive
)]
pub mod algorithms;
pub mod ecdsa;
pub mod protocol;
pub mod state_machine;

#[macro_use]
extern crate strum_macros;

pub use ecdsa::{Parameters, Signature};
