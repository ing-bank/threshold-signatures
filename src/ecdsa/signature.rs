//! Multi-party signature generation
//!
//! Multi-party signature generation. Full description of the protocol cab be found in ["Fast multiparty threshold ECDSA with Fast trustless setup"](https://eprint.iacr.org/2019/114.pdf), chapters 4.2, 4.3, and Appendix A.
//!
//! The code of `Phases` of the protocol is provided with references to the corresponding phases in the paper.
//!
//! The challenging aspect of ECDSA algorithm is in its requirement for unique randomness to be multiplied by private key during the signing so that if each party has both randomness and key additively shared,
//! the product of sums is the sum of products, where each term of the sum contains two values coming from different parties
//! while both values have to be kept private from each other.
//!
//! To overcome this problem the signing protocol uses the multiplication-to-addition (`MtA`) conversion algorithm described in very detail in the paper, chapter 3.
//! The `MtA` algorithm uses additive homomorphic encryption schema. In addition to that, zero-knowledge range proofs are used to prevent the generation of a wrong signature.
//!
//! # Details
//!
//! The protocol can be started with following steps:
//! * Check what threshold the given key requires and poll parties to collect the quorum. This step is external to the library.
//! * Create `Phase1` providing the list of parties in the collected quorum as the argument.
//! * Create the `StateMachine` and set the instance of `Phase1` as its argument.
//! * Execute the machine and obtain a result.
//!
//!  Every party obtains and verifies the complete signature before returning the result via state machine.
//!
//! # Example
//!
//!
//! * creates the stream `protocol_sink` for incoming messages
//! * creates another stream `state_machine_stream` for outgoing messages
//! * runs external algorithm to determine which parties will participate in signing
//! * instantiates `Phase1` of the protocol, where `message` argument is not a message itself but the output of hash function
//! * creates state machine providing the `Phase1` object and streams as arguments
//! * executes the machine and obtains the result
//!
//! ```text
//!
//!   let (protocol_sink, protocol_stream) = mpsc::unbounded();
//!   let (state_machine_sink, state_machine_stream) = mpsc::unbounded();
//!
//!   // to do: determine which parties(nodes) will participate in threshold signing
//!   // and fill the vector `signing_parties` with their PartyIndexes
//!   let start_phase = Box::new(Phase1::new(&message, key, signing_parties));
//!
//!   let state_machine = StateMachine::new(start_phase, protocol_stream, state_machine_sink);
//!   // to do : share protocol_stream and state_machine_sink with a network layer
//!   let machine_result = state_machine.execute(); // .await() in case aync version is used
//! ```
//!
//! # Input message format
//!
//! The signing protocol does not deal with messages directly. A message has to be hashed and then mapped to a field element using a hash function
//! $` H : \{ 0,1 \} ^{*} \to Z_{q} `$ . The following code can be used to perform the operation:
//!
//! ```text
//!    let mut hasher = Sha256::new();
//!    hasher.input(the_message);
//!    let msg_hash = ECScalar::from(&BigInt::from(hasher.result().as_slice()));
//! ```
//!
//!

#![allow(non_snake_case)]
use super::keygen::MultiPartyInfo;
use super::messages::signing::{
    Phase3data, Phase5Com1, Phase5Com2, Phase5Decom1, Phase5Decom2, Phase5Edata,
    SignBroadcastPhase1, SignDecommitPhase4,
};
use super::signature::phase5::LocalSignature;
use crate::ecdsa::{
    is_valid_curve_point, CommitmentScheme, MessageHashType, PaillierKeys, SigningParameters,
};
use crate::protocol::{Address, PartyIndex};

use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoElGamalStatement;

use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof, ProveDLog};

use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use std::collections::{BTreeSet, HashMap};

pub use super::messages::signing::{InMsg, Message, OutMsg};
use crate::state_machine::{State, StateMachineTraits, Transition};
use std::time::Duration;

use crate::algorithms::zkp::MTAMode::{MtA, MtAwc};
use crate::algorithms::zkp::{AliceProof, BobProofType, MessageA, MessageB};
use crate::ecdsa::keygen::RangeProofSetups;
use crate::ecdsa::signature::mta::MtaAliceOutput;
use paillier::{Decrypt, EncryptionKey, Paillier, RawCiphertext};
use std::iter::FromIterator;
use trace::trace;

/// Enumerates error types which can be raised by signing protocol
#[derive(Debug, Error)]
#[allow(clippy::large_enum_variant)]
pub enum SigningError {
    #[error("signing: timeout in {phase}")]
    Timeout { phase: String },
    #[error("unexpected message {message_type:?}, party {party}")]
    UnexpectedMessageType {
        message_type: Message,
        party: PartyIndex,
    },
    #[error("Range proof from Alice, her setup or key not found, party {party:?}, proof {proof:?}, key {key:?}")]
    AliceRangeProofIncomplete {
        party: PartyIndex,
        proof: Option<AliceProof>,
        key: Option<EncryptionKey>,
    },
    #[error("Alice proof failed {proof:?}, party {party:?}")]
    AliceProofFailed {
        party: PartyIndex,
        proof: AliceProof,
    },
    #[error("Bob proof failed {proof:?}, party {party:?}")]
    BobProofFailed {
        party: PartyIndex,
        proof: BobProofType,
    },

    #[error("Local zkp setup not found, party {party:?}")]
    LocalZkpSetupNotFound { party: PartyIndex },

    #[error("missing p1 commitment from party {0}")]
    MissingPhase1Commitment(PartyIndex),

    #[error("Dlog proof failed party {party:?} proofs {proof:?}")]
    DlogProofFailed { party: PartyIndex, proof: DLogProof },
    #[error("invalid decommitment at phase 4 , party {party:?}")]
    InvalidDecommitment { party: PartyIndex },
    #[error("invalid ElGamal proof at phase 5b , party {party:?}")]
    InvalidElGamalProof { party: PartyIndex },
    #[error("phase5 validation failed")]
    Phase5ValidationFailed,
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("protocol setup error: {0}")]
    ProtocolSetupError(String),
    #[error("invalid public key {point}")]
    InvalidPublicKey { point: String },
    #[error("{0}")]
    GeneralError(String),
}

#[derive(Debug, Error)]
pub enum ECDSAError {
    #[error("{desc}")]
    VerificationFailed { desc: String },
}

/// The module dedicated to range proofs in `MtA` protocol
mod mta {
    // Multiplication to addition
    use super::{
        trace, AliceProof, BigInt, BobProofType, Decrypt, EncryptionKey, Paillier, PartyIndex,
        RawCiphertext, SigningError,
    };
    use crate::algorithms::zkp::BobProofType::{RangeProof, RangeProofExt};
    use crate::algorithms::zkp::{MessageA, ZkpSetup};
    use crate::ecdsa::PaillierKeys;
    use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof, ProveDLog};
    use curv::elliptic::curves::traits::{ECPoint, ECScalar};
    use curv::{FE, GE};
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    pub enum MtaAliceOutput {
        Simple(MessageA),
        WithRangeProofs(HashMap<PartyIndex, MessageA>),
    }
    /// Verifies `AliceProof`
    #[trace(pretty)]
    pub(crate) fn verify_alice_range_proof(
        cipher: &BigInt,
        party: &PartyIndex,
        bob_setup: Option<&ZkpSetup>,
        proof: Option<&AliceProof>,
        alice_ek: Option<&EncryptionKey>,
    ) -> Result<(), SigningError> {
        if bob_setup.is_none() {
            return Err(SigningError::LocalZkpSetupNotFound { party: *party });
        }
        let bob_setup = bob_setup.unwrap();

        match (proof, alice_ek) {
            (Some(proof), Some(enc_key)) => {
                if proof.verify(cipher, &enc_key, bob_setup) {
                    Ok(())
                } else {
                    Err(SigningError::AliceProofFailed {
                        party: *party,
                        proof: proof.clone(),
                    })
                }
            }

            (proof, key) => Err(SigningError::AliceRangeProofIncomplete {
                party: *party,
                proof: proof.cloned(),
                key: key.cloned(),
            }),
        }
    }

    /// Verifies the proof sent by Bob
    ///
    /// Supports three choices of the proof:   `DLogProofs`, `BobProof`, and `BobProofExt`.
    /// Need the initial value of $` a `$ provided by Alice at the start of MtA
    #[trace(pretty)]
    pub(crate) fn verify_bob_range_proof(
        party: &PartyIndex,
        proof: &BobProofType,
        mta_output: &BigInt,
        a: &FE,
        a_enc: &BigInt,
        alice_keys: &PaillierKeys,
        alice_setup: Option<&ZkpSetup>,
    ) -> Result<FE, Vec<SigningError>> {
        match proof {
            RangeProof(_) | RangeProofExt(_) if alice_setup.is_none() => {
                return Err(vec![SigningError::LocalZkpSetupNotFound { party: *party }])
            }
            _ => {}
        }

        let alice_share = Paillier::decrypt(&alice_keys.dk, RawCiphertext::from(mta_output));
        let alice_share = alice_share.0.into_owned();
        let alpha: FE = ECScalar::from(&alice_share);
        let mut errors = Vec::new();
        match proof {
            // the simplified proof as defined in GG18, ch.5 , p.19
            BobProofType::DLogProofs(dlog_proofs) => {
                let g: GE = ECPoint::generator();
                let g_alpha = g * alpha;
                let ba_btag = dlog_proofs.b_proof.pk * a + dlog_proofs.beta_tag_proof.pk;
                if DLogProof::verify(&dlog_proofs.b_proof).is_err() {
                    errors.push(SigningError::DlogProofFailed {
                        party: *party,
                        proof: dlog_proofs.b_proof.clone(),
                    });
                }
                if DLogProof::verify(&dlog_proofs.beta_tag_proof).is_err() {
                    errors.push(SigningError::DlogProofFailed {
                        party: *party,
                        proof: dlog_proofs.beta_tag_proof.clone(),
                    });
                }
                if ba_btag.get_element() != g_alpha.get_element() {
                    errors.push(SigningError::GeneralError(format!(
                        "DlogProof: eq doesn't hold, g^alpha {:?}, B^a* B_prim {:?} ",
                        &g_alpha.get_element(),
                        &ba_btag.get_element()
                    )));
                }
            }
            // Bob's range proof
            RangeProof(range_proof) => {
                if !range_proof.verify(a_enc, &mta_output, &alice_keys.ek, &alice_setup.unwrap()) {
                    errors.push(SigningError::BobProofFailed {
                        party: *party,
                        proof: proof.clone(),
                    });
                }
            }
            // Bob's range proof with proof of knowing b and beta_prim
            RangeProofExt(range_proof) => {
                if !range_proof.verify(a_enc, &mta_output, &alice_keys.ek, &alice_setup.unwrap()) {
                    errors.push(SigningError::BobProofFailed {
                        party: *party,
                        proof: proof.clone(),
                    });
                }
            }
        };
        if errors.is_empty() {
            Ok(alpha)
        } else {
            Err(errors)
        }
    }
}

///The module dedicated to ZKP in the Phase5
mod phase5 {
    use super::{
        trace, CommitmentScheme, ECDSAError, ECPoint, ECScalar, HSha256, Hash, MessageHashType, FE,
        GE,
    };
    use crate::ecdsa::messages::signing::{Phase5Com1, Phase5Com2, Phase5Decom1, Phase5Decom2};
    use crate::ecdsa::signature::ECDSAError::VerificationFailed;
    use crate::ecdsa::Signature;
    use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::{
        HomoELGamalProof, HomoElGamalStatement, HomoElGamalWitness,
    };
    use serde::{Deserialize, Serialize};

    /// Represents the partial signature used by multiple sub-phases of phase 5 of the protocol
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct LocalSignature {
        pub l_i: FE,
        pub rho_i: FE,
        pub R: GE,
        pub s_i: FE,
    }

    #[trace(pretty, prefix = "LocalSignature::")]
    impl LocalSignature {
        /// Initializes the data with $` R, \space k_{i}, \space \sigma_{i} `$ .
        /// Sets (t,t) sharing of the desired signature to $` s_{i} = m k_{i} + r \sigma_{i} `$.
        /// Chooses  $` \ell_{i}, \space \rho_{i}  \underset{R}{\in} Z_q `$     
        pub fn new(message_hash: &MessageHashType, R: &GE, k_i: &FE, sigma_i: &FE) -> Self {
            // H'(R) = Rx mod q
            let r: FE = ECScalar::from(&R.x_coor().unwrap().mod_floor(&FE::q()));
            let s_i = (*message_hash) * k_i + r * sigma_i; // <- partial signature
            let l_i: FE = ECScalar::new_random();
            let rho_i: FE = ECScalar::new_random();
            Self {
                l_i,
                rho_i,
                R: *R,
                s_i,
            }
        }

        /// generates (Comm,Decomm) for $` V_{i} , \space A_{i} `$
        pub fn phase5b_proof(&self) -> (Phase5Com1, Phase5Decom1) {
            let g: GE = ECPoint::generator();
            let A_i = g * self.rho_i;
            let l_i_rho_i = self.l_i.mul(&self.rho_i.get_element());
            let V_i = self.R * self.s_i + g * self.l_i;
            let B_i = g * l_i_rho_i;
            let input_hash = HSha256::create_hash_from_ge(&[&V_i, &A_i, &B_i]).to_big_int();
            let commitment_scheme = CommitmentScheme::from_BigInt(&input_hash);

            let witness = HomoElGamalWitness {
                r: self.l_i,
                x: self.s_i,
            };
            let delta = HomoElGamalStatement {
                G: A_i,
                H: self.R,
                Y: g,
                D: V_i,
                E: B_i,
            };
            let proof = HomoELGamalProof::prove(&witness, &delta);
            (
                Phase5Com1 {
                    com: commitment_scheme.comm,
                },
                Phase5Decom1 {
                    V_i,
                    A_i,
                    B_i,
                    blind_factor: commitment_scheme.decomm,
                    proof,
                },
            )
        }

        /// generates (Comm, Decomm) for $` U_{i}, \space T_{i} `$
        pub fn phase5d_proof(&self, v: GE, a: GE) -> (Phase5Com2, Phase5Decom2) {
            let u_i = v * self.rho_i;
            let t_i = a * self.l_i;
            let input_hash = HSha256::create_hash_from_ge(&[&u_i, &t_i]).to_big_int();
            let scheme = CommitmentScheme::from_BigInt(&input_hash);
            (
                Phase5Com2 { com: scheme.comm },
                Phase5Decom2 {
                    U_i: u_i,
                    T_i: t_i,
                    blind_factor: scheme.decomm,
                },
            )
        }
        /// calculates final signature as the sum of partial signatures, and verifies it using standard verification schema
        pub fn output_signature(
            &self,
            s_vec: &[FE],
            pubkey: &GE,
            message: &MessageHashType,
        ) -> Result<Signature, ECDSAError> {
            let s = s_vec.iter().fold(self.s_i, |acc, x| acc + x);
            let r: FE = ECScalar::from(&self.R.x_coor().unwrap().mod_floor(&FE::q()));
            let sig = Signature { r, s };
            if sig.verify(pubkey, message) {
                Ok(sig)
            } else {
                Err(VerificationFailed {
                    desc: "ECDSA verification failed".to_string(),
                })
            }
        }
    }
}

#[doc(hidden)]
type OutMsgVec = Vec<OutMsg>;

#[derive(Debug)]
pub struct SigningTraits;

impl StateMachineTraits for SigningTraits {
    type InMsg = InMsg;
    type OutMsg = OutMsg;
    type FinalState = SignedMessage;
    type ErrorState = ErrorState;
}

pub type MachineResult = Result<SignedMessage, ErrorState>;

/// Signature in (r,s)  format, and the hash of the signed message
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedMessage {
    pub r: FE,
    pub s: FE,
    pub hash: MessageHashType,
}

/// vector of signing errors
#[derive(Debug)]
pub struct ErrorState {
    errors: Vec<SigningError>,
}

impl ErrorState {
    pub fn new(errors: Vec<SigningError>) -> Self {
        ErrorState { errors }
    }
}

/// Checks whether all expected messages have been received so far from other parties  
fn is_broadcast_input_complete(
    current_msg_set: &[InMsg],
    other_parties: &BTreeSet<PartyIndex>,
) -> bool {
    let senders = current_msg_set.iter().map(|m| m.sender).collect::<Vec<_>>();
    other_parties.iter().all(|p| senders.contains(p))
}

/// Extracts payloads form enum variants of input message into the hash map
#[trace(disable(current_msg_set), res = "{:?}")]
fn to_hash_map_gen<K, V>(current_msg_set: Vec<InMsg>) -> Result<HashMap<K, V>, SigningError>
where
    K: Eq + std::hash::Hash + From<PartyIndex> + std::fmt::Debug,
    V: std::fmt::Debug,
    Option<V>: From<Message>,
{
    let content = current_msg_set
        .iter()
        .map(|m| {
            let body: Option<V> = m.body.clone().into();
            (m.sender, m.body.clone(), body)
        })
        .collect::<Vec<(_, _, _)>>();

    // returns first failed result of  into() operation on a message
    if let Some((p, m)) = content.iter().find_map(|(party, msg_type, body)| {
        body.as_ref()
            .map_or_else(|| Some((party, msg_type)), |_| None)
    }) {
        Err(SigningError::UnexpectedMessageType {
            message_type: m.clone(),
            party: *p,
        })
    } else {
        Ok(content
            .into_iter()
            .map(|(party, _message, body)| (party.into(), body.unwrap()))
            .collect::<HashMap<K, V>>())
    }
}
/// First phase of the signing protocol
///
/// * Initializes the protocol, see [`Phase1::new`](struct.Phase1.html#method.new)
/// * Broadcasts the commitment to $` g^{\gamma_{i}} `$
/// * Broadcasts `MtA` with the share of $` k_{i}  `$
/// * Collects `MtA` inputs from other parties and verifies them using [`mta::verify_alice_range_proof`](mta/fn.verify_alice_range_proof.html)
#[derive(Debug)]
pub struct Phase1 {
    pub params: SigningParameters,
    pub multi_party_info: MultiPartyInfo,
    other_parties: BTreeSet<PartyIndex>,
    gamma_i: FE,
    k_i: FE,
    mta_a: MtaAliceOutput,
    comm_scheme: CommitmentScheme,
    timeout: Option<Duration>,
}

#[trace(pretty, prefix = "Phase1::")]
impl Phase1 {
    /// Initializes the protocol
    ///
    /// * Samples  $` k_{i}, \space \gamma_{i}  \underset{R}{\in} Z_q `$
    /// * Generates first message of MtA protocol where $`  k_{i} `$ is shared
    /// * Generates (comm, decomm) to $` g^{\gamma_{i}} `$
    pub fn new(
        message_hash: MessageHashType,
        multi_party_info: MultiPartyInfo,
        parties: &[PartyIndex],
        timeout: Option<Duration>,
    ) -> Result<Self, SigningError> {
        let signing_parties = BTreeSet::from_iter(parties.iter().cloned());
        if signing_parties.len() != parties.len() {
            return Err(SigningError::ProtocolSetupError(
                "duplicate entries in signing parties' list".to_string(),
            ));
        }
        if signing_parties
            .get(&multi_party_info.own_party_index)
            .is_none()
        {
            return Err(SigningError::ProtocolSetupError(
                "own party index not in the list of signing parties".to_string(),
            ));
        }
        if multi_party_info.key_params.signers() > signing_parties.len() {
            return Err(SigningError::ProtocolSetupError(
                "the number of parties is less than required threshold".to_string(),
            ));
        }

        let mut other_parties = signing_parties.clone();
        other_parties.remove(&multi_party_info.own_party_index);

        let missing_keys = other_parties
            .iter()
            .filter(|p| multi_party_info.party_he_keys.get(p).is_none())
            .collect::<Vec<_>>();
        if !missing_keys.is_empty() {
            return Err(SigningError::ProtocolSetupError(format!(
                "parties {:?} :  Paillier key is missing",
                missing_keys
            )));
        }

        let missing_points = other_parties
            .iter()
            .filter(|p| multi_party_info.party_to_point_map.points.get(p).is_none())
            .collect::<Vec<_>>();
        if !missing_points.is_empty() {
            return Err(SigningError::ProtocolSetupError(format!(
                "parties {:?} :  secret sharing point is missing",
                missing_points
            )));
        }

        if !PaillierKeys::is_valid(
            &multi_party_info.own_he_keys.ek,
            &multi_party_info.own_he_keys.dk,
        ) {
            return Err(SigningError::ProtocolSetupError(format!(
                "invalid own Paillier key {}",
                &multi_party_info.own_he_keys
            )));
        }

        let public_key = multi_party_info.public_key.get_element();
        if !is_valid_curve_point(public_key) {
            return Err(SigningError::InvalidPublicKey {
                point: format!("{:?}", public_key),
            });
        }
        let k_i = ECScalar::new_random();

        let mta_a = if let Some(setups) = &multi_party_info.range_proof_setups {
            MtaAliceOutput::WithRangeProofs(
                setups
                    .party_setups
                    .iter()
                    .map(|(p, setup)| {
                        (
                            *p,
                            MessageA::new(&k_i, &multi_party_info.own_he_keys.ek, Some(setup)),
                        )
                    })
                    .collect::<HashMap<_, _>>(),
            )
        } else {
            MtaAliceOutput::Simple(MessageA::new(&k_i, &multi_party_info.own_he_keys.ek, None))
        };

        let gamma_i: FE = ECScalar::new_random();
        let g: GE = ECPoint::generator();
        let g_gamma_i = g * gamma_i;
        let comm_scheme = CommitmentScheme::from_GE(&g_gamma_i);

        Ok(Phase1 {
            params: SigningParameters {
                keygen_params: multi_party_info.key_params,
                signing_parties,
                message_hash,
            },
            multi_party_info,
            other_parties,
            gamma_i,
            k_i,
            mta_a,
            comm_scheme,
            timeout,
        })
    }
    /// Checks if Shamir's secret sharing points are known for each other party involved into the signing protocol
    ///
    /// Called conditionally if ZK range proof setups of other parties exist for given key
    pub fn verify_points(&self) -> bool {
        self.params.signing_parties.iter().all(|party| {
            self.multi_party_info
                .party_to_point_map
                .points
                .contains_key(party)
        })
    }
}

#[trace(pretty, prefix = "Phase1::")]
impl Phase1 {
    ///  verifies that every party sent correct Alice's MtA input
    fn verify_alice_range_proofs(
        &self,
        mta_inputs: &HashMap<PartyIndex, MessageA>,
        range_proof_setup: &RangeProofSetups,
    ) -> Result<(), Vec<SigningError>> {
        let verification_errors = mta_inputs
            .iter()
            .filter_map(|(party, msg)| {
                match mta::verify_alice_range_proof(
                    &msg.c,
                    party,
                    Some(&range_proof_setup.my_setup),
                    msg.range_proof.as_ref(),
                    self.multi_party_info.party_he_keys.get(party),
                ) {
                    Ok(_) => None,
                    Err(e) => Some(e),
                }
            })
            .collect::<Vec<_>>();
        if verification_errors.is_empty() {
            Ok(())
        } else {
            Err(verification_errors)
        }
    }
}

#[trace(pretty, prefix = "Phase1::")]
impl State<SigningTraits> for Phase1 {
    fn start(&mut self) -> Option<OutMsgVec> {
        log::info!("Phase 1 starts");

        let output = match &self.mta_a {
            MtaAliceOutput::Simple(msg) => vec![OutMsg {
                recipient: Address::Broadcast,
                body: Message::R1(SignBroadcastPhase1 {
                    com: self.comm_scheme.comm.clone(),
                    mta_a: msg.clone(),
                }),
            }],
            MtaAliceOutput::WithRangeProofs(map) => map
                .iter()
                .map(|(p, msg)| OutMsg {
                    recipient: Address::Peer(*p),
                    body: Message::R1(SignBroadcastPhase1 {
                        com: self.comm_scheme.comm.clone(),
                        mta_a: msg.clone(),
                    }),
                })
                .collect::<Vec<_>>(),
        };
        Some(output)
    }

    #[trace(disable(current_msg_set))]
    fn is_message_expected(&self, msg: &InMsg, current_msg_set: &[InMsg]) -> bool {
        matches!(
            msg.body,
            Message::R1(_) if self.other_parties.contains(&msg.sender) && !msg.is_duplicate(current_msg_set)
        )
    }
    #[trace(disable(current_msg_set))]
    fn is_input_complete(&self, current_msg_set: &[InMsg]) -> bool {
        is_broadcast_input_complete(current_msg_set, &self.other_parties)
    }

    fn consume(&self, current_msg_set: Vec<InMsg>) -> Transition<SigningTraits> {
        let responses = match to_hash_map_gen::<PartyIndex, SignBroadcastPhase1>(current_msg_set) {
            Err(e) => {
                let error_state = ErrorState::new(vec![e]);
                log::error!("Phase 1 returns {:?}", error_state);
                return Transition::FinalState(Err(error_state));
            }
            Ok(msg_map) => msg_map,
        };

        let mta_inputs = responses
            .iter()
            .map(|(party, msg)| (*party, msg.mta_a.clone()))
            .collect::<HashMap<_, _>>();
        let commitments = responses
            .iter()
            .map(|(party, msg)| (*party, msg.com.clone()))
            .collect::<HashMap<_, _>>();

        if let Some(range_proof_setup) = &self.multi_party_info.range_proof_setups {
            if let Err(e) = self.verify_alice_range_proofs(&mta_inputs, range_proof_setup) {
                let error_state = ErrorState::new(e);
                log::error!("Phase 1 returns {:?}", error_state);
                return Transition::FinalState(Err(error_state));
            }
        }
        Transition::NewState(Box::new(Phase2a {
            params: self.params.clone(),
            multi_party_info: self.multi_party_info.clone(),
            other_parties: self.other_parties.clone(),
            gamma_i: self.gamma_i,
            k_i: self.k_i,
            comm_scheme: self.comm_scheme.clone(),
            mta_inputs,
            commitments,
            mta_a: self.mta_a.clone(),
            beta_outputs: HashMap::new(),
            timeout: self.timeout,
        }))
    }

    fn timeout_outcome(&self, _current_msg_set: Vec<InMsg>) -> MachineResult {
        Err(ErrorState::new(vec![SigningError::Timeout {
            phase: "phase1".to_string(),
        }]))
    }

    fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
}

/// Second phase of the protocol, part A
///
/// * Broadcasts Bob's `MtA` message where $` \gamma_{i} `$ is shared
/// * Collects Bob's `MtA` messages from other parties and verifies ZK range proof for each of them optionally.
/// * Computes $` \delta_{i} = k_{i}\gamma_{i} + \sum_{i \not = j} \alpha_{ij} + \sum_{i \not = j} \beta_{ij} `$
struct Phase2a {
    params: SigningParameters,
    multi_party_info: MultiPartyInfo,
    other_parties: BTreeSet<PartyIndex>,
    gamma_i: FE,
    k_i: FE,
    comm_scheme: CommitmentScheme,
    commitments: HashMap<PartyIndex, BigInt>,
    mta_a: MtaAliceOutput,
    mta_inputs: HashMap<PartyIndex, MessageA>,
    beta_outputs: HashMap<PartyIndex, FE>,
    timeout: Option<Duration>,
}

#[trace(pretty, prefix = "Phase2a::")]
impl State<SigningTraits> for Phase2a {
    fn start(&mut self) -> Option<OutMsgVec> {
        log::debug!("Phase 2a starts");
        let mut result = Vec::new();
        for (party, messageA) in &self.mta_inputs {
            if let Some(party_ek) = self.multi_party_info.party_he_keys.get(party) {
                let alice_zkp_setup = self
                    .multi_party_info
                    .range_proof_setups
                    .as_ref()
                    .map(|s| s.party_setups.get(party).expect("zkp setup not found"));

                let (message, beta_prime) = MessageB::new(
                    &self.gamma_i,
                    party_ek,
                    alice_zkp_setup,
                    messageA,
                    MtA, // first round of Mta goes without extra checks
                );
                self.beta_outputs.insert(*party, beta_prime);
                result.push(OutMsg {
                    recipient: Address::Peer(*party),
                    body: Message::R2(message),
                });
            } else {
                // the following statement should never be executed if Phase1::new() checks that all paillier keys available
                log::error!("paillier key not found for party {}", *party);
            }
        }

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    #[trace(disable(current_msg_set))]
    fn is_message_expected(&self, msg: &InMsg, current_msg_set: &[InMsg]) -> bool {
        matches!(
            msg.body,
            Message::R2(_) if self.other_parties.contains(&msg.sender) && !msg.is_duplicate(current_msg_set)
        )
    }

    #[trace(disable(current_msg_set))]
    fn is_input_complete(&self, current_msg_set: &[InMsg]) -> bool {
        is_broadcast_input_complete(current_msg_set, &self.other_parties)
    }

    fn consume(&self, current_msg_set: Vec<InMsg>) -> Transition<SigningTraits> {
        let responses = match to_hash_map_gen::<PartyIndex, MessageB>(current_msg_set) {
            Ok(map) => map,
            Err(e) => {
                let error_state = ErrorState::new(vec![e]);
                log::error!("Phase 2a returns {:?}", error_state);
                return Transition::FinalState(Err(error_state));
            }
        };

        let mut errors = Vec::new();

        let mut alpha_vec = Vec::new();
        for (party, msg) in &responses {
            let my_setup = self
                .multi_party_info
                .range_proof_setups
                .as_ref()
                .map(|s| &s.my_setup);

            let mta_a_message = match &self.mta_a {
                MtaAliceOutput::Simple(msg_a) => msg_a,
                MtaAliceOutput::WithRangeProofs(map) => {
                    map.get(party).expect("zkp setup not found")
                }
            };

            match mta::verify_bob_range_proof(
                party,
                &msg.proof,
                &msg.c,
                &self.k_i,
                &mta_a_message.c,
                &self.multi_party_info.own_he_keys,
                my_setup,
            ) {
                Ok(alpha) => alpha_vec.push(alpha),
                Err(ve) => errors.extend(ve),
            }
        }

        if !errors.is_empty() {
            let error_state = ErrorState::new(errors);
            log::error!("Phase 2a returns {:?}", error_state);
            return Transition::FinalState(Err(error_state));
        }

        let ki_gamma_i = self.k_i.mul(&self.gamma_i.get_element());
        let delta_i = alpha_vec.iter().fold(FE::zero(), |acc, x| acc + x)
            + self
                .beta_outputs
                .values()
                .fold(FE::zero(), |acc, x| acc + x)
            + ki_gamma_i;
        // k * gamma = sum(delta) across the cluster

        Transition::NewState(Box::new(Phase2b {
            params: self.params.clone(),
            multi_party_shared_info: self.multi_party_info.clone(),
            other_parties: self.other_parties.clone(),
            gamma_i: self.gamma_i,
            k_i: self.k_i,
            w_i: FE::zero(),
            comm_scheme: self.comm_scheme.clone(),
            commitments: self.commitments.clone(),
            mta_a: self.mta_a.clone(),
            mta_inputs: self.mta_inputs.clone(),
            delta_i,
            omega_outputs: HashMap::new(),
            timeout: self.timeout,
        }))
    }

    fn timeout_outcome(&self, _current_msg_set: Vec<InMsg>) -> MachineResult {
        Err(ErrorState::new(vec![SigningError::Timeout {
            phase: "phase2a".to_string(),
        }]))
    }

    fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
}
/// Second phase of the protocol, part B
///
/// * Broadcasts Bob's `MtAwc` message where $` \omega_{i} `$ is shared. Note that $` k_{i}  `$ is already broadcast at phase 1
/// * Collects Bob's `MtAwc` messages from other parties and verifies ZK range proof for each of them optionally.
/// * Computes $` \sigma_{i} = k_{i}\omega_{i} + \sum_{i \not = j} \mu_{ij} + \sum_{i \not = j} \upsilon_{ij} `$, where $` \mu, \space \upsilon `$ have same meaning as $` \alpha , \space \beta `$ in part A
struct Phase2b {
    params: SigningParameters,
    multi_party_shared_info: MultiPartyInfo,
    other_parties: BTreeSet<PartyIndex>,
    gamma_i: FE,
    k_i: FE,
    w_i: FE,
    comm_scheme: CommitmentScheme,
    commitments: HashMap<PartyIndex, BigInt>,
    mta_a: MtaAliceOutput,
    mta_inputs: HashMap<PartyIndex, MessageA>,
    delta_i: FE,
    omega_outputs: HashMap<PartyIndex, FE>,
    timeout: Option<Duration>,
}

#[trace(pretty, prefix = "Phase2b::")]
impl State<SigningTraits> for Phase2b {
    fn start(&mut self) -> Option<OutMsgVec> {
        log::debug!("Phase 2b starts");
        // calculate new lagrange coefficients according to teh list of parties which will sign

        let x_i: FE = self.multi_party_shared_info.own_share();
        let own_x: FE = ECScalar::from(&BigInt::from(
            self.multi_party_shared_info.own_point() as u64
        ));

        let signing_parties_as_vec = self
            .params
            .signing_parties
            .iter()
            .cloned()
            .collect::<Vec<_>>();

        let multiplier = self
            .multi_party_shared_info
            .party_to_point_map
            .calculate_lagrange_multiplier(signing_parties_as_vec.as_slice(), own_x);
        self.w_i = x_i * multiplier;

        let mut result = Vec::new();
        for (party, messageA) in &self.mta_inputs {
            if let Some(party_ek) = self.multi_party_shared_info.party_he_keys.get(party) {
                let alice_zkp_setup = self
                    .multi_party_shared_info
                    .range_proof_setups
                    .as_ref()
                    .map(|s| s.party_setups.get(party).expect("zkp setup not found"));
                let (message, beta_prime) =
                    MessageB::new(&self.w_i, party_ek, alice_zkp_setup, messageA, MtAwc);
                self.omega_outputs.insert(*party, beta_prime);
                result.push(OutMsg {
                    recipient: Address::Peer(*party),
                    body: Message::R2b(message),
                });
            } else {
                log::error!("paillier key not found for party {}", *party);
            }
        }

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    #[trace(disable(current_msg_set))]
    fn is_message_expected(&self, msg: &InMsg, current_msg_set: &[InMsg]) -> bool {
        matches!(
            msg.body,
            Message::R2b(_) if self.other_parties.contains(&msg.sender) && !msg.is_duplicate(current_msg_set)
        )
    }

    #[trace(disable(current_msg_set))]
    fn is_input_complete(&self, current_msg_set: &[InMsg]) -> bool {
        is_broadcast_input_complete(current_msg_set, &self.other_parties)
    }

    fn consume(&self, current_msg_set: Vec<InMsg>) -> Transition<SigningTraits> {
        let responses = match to_hash_map_gen::<PartyIndex, MessageB>(current_msg_set) {
            Ok(map) => map,
            Err(e) => {
                let error_state = ErrorState::new(vec![e]);
                log::error!("Phase 2b returns {:?}", error_state);
                return Transition::FinalState(Err(error_state));
            }
        };

        let mut errors = Vec::new();

        let mut alpha_vec = Vec::new();
        for (party, msg) in &responses {
            let my_setup = self
                .multi_party_shared_info
                .range_proof_setups
                .as_ref()
                .map(|s| &s.my_setup);

            let mta_a_message = match &self.mta_a {
                MtaAliceOutput::Simple(msg_a) => msg_a,
                MtaAliceOutput::WithRangeProofs(map) => {
                    map.get(party).expect("zkp setup not found")
                }
            };

            match mta::verify_bob_range_proof(
                party,
                &msg.proof,
                &msg.c,
                &self.k_i,
                &mta_a_message.c,
                &self.multi_party_shared_info.own_he_keys,
                my_setup,
            ) {
                Ok(alpha) => alpha_vec.push(alpha),
                Err(ve) => errors.extend(ve),
            }
        }

        if !errors.is_empty() {
            let error_state = ErrorState::new(errors);
            log::error!("Phase 2b returns {:?}", error_state);
            return Transition::FinalState(Err(error_state));
        }

        let ki_w_i = self.k_i.mul(&self.w_i.get_element());
        let sigma_i = alpha_vec.iter().fold(FE::zero(), |acc, x| acc + x)
            + self
                .omega_outputs
                .values()
                .fold(FE::zero(), |acc, x| acc + x)
            + ki_w_i;
        // k * w = sum(sigma) across the cluster, check the paper

        Transition::NewState(Box::new(Phase3 {
            params: self.params.clone(),
            multi_party_info: self.multi_party_shared_info.clone(),
            other_parties: self.other_parties.clone(),
            gamma_i: self.gamma_i,
            k_i: self.k_i,
            comm_scheme: self.comm_scheme.clone(),
            commitments: self.commitments.clone(),
            delta_i: self.delta_i,
            sigma_i,
            timeout: self.timeout,
        }))
    }

    fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    fn timeout_outcome(&self, _current_msg_set: Vec<InMsg>) -> MachineResult {
        Err(ErrorState::new(vec![SigningError::Timeout {
            phase: "phase2b".to_string(),
        }]))
    }
}
/// Third phase of the protocol
///
/// * Broadcasts  $` \delta_{i} `$
/// * Reconstructs $` \delta = \sum_{i \in S} \delta_{i} = k \gamma `$, where $`S`$ is the signing quorum    
struct Phase3 {
    params: SigningParameters,
    multi_party_info: MultiPartyInfo,
    other_parties: BTreeSet<PartyIndex>,
    gamma_i: FE,
    k_i: FE,
    comm_scheme: CommitmentScheme,
    commitments: HashMap<PartyIndex, BigInt>,
    delta_i: FE,
    sigma_i: FE,
    timeout: Option<Duration>,
}

#[trace(pretty, prefix = "Phase3::")]
impl State<SigningTraits> for Phase3 {
    fn start(&mut self) -> Option<OutMsgVec> {
        log::debug!("Phase 3 starts");
        let output = vec![OutMsg {
            recipient: Address::Broadcast,
            body: Message::R3(Phase3data {
                delta_i: self.delta_i,
            }),
        }];
        Some(output)
    }

    #[trace(disable(current_msg_set))]
    fn is_message_expected(&self, msg: &InMsg, current_msg_set: &[InMsg]) -> bool {
        matches!(
            msg.body,
            Message::R3(_) if self.other_parties.contains(&msg.sender) && !msg.is_duplicate(current_msg_set)
        )
    }

    #[trace(disable(current_msg_set))]
    fn is_input_complete(&self, current_msg_set: &[InMsg]) -> bool {
        is_broadcast_input_complete(current_msg_set, &self.other_parties)
    }

    fn consume(&self, current_msg_set: Vec<InMsg>) -> Transition<SigningTraits> {
        let responses = match to_hash_map_gen::<PartyIndex, Phase3data>(current_msg_set) {
            Ok(map) => map,
            Err(e) => {
                let error_state = ErrorState::new(vec![e]);
                log::error!("Phase 3 returns {:?}", error_state);
                return Transition::FinalState(Err(error_state));
            }
        };

        let delta = responses
            .iter()
            .fold(self.delta_i, |acc, (_party, msg)| acc + msg.delta_i);
        let delta_inv = delta.invert();

        Transition::NewState(Box::new(Phase4 {
            params: self.params.clone(),
            multi_party_info: self.multi_party_info.clone(),
            other_parties: self.other_parties.clone(),
            gamma_i: self.gamma_i,
            k_i: self.k_i,
            comm_scheme: self.comm_scheme.clone(),
            commitments: self.commitments.clone(),
            delta_inv,
            sigma_i: self.sigma_i,
            timeout: self.timeout,
        }))
    }

    fn timeout_outcome(&self, _current_msg_set: Vec<InMsg>) -> MachineResult {
        Err(ErrorState::new(vec![SigningError::Timeout {
            phase: "phase3".to_string(),
        }]))
    }

    fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
}

/// Fourth phase of the protocol
///
/// * Broadcasts $`  \Gamma_{i} = g^{\gamma_{i}} `$ and ZKP of it
/// * Verifies ZKP of each other party
/// * Reconstructs $` R = ( \prod_{i \in S} \Gamma_{i})^{\delta^{-1}} = g^{k^{-1}} `$ and $` r = H^{\prime}(R) `$
struct Phase4 {
    params: SigningParameters,
    multi_party_info: MultiPartyInfo,
    other_parties: BTreeSet<PartyIndex>,
    gamma_i: FE,
    k_i: FE,
    comm_scheme: CommitmentScheme,
    commitments: HashMap<PartyIndex, BigInt>,
    delta_inv: FE,
    sigma_i: FE,
    timeout: Option<Duration>,
}

#[trace(pretty, prefix = "Phase4::")]
impl State<SigningTraits> for Phase4 {
    fn start(&mut self) -> Option<OutMsgVec> {
        log::debug!("Phase 4 starts");
        let g: GE = ECPoint::generator();
        let g_gamma_i = g * self.gamma_i;
        let output = vec![OutMsg {
            recipient: Address::Broadcast,
            body: Message::R4(SignDecommitPhase4 {
                blind_factor: self.comm_scheme.decomm.clone(),
                g_gamma_i,
                gamma_proof: DLogProof::prove(&self.gamma_i),
            }),
        }];
        Some(output)
    }

    #[trace(disable(current_msg_set))]
    fn is_message_expected(&self, msg: &InMsg, current_msg_set: &[InMsg]) -> bool {
        matches!(
            msg.body,
            Message::R4(_) if self.other_parties.contains(&msg.sender) && !msg.is_duplicate(current_msg_set)
        )
    }

    #[trace(disable(current_msg_set))]
    fn is_input_complete(&self, current_msg_set: &[InMsg]) -> bool {
        is_broadcast_input_complete(current_msg_set, &self.other_parties)
    }

    fn consume(&self, current_msg_set: Vec<InMsg>) -> Transition<SigningTraits> {
        let responses = match to_hash_map_gen::<PartyIndex, SignDecommitPhase4>(current_msg_set) {
            Ok(map) => map,
            Err(e) => {
                let error_state = ErrorState::new(vec![e]);
                log::error!("Phase 4 returns {:?}", error_state);
                return Transition::FinalState(Err(error_state));
            }
        };

        let verification_errors = responses
            .iter()
            .filter_map(|(party, msg)| {
                let foreign_comm_scheme = CommitmentScheme {
                    comm: self
                        .commitments
                        .get(party)
                        .expect("commitment not found")
                        .clone(),
                    decomm: msg.blind_factor.clone(),
                };
                if is_valid_curve_point(msg.g_gamma_i.get_element())
                    && foreign_comm_scheme.verify_commitment(msg.g_gamma_i)
                    && DLogProof::verify(&msg.gamma_proof).is_ok()
                // TODO : map 2 possible bad outcomes into 2 errors
                {
                    None
                } else {
                    // TODO : add details of a problem
                    Some(SigningError::InvalidDecommitment { party: *party })
                }
            })
            .collect::<Vec<_>>();

        if verification_errors.is_empty() {
            let g: GE = ECPoint::generator();
            let g_gamma_i = g * self.gamma_i;

            let g_gamma_sum = responses
                .iter()
                .fold(g_gamma_i, |acc, msg| acc + msg.1.g_gamma_i);

            let R = g_gamma_sum * self.delta_inv;
            let local_sig =
                LocalSignature::new(&self.params.message_hash, &R, &self.k_i, &self.sigma_i);
            let (p5_commit, p5_decommit) = local_sig.phase5b_proof();

            Transition::NewState(Box::new(Phase5ab {
                params: self.params.clone(),
                multi_party_info: self.multi_party_info.clone(),
                other_parties: self.other_parties.clone(),
                R,
                sigma_i: self.sigma_i,
                local_sig,
                p5_commit,
                p5_decommit,
                subphase: SubPhaseAB::A,
                p5_commitments: HashMap::new(),
                timeout: self.timeout,
            }))
        } else {
            let error_state = ErrorState::new(verification_errors);
            log::error!("Phase 4 returns {:?}", error_state);
            Transition::FinalState(Err(error_state))
        }
    }
    fn timeout_outcome(&self, _current_msg_set: Vec<InMsg>) -> MachineResult {
        Err(ErrorState::new(vec![SigningError::Timeout {
            phase: "phase4".to_string(),
        }]))
    }

    fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
}

impl Drop for Phase4 {
    fn drop(&mut self) {
        self.k_i = FE::zero();
        self.gamma_i = FE::zero();
    }
}

/// Discriminates the sub phase in Phase 5 protocol
#[derive(Copy, Clone, PartialEq)]
enum SubPhaseAB {
    A,
    B,
}
/// Fifth phase of the protocol, sub-phases A and B
///
/// Subphase A, see  (5A) in the paper:
/// * Initializes [`phase5::LocalSignature`](phase5/struct.LocalSignature.html#method.new)
/// * Broadcasts [`Phase5Com1`](../messages/signing/struct.Phase5Com1.html)
///
/// Subphase B, see (5B) in the paper:
/// * Broadcasts [`Phase5Decom1`](../messages/signing/struct.Phase5Decom1.html)
/// * Verifies each party's `Phase5Com` using [`check_comms_A`](#method.check_comms_A)
///
struct Phase5ab {
    params: SigningParameters,
    multi_party_info: MultiPartyInfo,
    other_parties: BTreeSet<PartyIndex>,
    R: GE,
    sigma_i: FE,
    local_sig: LocalSignature,
    p5_commit: Phase5Com1,
    p5_decommit: Phase5Decom1,
    subphase: SubPhaseAB,
    p5_commitments: HashMap<PartyIndex, BigInt>,
    timeout: Option<Duration>,
}

#[trace(pretty, prefix = "Phase5a::")]
impl Phase5ab {
    fn check_comms_A(&self, party: &PartyIndex, msg: &Phase5Decom1) -> Result<(), SigningError> {
        let comm = self.p5_commitments.get(party).unwrap();
        let input_hash = HSha256::create_hash_from_ge(&[&msg.V_i, &msg.A_i, &msg.B_i]).to_big_int();
        let scheme = CommitmentScheme {
            comm: comm.clone(),
            decomm: msg.blind_factor.clone(),
        };
        if scheme.verify_hash(&input_hash)
            && is_valid_curve_point(msg.A_i.get_element())
            && is_valid_curve_point(msg.V_i.get_element())
        {
            Ok(())
        } else {
            Err(SigningError::InvalidDecommitment { party: *party })
        }
    }

    fn check_el_gamal_proof(
        &self,
        party: &PartyIndex,
        msg: &Phase5Decom1,
    ) -> Result<(), SigningError> {
        let delta = HomoElGamalStatement {
            G: msg.A_i,
            H: self.R,
            Y: ECPoint::generator(),
            D: msg.V_i,
            E: msg.B_i,
        };
        if msg.proof.verify(&delta).is_ok() {
            Ok(())
        } else {
            Err(SigningError::InvalidElGamalProof { party: *party })
        }
    }

    fn compute_va(&self, decomms: &HashMap<PartyIndex, Phase5Decom1>) -> (GE, GE) {
        let (V, A) = decomms.iter().fold(
            (self.p5_decommit.V_i, self.p5_decommit.A_i),
            |acc, (_, msg)| (acc.0 + msg.V_i, acc.1 + msg.A_i),
        );

        let r: FE = ECScalar::from(&self.R.x_coor().unwrap().mod_floor(&FE::q()));
        let yr = self.multi_party_info.public_key * r;
        let g: GE = ECPoint::generator();
        let m_fe = self.params.message_hash;
        let gm = g * m_fe;
        let V = V.sub_point(&gm.get_element()).sub_point(&yr.get_element());
        (V, A)
    }
}

impl Clone for Phase5ab {
    fn clone(&self) -> Self {
        Phase5ab {
            params: self.params.clone(),
            multi_party_info: self.multi_party_info.clone(),
            other_parties: self.other_parties.clone(),
            R: self.R,
            sigma_i: self.sigma_i,
            local_sig: self.local_sig.clone(),
            p5_commit: self.p5_commit.clone(),
            p5_decommit: self.p5_decommit.clone(),
            subphase: self.subphase,
            p5_commitments: self.p5_commitments.clone(),
            timeout: self.timeout,
        }
    }
}

#[trace(pretty, prefix = "Phase5a::")]
impl State<SigningTraits> for Phase5ab {
    fn start(&mut self) -> Option<OutMsgVec> {
        match &self.subphase {
            SubPhaseAB::A => {
                log::debug!("Subphase A starts");
                let output = vec![OutMsg {
                    recipient: Address::Broadcast,
                    body: Message::R5(self.p5_commit.clone()),
                }];
                Some(output)
            }
            SubPhaseAB::B => {
                log::debug!("Subphase B starts");
                let output = vec![OutMsg {
                    recipient: Address::Broadcast,
                    body: Message::R6(self.p5_decommit.clone()),
                }];
                Some(output)
            }
        }
    }

    #[trace(disable(current_msg_set))]
    fn is_message_expected(&self, msg: &InMsg, current_msg_set: &[InMsg]) -> bool {
        (match msg.body {
            Message::R5(_) => self.subphase == SubPhaseAB::A,
            Message::R6(_) => self.subphase == SubPhaseAB::B,
            _ => false,
        }) && self.other_parties.contains(&msg.sender)
            && !msg.is_duplicate(current_msg_set)
    }

    #[trace(disable(current_msg_set))]
    fn is_input_complete(&self, current_msg_set: &[InMsg]) -> bool {
        is_broadcast_input_complete(current_msg_set, &self.other_parties)
    }

    fn consume(&self, current_msg_set: Vec<InMsg>) -> Transition<SigningTraits> {
        match &self.subphase {
            SubPhaseAB::A => match to_hash_map_gen::<PartyIndex, Phase5Com1>(current_msg_set) {
                Ok(comms) => {
                    let mut new_state = self.clone();
                    new_state
                        .p5_commitments
                        .extend(comms.iter().map(|(party, msg)| (*party, msg.com.clone())));
                    new_state.subphase = SubPhaseAB::B;
                    Transition::NewState(Box::new(new_state))
                }
                Err(e) => {
                    let error_state = ErrorState::new(vec![e]);
                    log::error!("Phase 5a returns {:?}", error_state);
                    Transition::FinalState(Err(error_state))
                }
            },
            SubPhaseAB::B => {
                match to_hash_map_gen::<PartyIndex, Phase5Decom1>(current_msg_set) {
                    Ok(decomms) => {
                        let mut errors = decomms
                            .iter()
                            .filter_map(|(party, msg)| self.check_comms_A(party, msg).err())
                            .collect::<Vec<_>>();
                        errors.extend(decomms.iter().filter_map(|(party, msg)| {
                            self.check_el_gamal_proof(party, msg).err()
                        }));

                        let (V, A) = self.compute_va(&decomms);
                        let (p5commit2, p5decommit2) = self.local_sig.phase5d_proof(V, A);

                        if errors.is_empty() {
                            Transition::NewState(Box::new(Phase5cde {
                                params: self.params.clone(),
                                shared_keys: self.multi_party_info.clone(),
                                other_parties: self.other_parties.clone(),
                                R: self.R,
                                sigma_i: self.sigma_i,
                                local_sig: self.local_sig.clone(),
                                p5_decommit: self.p5_decommit.clone(),
                                p5_decommitments: decomms,
                                p5_commit2: p5commit2,
                                p5_decommit2: p5decommit2,
                                p5_commitments2: HashMap::new(),
                                subphase: SubPhaseCDE::C,
                                timeout: self.timeout,
                            }))
                        } else {
                            let error_state = ErrorState::new(errors);
                            log::error!("Phase 5a returns {:?}", error_state);
                            Transition::FinalState(Err(error_state))
                        }
                    }
                    Err(e) => {
                        let error_state = ErrorState::new(vec![e]);
                        log::error!("Phase 5a returns {:?}", error_state);
                        Transition::FinalState(Err(error_state))
                    }
                }
            }
        }
    }

    fn timeout_outcome(&self, _current_msg_set: Vec<InMsg>) -> MachineResult {
        Err(ErrorState::new(vec![SigningError::Timeout {
            phase: "phase5a".to_string(),
        }]))
    }

    fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
}

/// Discriminates the sub phase in Phase 5 protocol
#[derive(Copy, Clone, PartialEq)]
enum SubPhaseCDE {
    C,
    D,
    E,
}

/// Fifth phase of the protocol, sub phases C, D and E
///
/// Subphase C, see  (5C) in the paper:
/// * Broadcasts [`Phase5Com2`](../messages/signing/struct.Phase5Com2.html)
///
/// Subphase D, see (5D) in the paper:
/// * Broadcasts [`Phase5Decom2`](../messages/signing/struct.Phase5Decom2.html)
/// * Verifies each party's `Phase5Com` using [`check_comms`](#method.check_comms)
///
/// Subphase E:, see (5E) in the paper
/// * Broadcasts the partial signature [`Phase5Edata`](../messages/signing/struct.Phase5Edata.html)
/// * Reconstructs full signature and verifies it using standard method
struct Phase5cde {
    params: SigningParameters,
    shared_keys: MultiPartyInfo,
    other_parties: BTreeSet<PartyIndex>,
    R: GE,
    sigma_i: FE,
    local_sig: LocalSignature,
    p5_decommit: Phase5Decom1,
    p5_decommitments: HashMap<PartyIndex, Phase5Decom1>,
    p5_commit2: Phase5Com2,
    p5_decommit2: Phase5Decom2,
    p5_commitments2: HashMap<PartyIndex, BigInt>,
    subphase: SubPhaseCDE,
    timeout: Option<Duration>,
}

#[trace(pretty, prefix = "Phase5c::")]
impl Phase5cde {
    fn check_comms(&self, party: &PartyIndex, msg: &Phase5Decom2) -> Result<(), SigningError> {
        let comm = self.p5_commitments2.get(party).unwrap();
        let input_hash = HSha256::create_hash_from_ge(&[&msg.U_i, &msg.T_i]).to_big_int();
        let scheme = CommitmentScheme {
            comm: comm.clone(),
            decomm: msg.blind_factor.clone(),
        };
        if scheme.verify_hash(&input_hash) {
            Ok(())
        } else {
            Err(SigningError::InvalidDecommitment { party: *party })
        }
    }
}

impl Clone for Phase5cde {
    fn clone(&self) -> Self {
        Phase5cde {
            params: self.params.clone(),
            shared_keys: self.shared_keys.clone(),
            other_parties: self.other_parties.clone(),
            R: self.R,
            sigma_i: self.sigma_i,
            local_sig: self.local_sig.clone(),
            p5_commit2: self.p5_commit2.clone(),
            p5_decommit2: self.p5_decommit2.clone(),
            p5_commitments2: self.p5_commitments2.clone(),
            p5_decommit: self.p5_decommit.clone(),
            p5_decommitments: self.p5_decommitments.clone(),
            subphase: self.subphase,
            timeout: self.timeout,
        }
    }
}

#[trace(pretty, prefix = "Phase5c::")]
impl State<SigningTraits> for Phase5cde {
    fn start(&mut self) -> Option<OutMsgVec> {
        match &self.subphase {
            SubPhaseCDE::C => {
                log::debug!("Subphase C starts");
                let output = vec![OutMsg {
                    recipient: Address::Broadcast,
                    body: Message::R7(self.p5_commit2.clone()),
                }];
                Some(output)
            }
            SubPhaseCDE::D => {
                log::debug!("Subphase D starts");
                let output = vec![OutMsg {
                    recipient: Address::Broadcast,
                    body: Message::R8(self.p5_decommit2.clone()),
                }];
                Some(output)
            }
            SubPhaseCDE::E => {
                log::debug!("Subphase E starts");
                let output = vec![OutMsg {
                    recipient: Address::Broadcast,
                    body: Message::R9(Phase5Edata {
                        s_i: self.local_sig.s_i,
                    }),
                }];
                Some(output)
            }
        }
    }

    #[trace(disable(current_msg_set))]
    fn is_message_expected(&self, msg: &InMsg, current_msg_set: &[InMsg]) -> bool {
        (match msg.body {
            Message::R7(_) => self.subphase == SubPhaseCDE::C,
            Message::R8(_) => self.subphase == SubPhaseCDE::D,
            Message::R9(_) => self.subphase == SubPhaseCDE::E,
            _ => false,
        }) && self.other_parties.contains(&msg.sender)
            && !msg.is_duplicate(current_msg_set)
    }

    #[trace(disable(current_msg_set))]
    fn is_input_complete(&self, current_msg_set: &[InMsg]) -> bool {
        is_broadcast_input_complete(current_msg_set, &self.other_parties)
    }

    fn consume(&self, current_msg_set: Vec<InMsg>) -> Transition<SigningTraits> {
        match self.subphase {
            SubPhaseCDE::C => {
                let comms = match to_hash_map_gen::<PartyIndex, Phase5Com2>(current_msg_set) {
                    Ok(map) => map,
                    Err(e) => {
                        let error_state = ErrorState::new(vec![e]);
                        log::error!("Phase 5 returns {:?}", error_state);
                        return Transition::FinalState(Err(error_state));
                    }
                };

                let mut new_state = self.clone();
                new_state
                    .p5_commitments2
                    .extend(comms.iter().map(|(party, msg)| (*party, msg.com.clone())));
                new_state.subphase = SubPhaseCDE::D;
                Transition::NewState(Box::new(new_state))
            }
            SubPhaseCDE::D => {
                let decomms = match to_hash_map_gen::<PartyIndex, Phase5Decom2>(current_msg_set) {
                    Ok(map) => map,
                    Err(e) => {
                        let error_state = ErrorState::new(vec![e]);
                        log::error!("Phase 5 returns {:?}", error_state);
                        return Transition::FinalState(Err(error_state));
                    }
                };

                let mut errors = decomms
                    .iter()
                    .filter_map(|(party, msg)| self.check_comms(party, msg).err())
                    .collect::<Vec<_>>();

                let (t_sum, u_sum) = decomms.iter().fold(
                    (self.p5_decommit2.T_i, self.p5_decommit2.U_i),
                    |acc, (_, msg)| (acc.0 + msg.T_i, acc.1 + msg.U_i),
                );

                let g: GE = ECPoint::generator();

                if g != (g + t_sum).sub_point(&u_sum.get_element()) {
                    errors.push(SigningError::Phase5ValidationFailed)
                }

                if errors.is_empty() {
                    let mut new_state = self.clone();
                    new_state.subphase = SubPhaseCDE::E;
                    Transition::NewState(Box::new(new_state))
                } else {
                    let error_state = ErrorState::new(errors);
                    log::error!("Phase 5 returns {:?}", error_state);
                    Transition::FinalState(Err(error_state))
                }
            }
            SubPhaseCDE::E => {
                let local_signatures =
                    match to_hash_map_gen::<PartyIndex, Phase5Edata>(current_msg_set) {
                        Ok(map) => map,
                        Err(e) => {
                            let error_state = ErrorState::new(vec![e]);
                            log::error!("Phase 5 returns {:?}", error_state);
                            return Transition::FinalState(Err(error_state));
                        }
                    };
                {
                    let sig_vec = local_signatures
                        .into_iter()
                        .map(|(_, v)| v.s_i)
                        .collect::<Vec<_>>();
                    match self.local_sig.output_signature(
                        &sig_vec,
                        &self.shared_keys.public_key,
                        &self.params.message_hash,
                    ) {
                        Ok(signature) => Transition::FinalState(Ok(SignedMessage {
                            r: signature.r,
                            s: signature.s,
                            hash: self.params.message_hash,
                        })),
                        Err(_e) => {
                            log::error!("ECDSA signature verification error");
                            Transition::FinalState(Err(ErrorState::new(vec![
                                SigningError::SignatureVerificationFailed {},
                            ])))
                        }
                    }
                }
            }
        }
    }

    fn timeout_outcome(&self, _current_msg_set: Vec<InMsg>) -> MachineResult {
        Err(ErrorState::new(vec![SigningError::Timeout {
            phase: "phase5c".to_string(),
        }]))
    }

    fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
}

#[cfg(test)]
mod tests {

    use crate::ecdsa::signature::{InMsg, OutMsg, Phase1, SigningTraits};

    use crate::ecdsa::keygen::MultiPartyInfo;
    use crate::protocol::{Address, InputMessage, PartyIndex};
    use crate::state_machine::sync_channels::StateMachine;
    use anyhow::bail;
    use crossbeam_channel::{Receiver, Sender};
    use curv::elliptic::curves::traits::ECScalar;
    use curv::BigInt;
    use sha2::{Digest, Sha256};
    use std::path::Path;
    use std::{fs, thread};

    struct Node {
        party: PartyIndex,
        egress: Receiver<OutMsg>,
        ingress: Sender<InMsg>,
    }

    struct OutputMessageWithSource {
        msg: OutMsg,
        source: PartyIndex,
    }

    #[test]
    fn signing() -> anyhow::Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();
        signing_helper(false)
    }

    #[test]
    fn signing_with_range_proofs() -> anyhow::Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();
        signing_helper(true)
    }

    fn signing_helper(enable_range_proofs: bool) -> anyhow::Result<()> {
        let mut nodes = Vec::new();
        let mut handles = Vec::new();

        let mut hasher = Sha256::new();
        hasher.input("MPC TS signing tests");
        let msg_hash = ECScalar::from(&BigInt::from(hasher.result().as_slice()));

        // the valid output of keygen is stored in files keys{0,1,2}.json
        // hence the party n
        let mut parties: Vec<usize> = vec![0, 1, 2];
        // One party can be excluded because two remaining are sufficient to produce the signature
        parties.remove(1);
        let signing_parties: Vec<PartyIndex> = parties
            .iter()
            .map(|x| PartyIndex::from(*x))
            .collect::<Vec<_>>();

        for i in parties {
            let (ingress, rx) = crossbeam_channel::unbounded();
            let (tx, egress) = crossbeam_channel::unbounded();

            let path = if enable_range_proofs {
                format!("tests/data/zkrp-keys.{}.json", i)
            } else {
                format!("tests/data/keys.{}.json", i)
            };
            let path = Path::new(&path);
            let multi_party_shared_info: MultiPartyInfo =
                serde_json::from_str(&fs::read_to_string(path)?)?;

            assert!(!enable_range_proofs || multi_party_shared_info.range_proof_setups.is_some());
            let signing_parties = signing_parties.clone();
            log::info!("starting party {}", i);
            let join_handle = thread::spawn(move || {
                let start_state = Box::new(Phase1::new(
                    msg_hash,
                    multi_party_shared_info,
                    &signing_parties,
                    None,
                )?);
                let mut machine = StateMachine::<SigningTraits>::new(start_state, &rx, &tx);
                match machine.execute() {
                    Some(Ok(fs)) => {
                        log::info!("success");
                        Ok(fs)
                    }
                    Some(Err(e)) => {
                        bail!("error {:?}", e);
                    }
                    None => {
                        bail!("error in the machine");
                    }
                }
            });
            nodes.push(Node {
                party: i.clone().into(),
                egress,
                ingress,
            });
            handles.push(join_handle);
        }

        let _mx_thread = thread::spawn(move || {
            loop {
                let mut output_messages = Vec::new();
                // collect output from nodes
                for node in nodes.iter() {
                    if let Ok(out_msg) = node.egress.try_recv() {
                        output_messages.push(OutputMessageWithSource {
                            msg: out_msg,
                            source: node.party,
                        });
                    }
                }
                // forward collected messages
                output_messages
                    .iter()
                    .for_each(|mm| match &mm.msg.recipient {
                        Address::Broadcast => {
                            log::trace!(
                                "broadcast from {} to parties {:?}",
                                mm.source,
                                nodes
                                    .iter()
                                    .filter(|node| node.party != mm.source)
                                    .map(|node| node.party)
                                    .collect::<Vec<_>>()
                            );
                            nodes
                                .iter()
                                .filter(|node| node.party != mm.source)
                                .for_each(|node| {
                                    let message_to_deliver = InputMessage {
                                        sender: mm.source,
                                        body: mm.msg.body.clone(),
                                    };
                                    node.ingress.send(message_to_deliver).unwrap();
                                });
                        }
                        Address::Peer(peer) => {
                            if let Some(node) = nodes.iter().find(|node| (*node).party == *peer) {
                                log::trace!("unicast from {} to  {:?}", mm.source, *peer);
                                node.ingress
                                    .send(InputMessage {
                                        sender: mm.source,
                                        body: mm.msg.body.clone(),
                                    })
                                    .unwrap();
                            }
                        }
                    })
            }
        });

        //
        let results = handles.into_iter().map(|h| h.join()).collect::<Vec<_>>();
        if results
            .iter()
            .any(|r| r.is_err() || r.as_ref().unwrap().is_err())
        {
            results.iter().for_each(|r| match r {
                Ok(result) => match result {
                    Ok(final_state) => log::error!("{:?}", final_state),
                    Err(e) => log::error!("{:?}", e),
                },
                Err(e) => log::error!("{:?}", e),
            });
            assert!(false, "Some state machines returned error");
        }

        // safe to assume here that results contain FinalState only, no errors
        let _final_states = results
            .into_iter()
            .map(|x| x.unwrap().unwrap())
            .collect::<Vec<_>>();

        Ok(())
    }
}
