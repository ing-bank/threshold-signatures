//! Multi-party key generation
//!
//! Multi-party key generation, as defined in *"Fast multiparty threshold ECDSA with Fast trustless setup"*, chapter 4.1
//!
//! * The key shard is sampled randomly by each party. The resulting public key is the product of partial public keys and the resulting private key is the sum of individual private keys.
//! * Private keys are shared with Shamir's secret sharing schema. The signing threshold is fixed for a key.
//! * Traditional attacks on this schema are addressed by non-malleable commitments to a partial public key and by Feldman's verifiable secret sharing.
//!
//! # Details
//!
//! The protocol can be started in two steps:
//! * Create [`Phase1`]
//! * Create the [`StateMachine`] and set the instance of [`Phase1`] as its argument.
//!
//! # Example
//!
//! * creates the stream `protocol_sink` for incoming messages
//! * creates another stream `state_machine_stream` for outgoing messages
//! * generates new keys
//! * instantiates [`Phase1`] of the protocol with parameters *(key, initial secrets, optional range proof setup, own party index,  key loader)*
//! * creates state machine providing the [`Phase1`] object and streams as arguments
//! * executes the machine and obtains the result
//! ```text
//!   let (protocol_sink, protocol_stream) = mpsc::unbounded();
//!   let (state_machine_sink, state_machine_stream) = mpsc::unbounded();
//!   let init_keys = InitialKeys::random();
//!   let init_pubkeys = InitialPublicKeys::from(init_keys);
//!   // to do: save the copy of init_keys to the vault here
//!   init_keys.zeroize();
//!   let key_loader = Arc::new(Box::new(SecretKeyLoaderImpl::new(the_vault)));
//!
//!   let start_phase = Box::new(Phase1::new(
//!             &parameters,
//!             init_pubkeys,
//!             range_proofs_setup,
//!             myself,
//!             key_loader
//!         ));
//!
//!   let state_machine = StateMachine::new(start_phase, protocol_stream, state_machine_sink);
//!   // to do: share protocol_stream and state_machine_sink with a network layer
//!   let result = state_machine.execute(); // .await() if the machine is async
//! ```
//!
//! Loading secrets from a vault requires a proxy object which implements `SecretKeyLoader` trait. The following example shows what is expected from this object:
//!
//! ```text
//!
//!     // Creates dummy vault
//!     struct Wallet {
//!         pub records: HashMap<usize, InitialKeys>,
//!     }
//!
//!     impl Wallet {
//!         pub fn new(keys: HashMap<usize, InitialKeys>) -> Self {
//!             Self { records: keys }
//!         }
//!     }
//!
//!    // Wraps dummy vault with key loader
//!    struct SecretKeyLoaderImpl {
//!         wallet: Arc<Mutex<Wallet>>,
//!         key_index: usize,
//!     }
//!
//!     impl SecretKeyLoaderImpl {
//!         pub fn new(wallet: &Arc<Mutex<Wallet>>, key_index: usize) -> Self {
//!             Self {
//!                 wallet: wallet.clone(),
//!                 key_index,
//!             }
//!         }
//!     }
//!
//!     impl SecretKeyLoader for SecretKeyLoaderImpl {
//!         fn get_initial_secret(&self) -> Result<Secp256k1Scalar,SecretKeyLoaderError> {
//!             let wallet = self.wallet.lock().map_err(|e| SecretKeyLoaderError(e.to_string()))?;
//!
//!             Ok(wallet
//!                 .records
//!                 .get(&self.key_index)
//!                 .ok_or(SecretKeyLoaderError("key not found".to_string()))?
//!                 .u_i
//!             )
//!         }
//!
//!         fn get_paillier_secret(&self) -> Result<DecryptionKey,SecretKeyLoaderError> {
//!             let wallet = self.wallet.lock().map_err(|e| SecretKeyLoaderError(e.to_string()))?;
//!
//!             Ok(wallet
//!                 .records
//!                 .get(&self.key_index)
//!                 .ok_or(SecretKeyLoaderError("key not found".to_string()))?
//!                 .paillier_keys
//!                 .dk
//!                 .clone()
//!             )
//!        }
//!    }
//! ```
//!
//! [`StateMachine`]: ../../state_machine/async_channels/struct.StateMachine.html
//! [`Phase1`]: struct.Phase1.html

use std::collections::{BTreeSet, HashMap, HashSet};

use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::ProveDLog;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};

use crate::ecdsa::messages::{FeldmanVSS, SecretShare};

use crate::algorithms::nizk_rsa;
use crate::ecdsa::{
    from_secp256k1_pk, is_valid_curve_point, CommitmentScheme, InitialPublicKeys,
    ManagedPaillierDecryptionKey, ManagedSecretKey, PaillierKeys, Parameters,
};
use crate::protocol::{Address, PartyIndex};
pub use paillier::DecryptionKey;
use paillier::EncryptionKey;
use thiserror::Error;

#[doc(inline)]
pub use super::messages::keygen::{DecommitPublicKey, InMsg, Message, OutMsg, Phase1Broadcast};

use crate::state_machine::{State, StateMachineTraits, Transition};
use serde::{Deserialize, Serialize};

use crate::algorithms::zkp::{ZkpPublicSetup, ZkpSetup, ZkpSetupVerificationError};
use std::iter::FromIterator;
use std::sync::Arc;
use std::time::Duration;
use trace::trace;
use zeroize::Zeroize;

/// Interface for loading secrets , for example, loading pre-determined record from a vault
pub trait SecretKeyLoader: std::fmt::Debug {
    fn get_initial_secret(&self) -> Result<Box<FE>, SecretKeyLoaderError>;
    fn get_paillier_secret(&self) -> Result<Box<DecryptionKey>, SecretKeyLoaderError>;
}

#[derive(Debug)]
pub struct SecretKeyLoaderError(pub String);

/// the type of the reference to [`SecretKeyLoader`]  used by key generation protocol to load secret key of EC schema or secret Paillier key
///
/// # Rationale
/// The state machine does not keep these secret keys in memory. It loads them on demand and erased them shorty afterwards by using [`SecretKeyLoader`] trait.
/// Main application has to provide a proxy object which implements the interface to the method [`Phase1::new`].
/// For example, it can be object which loads the key from a vault where the address of a record within the vault is pre-initialized.
///
/// [`SecretKeyLoader`]: trait.SecretKeyLoader.html
/// [`Phase1::new`]: struct.Phase1#method.new
pub type ASecretKeyLoader = Arc<Box<dyn SecretKeyLoader + Send + Sync>>;

/// Zero knowledge proof of Paillier key's correctness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrectKeyProof(pub Vec<BigInt>);

/// Enumerates error type which can be raised by key generation protocol
#[derive(Debug, Error)]
#[allow(clippy::large_enum_variant)]
pub enum KeygenError {
    #[error("Key generation cannot be started: {0}")]
    IncorrectParameters(String),
    #[error("keygen: timeout in {phase}")]
    Timeout { phase: String },
    #[error("invalid decommitment {decomm}, commitment {comm}, party {party}")]
    InvalidComm {
        comm: String,
        decomm: String,
        party: PartyIndex,
    },
    #[error("invalid secret sharing {vss}, party {party}")]
    InvalidVSS { vss: String, party: PartyIndex },
    #[error("Number of parties responded ({parties_responded}) is not same as share count ({share_count}) - 1")]
    NumberOfPartiesMismatch {
        parties_responded: usize,
        share_count: usize,
    },
    #[error("multiple points on the polynomial encountered {points:?}")]
    MultiplePointsUsed { points: String },
    #[error("received point has wrong X coordinate: {x_coord}")]
    WrongXCoordinate { x_coord: usize },
    #[error("invalid public key {point}, party {party}")]
    InvalidPublicKey { point: String, party: PartyIndex },
    #[error("unexpected message {message_type:?}, party {party}")]
    UnknownMessageType {
        message_type: Message,
        party: PartyIndex,
    },
    #[error("invalid dlog proof {proof}, party {party}")]
    InvalidDlogProof { proof: String, party: PartyIndex },
    #[error("invalid correct key proof {proof}, party {party}")]
    InvalidCorrectKeyProof { proof: String, party: PartyIndex },
    #[error("missing range proof from {party} ")]
    RangeProofSetupMissing { party: PartyIndex },
    #[error("unexpected range proof from {party}, proof {proof:?} ")]
    RangeProofSetupUnexpected { proof: String, party: PartyIndex },
    #[error("range proof setup: dlog proof failed , party {party}, proof {proof} ")]
    RangeProofSetupDlogProofFailed { proof: String, party: PartyIndex },
    #[error("protocol setup error: {0}")]
    ProtocolSetupError(String),
    #[error("{0}")]
    GeneralError(String),
}

impl super::InitialKeys {
    /// samples from randomness
    pub fn random() -> Self {
        let u: FE = ECScalar::new_random();

        #[allow(clippy::op_ref)]
        let y = &ECPoint::generator() * &u;
        super::InitialKeys {
            u_i: u,
            y_i: y,
            paillier_keys: PaillierKeys::random(),
        }
    }
}

/// Comprises various outputs of key generation protocol
///
/// The output value of key generation protocol and input parameter for signing protocol. Has to be saved to wallet/vault.   
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MultiPartyInfo {
    pub key_params: Parameters,
    pub own_party_index: PartyIndex,
    pub secret_share: SecretShare,
    pub public_key: GE,
    pub own_he_keys: PaillierKeys,
    pub party_he_keys: HashMap<PartyIndex, EncryptionKey>,
    pub party_to_point_map: Party2PointMap,
    pub range_proof_setups: Option<RangeProofSetups>,
}

impl MultiPartyInfo {
    pub fn own_point(&self) -> usize {
        self.secret_share.0
    }
    pub fn own_share(&self) -> FE {
        self.secret_share.1
    }
}

/// Range proof private setup of ours and public versions of setups shared by other parties  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeProofSetups {
    pub my_setup: ZkpSetup,
    pub party_setups: HashMap<PartyIndex, ZkpPublicSetup>,
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
fn to_hash_map_gen<K, V>(current_msg_set: Vec<InMsg>) -> Result<HashMap<K, V>, Vec<KeygenError>>
where
    K: std::cmp::Eq + std::hash::Hash + std::convert::From<PartyIndex> + std::fmt::Debug,
    V: std::fmt::Debug,
    Option<V>: std::convert::From<Message>,
{
    let (converted_messages, errors) =
        current_msg_set
            .iter()
            .fold((vec![], vec![]), |(mut values, mut errors), m| {
                let body: Option<V> = m.body.clone().into();
                match body {
                    Some(b) => values.push((m.sender, b)),
                    None => errors.push(KeygenError::UnknownMessageType {
                        message_type: m.body.clone(),
                        party: m.sender,
                    }),
                };
                (values, errors)
            });

    if errors.is_empty() {
        Ok(converted_messages
            .into_iter()
            .map(|(party, body)| (party.into(), body))
            .collect::<HashMap<K, V>>())
    } else {
        Err(errors)
    }
}

#[doc(hidden)]
type OutMsgVec = Vec<OutMsg>;

/// Type definitions
#[derive(Debug)]
pub struct KeyGeneratorTraits;

impl StateMachineTraits for KeyGeneratorTraits {
    type InMsg = InMsg;
    type OutMsg = OutMsg;
    type FinalState = FinalState;
    type ErrorState = ErrorState;
}
pub type MachineResult = Result<FinalState, ErrorState>;

/// First phase of key generation protocol
///
/// Generates and broadcasts:
/// * the commitment to public key of EC scheme
/// * new Paillier pair
/// * ZKP of correct Paillier private key
/// * proof of correct range proof setup, if applicable
///
/// Receives all aforementioned from other parties, verifies proofs. If succeeds , stores commitments, public Paiilier keys, and public range proof setups  to their respective hash maps.
#[derive(Debug)]
pub struct Phase1 {
    params: Parameters,
    keys: InitialPublicKeys,
    own_party_index: PartyIndex,
    other_parties: BTreeSet<PartyIndex>,
    comm_scheme: CommitmentScheme,
    secret_key_loader: ASecretKeyLoader,
    paillier_key_proof: CorrectKeyProof,
    range_proof_setup: Option<ZkpSetup>,
    timeout: Option<Duration>,
}

#[doc(hidden)]
fn verify_zkp_public_setup(setup: &ZkpSetup) -> Result<(), ZkpSetupVerificationError> {
    let public_setup = ZkpPublicSetup::from_private_zkp_setup(&setup);
    public_setup.verify()
}

#[trace(pretty, prefix = "Phase1::")]
impl Phase1 {
    /// initializes the protocol
    pub fn new(
        params: &Parameters,
        init_keys: InitialPublicKeys,
        range_proof_setup: Option<ZkpSetup>,
        parties: &[PartyIndex],
        own_party_index: PartyIndex,
        secret_key_loader: ASecretKeyLoader,
        timeout: Option<Duration>,
    ) -> Result<Self, KeygenError> {
        let proof = {
            let dk = secret_key_loader
                .get_paillier_secret()
                .map(|dk| ManagedPaillierDecryptionKey(dk))
                .map_err(|e| KeygenError::ProtocolSetupError(e.0))?;
            if !PaillierKeys::is_valid(&init_keys.paillier_encryption_key, &dk.0) {
                return Err(KeygenError::ProtocolSetupError(
                    "invalid own Paillier key".to_string(),
                ));
            }
            nizk_rsa::gen_proof(&dk.0)
        };
        let scheme = CommitmentScheme::from_GE(&init_keys.y_i);

        let acting_parties = BTreeSet::from_iter(parties.iter().cloned());
        if acting_parties.len() != parties.len() {
            return Err(KeygenError::ProtocolSetupError(
                "duplicate entries in signing parties' list".to_string(),
            ));
        }
        if acting_parties.get(&own_party_index).is_none() {
            return Err(KeygenError::ProtocolSetupError(
                "own party index not in the list of signing parties".to_string(),
            ));
        }

        let mut other_parties = acting_parties;
        other_parties.remove(&own_party_index);

        if let Some(setup) = &range_proof_setup {
            verify_zkp_public_setup(setup)
                .map_err(|e| KeygenError::ProtocolSetupError(format!("{:?}", e)))?;
        } else {
            return Err(KeygenError::ProtocolSetupError(
                "Using this signature scheme without range proofs is insecure".to_string(),
            ));
        }
        Ok(Phase1 {
            params: *params,
            keys: init_keys,
            own_party_index,
            other_parties,
            comm_scheme: scheme,
            secret_key_loader,
            paillier_key_proof: CorrectKeyProof(proof),
            range_proof_setup,
            timeout,
        })
    }
}

#[trace(pretty, prefix = "Phase1::")]
impl State<KeyGeneratorTraits> for Phase1 {
    fn start(&mut self) -> Option<OutMsgVec> {
        log::info!("Phase1 starts");
        let zkp_public_setup = self
            .range_proof_setup
            .as_ref()
            .map(|s| ZkpPublicSetup::from_private_zkp_setup(&s));

        let output = vec![OutMsg {
            recipient: Address::Broadcast,
            body: Message::R1(Phase1Broadcast {
                com: self.comm_scheme.comm.clone(),
                e: self.keys.paillier_encryption_key.clone(),
                correct_key_proof: self.paillier_key_proof.clone(),
                range_proof_setup: zkp_public_setup,
            }),
        }];
        Some(output)
    }
    #[trace(disable(input))]
    fn is_message_expected(&self, msg: &InMsg, input: &[InMsg]) -> bool {
        matches!(msg.body, Message::R1(_) if self.other_parties.contains(&msg.sender) && !msg.is_duplicate(input))
    }

    #[trace(disable(current_msg_set))]
    fn is_input_complete(&self, current_msg_set: &[InMsg]) -> bool {
        is_broadcast_input_complete(current_msg_set, &self.other_parties)
    }

    fn consume(&self, current_msg_set: Vec<InMsg>) -> Transition<KeyGeneratorTraits> {
        match to_hash_map_gen::<PartyIndex, Phase1Broadcast>(current_msg_set) {
            Ok(comms) => {
                let errors = comms
                    .iter()
                    .filter_map(
                        |(&p, m)| match (&self.range_proof_setup, &m.range_proof_setup) {
                            (Some(_), None) => {
                                Some(KeygenError::RangeProofSetupMissing { party: p })
                            }
                            (None, Some(s)) => Some(KeygenError::RangeProofSetupUnexpected {
                                party: p,
                                proof: format!("{:?}", s.dlog_proof),
                            }),
                            (Some(_), Some(setup)) => setup.verify().map_or_else(
                                |e| {
                                    Some(KeygenError::RangeProofSetupDlogProofFailed {
                                        proof: format!("{:?} {:?}", e, setup.dlog_proof),
                                        party: p,
                                    })
                                },
                                |_| None,
                            ),
                            _ => None,
                        },
                    )
                    .collect::<Vec<_>>();

                if errors.is_empty() {
                    let range_proof_setups =
                        self.range_proof_setup.as_ref().map(|s| RangeProofSetups {
                            my_setup: s.clone(),
                            party_setups: comms
                                .iter()
                                .map(|(&p, m)| {
                                    (
                                        p,
                                        m.range_proof_setup
                                            .as_ref()
                                            .expect("range proof setup can't be None here")
                                            .clone(),
                                    )
                                })
                                .collect::<HashMap<_, _>>(),
                        });
                    Transition::NewState(Box::new(Phase2 {
                        keys: self.keys.clone(),
                        params: self.params,
                        own_party_index: self.own_party_index,
                        other_parties: self.other_parties.clone(),
                        comm_scheme: self.comm_scheme.clone(),
                        commitments: comms,
                        secret_key_loader: self.secret_key_loader.clone(),
                        range_proof_setups,
                        timeout: self.timeout,
                    }))
                } else {
                    let error_state = ErrorState::new(errors);
                    log::error!("Phase1 returns {:?}", error_state);
                    Transition::FinalState(Err(error_state))
                }
            }
            Err(e) => {
                let error_state = ErrorState::new(e);
                log::error!("Phase1 returns {:?}", error_state);
                Transition::FinalState(Err(error_state))
            }
        }
    }
    fn timeout_outcome(&self, _current_msg_set: Vec<InMsg>) -> MachineResult {
        Err(ErrorState::new(vec![KeygenError::Timeout {
            phase: "phase1".to_string(),
        }]))
    }
    fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
}

/// Second phase of the protocol: broadcasts decommitments, verifies them, and verifies Pailliier key correctness
struct Phase2 {
    params: Parameters,
    keys: InitialPublicKeys,
    own_party_index: PartyIndex,
    other_parties: BTreeSet<PartyIndex>,
    comm_scheme: CommitmentScheme,
    commitments: HashMap<PartyIndex, Phase1Broadcast>,
    secret_key_loader: ASecretKeyLoader,
    range_proof_setups: Option<RangeProofSetups>,
    timeout: Option<Duration>,
}

impl Phase2 {
    #[trace]
    fn map_parties_to_shares(
        &self,
        party_list: Vec<PartyIndex>,
        mut outgoing_shares: Vec<FE>,
    ) -> HashMap<PartyIndex, SecretShare> {
        let party_indexes_sorted = party_list.into_iter().collect::<BTreeSet<_>>();
        let number_of_parties = party_indexes_sorted.len();
        let result = party_indexes_sorted
            .into_iter()
            .zip(1..=number_of_parties)
            .zip(outgoing_shares.iter().cloned())
            .map(|((party, index), share)| (party, (index, share)))
            .collect::<HashMap<_, _>>();

        // Simultaneously remove and zeroize elements.
        outgoing_shares.drain(..).for_each(|mut s| s.zeroize());

        result
    }
}

#[trace(pretty, prefix = "Phase2::")]
impl State<KeyGeneratorTraits> for Phase2 {
    fn start(&mut self) -> Option<OutMsgVec> {
        log::debug!("Phase2 starts");
        Some(vec![OutMsg {
            recipient: Address::Broadcast,
            body: Message::R2(DecommitPublicKey {
                y_i: self.keys.y_i,
                blind_factor: self.comm_scheme.decomm.clone(),
            }),
        }])
    }

    #[trace(disable(input))]
    fn is_message_expected(&self, msg: &InMsg, input: &[InMsg]) -> bool {
        matches!(msg.body, Message::R2(_) if self.other_parties.contains(&msg.sender) && !msg.is_duplicate(input))
    }

    #[trace(disable(current_msg_set))]
    fn is_input_complete(&self, current_msg_set: &[InMsg]) -> bool {
        is_broadcast_input_complete(current_msg_set, &self.other_parties)
    }

    fn consume(&self, current_msg_set: Vec<InMsg>) -> Transition<KeyGeneratorTraits> {
        let decomms = match to_hash_map_gen::<PartyIndex, DecommitPublicKey>(current_msg_set) {
            Ok(map) => map,
            Err(e) => return Transition::FinalState(Err(ErrorState::new(e))),
        };

        let mut errors = Vec::new();

        let factorization_errors = self
            .commitments
            .iter()
            .filter_map(|(party, msg)| {
                if nizk_rsa::verify(&msg.e, &msg.correct_key_proof.0).is_err() {
                    Some(KeygenError::InvalidCorrectKeyProof {
                        proof: format!("{:?}", msg.correct_key_proof),
                        party: *party,
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        errors.extend(factorization_errors);

        let party_index_set = self
            .commitments
            .keys()
            .chain(decomms.keys())
            .collect::<HashSet<_>>();

        let commitment_errors = party_index_set
            .iter()
            .filter_map(|party| {
                let comm_message = self.commitments.get(party);
                let decomm_message = decomms.get(party);
                match (comm_message, decomm_message) {
                    (Some(comm), Some(decomm)) => {
                        let scheme = CommitmentScheme {
                            comm: comm.com.clone(),
                            decomm: decomm.blind_factor.clone(),
                        };
                        if scheme.verify_commitment(decomm.y_i) {
                            None
                        } else {
                            Some(KeygenError::InvalidComm {
                                comm: format!("{:?}", scheme.comm),
                                decomm: format!("{:?}", scheme.decomm),
                                party: **party,
                            })
                        }
                    }
                    _ => Some(KeygenError::InvalidComm {
                        comm: format!("{:?}", comm_message.map(|m| m.com.clone())),
                        decomm: format!("{:?}", decomm_message.map(|m| m.blind_factor.clone())),
                        party: **party,
                    }),
                }
            })
            .collect::<Vec<_>>();

        errors.extend(commitment_errors);

        // make map of ids of parties which broadcast their partial pubkey
        let mut pubkey_map = decomms
            .iter()
            .map(|(party, msg)| (*party, msg.y_i))
            .collect::<HashMap<PartyIndex, GE>>();
        // add local public key too
        pubkey_map.insert(self.own_party_index, self.keys.y_i);

        let party_list = pubkey_map.keys().copied().collect::<Vec<PartyIndex>>();

        let paillier_keys = self
            .commitments
            .iter()
            .map(|(party, msg)| (*party, msg.e.clone()))
            .collect::<HashMap<PartyIndex, EncryptionKey>>();

        let sk_loader_result = self
            .secret_key_loader
            .get_initial_secret()
            .map(|s| ManagedSecretKey(s));
        if let Err(e) = &sk_loader_result {
            errors.push(KeygenError::GeneralError(e.0.clone()));
        }

        if !errors.is_empty() {
            log::error!("Phase2 returns errors {:?}", errors);
            return Transition::FinalState(Err(ErrorState::new(errors)));
            //sk_loader_result is dropped here
        }

        let (vss_scheme, outgoing_shares) = {
            let sk = sk_loader_result.unwrap();
            let vss_sharing =
                VerifiableSS::share(self.params.threshold, self.params.share_count, &sk.0);
            vss_sharing
        }; // sk is dropped here

        let mapped_shares = self.map_parties_to_shares(party_list, outgoing_shares);
        let (parties_points, own_point): (Vec<(_, _)>, Vec<(_, _)>) = mapped_shares
            .into_iter()
            .partition(|(party, _)| *party != self.own_party_index);
        let own_point = own_point[0].1;
        let other_points = parties_points
            .into_iter()
            .map(|(party, share_xy)| (party, share_xy))
            .collect::<HashMap<_, _>>();

        Transition::NewState(Box::new(Phase3 {
            params: self.params,
            keys: self.keys.clone(),
            own_party_index: self.own_party_index,
            other_parties: self.other_parties.clone(),
            paillier_keys,
            pubkey_map,
            own_point,
            other_points,
            vss_scheme,
            secret_key_loader: self.secret_key_loader.clone(),
            range_proof_setups: self.range_proof_setups.clone(),
            timeout: self.timeout,
        }))
    }

    fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
    fn timeout_outcome(&self, _current_msg_set: Vec<InMsg>) -> MachineResult {
        Err(ErrorState::new(vec![KeygenError::Timeout {
            phase: "phase2".to_string(),
        }]))
    }
}
/// Computes the sum of points on the curve and validates every point
/// Returns Ok(Some(pk)) on success
/// Returns Ok(None) if the input list of points is empty
/// Uses PublicKey type from underlying secp256k1 library to work around limited API in curv crate
fn try_computing_public_key(
    pubkey_map: &HashMap<PartyIndex, GE>,
) -> Result<curv::PK, Vec<KeygenError>> {
    if pubkey_map.is_empty() {
        return Err(vec![KeygenError::GeneralError(
            "cant reconstruct public key: input list is empty".to_string(),
        )]);
    }

    let evec = pubkey_map.iter().fold(Vec::new(), |mut evec, point| {
        if !is_valid_curve_point(point.1.get_element()) {
            evec.push(KeygenError::InvalidPublicKey {
                point: format!("Party {}, point {:?}", point.0, point.1.get_element()),
                party: *point.0,
            });
        }
        evec
    });

    if evec.is_empty() {
        let acc: Option<curv::PK> = None;
        let sum = pubkey_map.iter().fold(acc, |acc, point| match acc {
            None => Some(point.1.get_element()),
            Some(v) => Some(
                v.combine(&point.1.get_element())
                    .expect("invalid curve point"),
            ),
        });
        Ok(sum.unwrap())
    } else {
        Err(evec)
    }
}

/// Third phase of the protocol: broadcasts Shamir's shares with Feldman's proofs and verifies them
struct Phase3 {
    params: Parameters,
    keys: InitialPublicKeys,
    own_party_index: PartyIndex,
    other_parties: BTreeSet<PartyIndex>,
    paillier_keys: HashMap<PartyIndex, EncryptionKey>,
    pubkey_map: HashMap<PartyIndex, GE>,
    own_point: SecretShare,
    other_points: HashMap<PartyIndex, SecretShare>,
    vss_scheme: VerifiableSS,
    secret_key_loader: ASecretKeyLoader,
    range_proof_setups: Option<RangeProofSetups>,
    timeout: Option<Duration>,
}

#[trace(pretty, prefix = "Phase3::")]
impl State<KeyGeneratorTraits> for Phase3 {
    fn start(&mut self) -> Option<OutMsgVec> {
        log::debug!("Phase3 starts");

        Some(
            self.other_points
                .iter()
                .map(|(party, share_xy)| OutMsg {
                    recipient: Address::Peer(*party),
                    body: Message::R3(FeldmanVSS {
                        vss: self.vss_scheme.clone(),
                        share: *share_xy,
                    }),
                })
                .collect::<OutMsgVec>(),
        )
    }

    #[trace(disable(input))]
    fn is_message_expected(&self, msg: &InMsg, input: &[InMsg]) -> bool {
        matches!(msg.body, Message::R3(_)  if self.other_parties.contains(&msg.sender) && !msg.is_duplicate(input))
    }

    #[trace(disable(current_msg_set))]
    fn is_input_complete(&self, current_msg_set: &[InMsg]) -> bool {
        is_broadcast_input_complete(current_msg_set, &self.other_parties)
    }

    fn consume(&self, current_msg_set: Vec<InMsg>) -> Transition<KeyGeneratorTraits> {
        let mut shares = match to_hash_map_gen::<PartyIndex, FeldmanVSS>(current_msg_set) {
            Ok(map) => map,
            Err(e) => return Transition::FinalState(Err(ErrorState::new(e))),
        };

        let mut errors = shares
            .iter()
            .filter_map(|(party, fvss)| {
                if let Some(pubkey) = self.pubkey_map.get(party) {
                    if fvss.verify(pubkey) {
                        None
                    } else {
                        Some(KeygenError::InvalidVSS {
                            vss: format!("{:?}", fvss),
                            party: *party,
                        })
                    }
                } else {
                    Some(KeygenError::GeneralError(format!(
                        "pubkey is missing for party {}",
                        party
                    )))
                }
            })
            .collect::<Vec<_>>();

        // assert that SharedSecrets have same x-coord
        let x_coords = shares
            .iter()
            .map(|(_, fvss)| fvss.share.0)
            .collect::<HashSet<_>>();
        if x_coords.len() != 1 {
            errors.push(KeygenError::MultiplePointsUsed {
                points: format!("{:?}", x_coords),
            });
        }

        let x_coord = x_coords.into_iter().collect::<Vec<_>>()[0];
        if x_coord != self.own_point.0 {
            errors.push(KeygenError::WrongXCoordinate { x_coord });
        }

        let private_share = shares
            .iter()
            .fold(self.own_point.1, |acc, (_party, fvss)| acc + fvss.share.1);

        shares.values_mut().for_each(|x| x.zeroize());

        let public_key = match try_computing_public_key(&self.pubkey_map) {
            Err(pk_verification_errors) => {
                errors.extend(pk_verification_errors);
                None
            }
            Ok(pk) => Some(pk),
        };

        let dk_loader_result = self
            .secret_key_loader
            .get_paillier_secret()
            .map(|dk| ManagedPaillierDecryptionKey(dk));

        if let Err(e) = &dk_loader_result {
            errors.push(KeygenError::GeneralError(e.0.clone()));
        }

        if !errors.is_empty() {
            log::error!("Phase3 returns errors {:?}", errors);
            return Transition::FinalState(Err(ErrorState::new(errors)));
        }

        // panic() on dk_loader_result.unwrap() is unreachable as dk_loader_result.is_err() is checked above
        let dk = dk_loader_result.unwrap();
        // panic() on public_key.unwrap() is unreachable as try_computing_public_key().is_err() is checked above
        let public_key = from_secp256k1_pk(public_key.unwrap()).expect("invalid full public key");
        let points = self
            .other_points
            .iter()
            .map(|(p, share_xy)| (*p, share_xy.0))
            .collect();

        let new_state = Transition::NewState(Box::new(Phase4 {
            own_party_index: self.own_party_index,
            other_parties: self.other_parties.clone(),
            multiparty_shared: MultiPartyInfo {
                key_params: self.params,
                own_party_index: self.own_party_index,
                secret_share: (self.own_point.0, private_share),
                public_key,
                own_he_keys: PaillierKeys {
                    ek: self.keys.paillier_encryption_key.clone(),
                    dk: (*dk.0).clone(),
                },
                party_he_keys: self.paillier_keys.clone(),
                party_to_point_map: Party2PointMap { points },
                range_proof_setups: self.range_proof_setups.clone(),
            },
            timeout: self.timeout,
        }));
        new_state
    }

    fn timeout_outcome(&self, _current_msg_set: Vec<InMsg>) -> MachineResult {
        Err(ErrorState::new(vec![KeygenError::Timeout {
            phase: "phase3".to_string(),
        }]))
    }
    fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
}

/// Last phase of the protocol: broadcasts `DlogProof` for partial key share and verifies it
struct Phase4 {
    own_party_index: PartyIndex,
    other_parties: BTreeSet<PartyIndex>,
    multiparty_shared: MultiPartyInfo,
    timeout: Option<Duration>,
}
#[trace(pretty, prefix = "Phase4::")]
impl State<KeyGeneratorTraits> for Phase4 {
    fn start(&mut self) -> Option<OutMsgVec> {
        log::debug!("Phase4 starts");
        let dlog_proof = DLogProof::prove(&self.multiparty_shared.own_share());
        Some(vec![OutMsg {
            recipient: Address::Broadcast,
            body: Message::R4(dlog_proof),
        }])
    }

    #[trace(disable(input))]
    fn is_message_expected(&self, msg: &InMsg, current_msg_set: &[InMsg]) -> bool {
        matches!(msg.body, Message::R4(_) if self.other_parties.contains(&msg.sender) && !msg.is_duplicate(current_msg_set))
    }

    #[trace(disable(current_msg_set))]
    fn is_input_complete(&self, current_msg_set: &[InMsg]) -> bool {
        is_broadcast_input_complete(current_msg_set, &self.other_parties)
    }

    fn consume(&self, current_msg_set: Vec<InMsg>) -> Transition<KeyGeneratorTraits> {
        let proofs = match to_hash_map_gen::<PartyIndex, DLogProof>(current_msg_set) {
            Ok(p) => p,
            Err(e) => {
                let err_state = ErrorState::new(e);
                log::error!("Phase4 returns {:?}", err_state);
                return Transition::FinalState(Err(err_state));
            }
        };

        let verification_error_vec = proofs
            .iter()
            .filter_map(|(party, msg)| {
                if DLogProof::verify(&msg).is_ok() {
                    None
                } else {
                    Some(KeygenError::InvalidDlogProof {
                        proof: format!("{:?}", msg),
                        party: *party,
                    })
                }
            })
            .collect::<Vec<_>>();

        // Update multiparty shared info to include mapping our PartyIndex to our point
        let mut shared_info = self.multiparty_shared.clone();
        let new_point_x = shared_info.own_point();
        if let Some(old_point_x) = shared_info
            .party_to_point_map
            .points
            .insert(self.own_party_index, new_point_x)
        {
            // not an error if the correct value is inserted
            log::warn!(
                "Own party index was already mapped to point {} instead of {}",
                old_point_x,
                new_point_x
            );
        }

        if verification_error_vec.is_empty() {
            log::info!("Phase4 ends successfully");
            Transition::FinalState(Ok(FinalState {
                multiparty_shared_info: shared_info,
            }))
        } else {
            log::error!("Phase4 returns error vector {:?}", verification_error_vec);
            Transition::FinalState(Err(ErrorState::new(verification_error_vec)))
        }
    }

    fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
    fn timeout_outcome(&self, _current_msg_set: Vec<InMsg>) -> MachineResult {
        Err(ErrorState::new(vec![KeygenError::Timeout {
            phase: "phase4".to_string(),
        }]))
    }
}

/// Map of `PartyIndex` of each party into the x-coordinate of the shares received by this party
///
/// Maps [`PartyIndex`] to a number. Used in the calculation of Lagrange's coefficients in the signing protocol as only some parties take part in it   
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Party2PointMap {
    pub points: HashMap<PartyIndex, usize>,
}

impl Party2PointMap {
    #[trace(pretty)]
    pub fn map_signing_parties_to_points(&self, signing_parties: &[PartyIndex]) -> Vec<usize> {
        let mut present = Vec::new();
        let mut absent = Vec::new();
        for idx in signing_parties {
            match self.points.get(idx) {
                Some(point) => present.push(*point),
                None => absent.push(*idx),
            }
        }

        log::debug!(
            "Panic is expected if not all parties are mapped to points.\nAbsent: {:?}",
            absent
        );
        assert_eq!(absent.len(), 0);

        present
    }

    #[trace(pretty)]
    pub fn calculate_lagrange_multiplier(&self, signing_parties: &[PartyIndex], own_x: FE) -> FE {
        // build set of points {1,2...}
        #[allow(clippy::cast_possible_truncation)]
        let subset_of_fe_points = self
            .map_signing_parties_to_points(signing_parties)
            .into_iter()
            .map(|x| {
                let index_bn = BigInt::from(x as u32);
                ECScalar::from(&index_bn)
            })
            .collect::<Vec<FE>>();

        let fold_with_one = |op: &dyn Fn(FE, &FE) -> FE| {
            subset_of_fe_points
                .iter()
                .filter(|x| (*x).get_element() != own_x.get_element())
                .fold(ECScalar::from(&BigInt::one()), |acc: FE, x| op(acc, x))
        };

        let num_fun = |acc: FE, x: &FE| acc * x;
        let denom_fun = |acc: FE, x: &FE| acc * x.sub(&own_x.get_element());

        fold_with_one(&denom_fun).invert() * fold_with_one(&num_fun)
    }
}
/// Result of key generation protocol
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalState {
    pub multiparty_shared_info: MultiPartyInfo,
}

/// Container of `KeygenError` type
#[derive(Debug)]
pub struct ErrorState {
    errors: Vec<KeygenError>,
}

impl ErrorState {
    pub fn new(errors: Vec<KeygenError>) -> Self {
        ErrorState { errors }
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithms::zkp::ZkpSetup;
    use crate::ecdsa::keygen::{
        FinalState, InMsg, KeyGeneratorTraits, OutMsg, Phase1, SecretKeyLoader,
        SecretKeyLoaderError,
    };
    use crate::ecdsa::messages::SecretShare;
    use crate::ecdsa::{InitialKeys, InitialPublicKeys, PaillierKeys, Parameters};
    use crate::protocol::{Address, InputMessage, PartyIndex};
    use crate::state_machine::sync_channels::StateMachine;
    use anyhow::bail;
    use crossbeam_channel::{Receiver, Sender};
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
    use curv::elliptic::curves::secp256_k1::Secp256k1Scalar;
    use curv::elliptic::curves::traits::{ECPoint, ECScalar};
    use curv::{BigInt, FE, GE};
    use paillier::DecryptionKey;
    use std::collections::{HashMap, HashSet};
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
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

    #[derive(Debug)]
    struct Wallet {
        pub records: HashMap<usize, InitialKeys>,
    }

    impl Wallet {
        pub fn new(keys: HashMap<usize, InitialKeys>) -> Self {
            Self { records: keys }
        }
    }

    #[derive(Debug)]
    struct SecretKeyLoaderImpl {
        wallet: Arc<Mutex<Wallet>>,
        key_index: usize,
    }

    impl SecretKeyLoaderImpl {
        pub fn new(wallet: &Arc<Mutex<Wallet>>, key_index: usize) -> Self {
            Self {
                wallet: wallet.clone(),
                key_index,
            }
        }
    }

    impl SecretKeyLoader for SecretKeyLoaderImpl {
        fn get_initial_secret(&self) -> Result<Box<Secp256k1Scalar>, SecretKeyLoaderError> {
            let wallet = self
                .wallet
                .lock()
                .map_err(|e| SecretKeyLoaderError(e.to_string()))?;

            Ok(Box::new(
                wallet
                    .records
                    .get(&self.key_index)
                    .ok_or(SecretKeyLoaderError("key not found".to_string()))?
                    .u_i,
            ))
        }

        fn get_paillier_secret(&self) -> Result<Box<DecryptionKey>, SecretKeyLoaderError> {
            let wallet = self
                .wallet
                .lock()
                .map_err(|e| SecretKeyLoaderError(e.to_string()))?;

            Ok(Box::new(
                wallet
                    .records
                    .get(&self.key_index)
                    .ok_or(SecretKeyLoaderError("key not found".to_string()))?
                    .paillier_keys
                    .dk
                    .clone(),
            ))
        }
    }

    // The test has been dropped. The signing protocol is proven to be insecure when used without range proofs.
    #[allow(dead_code)]
    fn keygen() -> anyhow::Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();
        keygen_helper(false)
    }

    #[test]
    fn keygen_with_range_proofs() -> anyhow::Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();
        keygen_helper(true)
    }

    fn keygen_helper(enable_range_proofs: bool) -> anyhow::Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();
        let params = Parameters {
            share_count: 3,
            threshold: 1,
        };

        let party_index_range = 0..=2;
        let parties = party_index_range
            .clone()
            .map(|p| PartyIndex::from(p))
            .collect::<Vec<_>>();

        let mut nodes = Vec::new();
        let mut handles = Vec::new();
        let wallet = Wallet::new(HashMap::new());
        let shared_wallet_reference = Arc::new(Mutex::new(wallet));

        // the setup from the bank of pre-generated ones
        let path = Path::new("tests/data/rp-setups.json");
        let zkp_setups: Vec<ZkpSetup> = serde_json::from_str(&fs::read_to_string(path)?)?;

        for i in party_index_range {
            let range_proof_setup = if enable_range_proofs {
                Some(zkp_setups[i].clone())
            } else {
                None
            };
            let (ingress, rx) = crossbeam_channel::unbounded();
            let (tx, egress) = crossbeam_channel::unbounded();
            let init_keys = InitialKeys::random();
            let init_pub_keys = InitialPublicKeys::from(&init_keys);
            shared_wallet_reference
                .lock()
                .expect("cant lock mutex")
                .records
                .insert(i, init_keys);
            let secret_loader = SecretKeyLoaderImpl::new(&shared_wallet_reference, i);

            log::info!("starting party {}", i);
            let parties = parties.clone();
            let join_handle = thread::spawn(move || {
                let start_state = Box::new(Phase1::new(
                    &params,
                    init_pub_keys,
                    range_proof_setup,
                    parties.as_slice(),
                    i.into(),
                    Arc::new(Box::new(secret_loader)),
                    None,
                )?);
                let mut machine = StateMachine::<KeyGeneratorTraits>::new(start_state, &rx, &tx);
                match machine.execute() {
                    Some(Ok(fs)) => Ok(fs),
                    Some(Err(e)) => {
                        bail!("error {:?}", e);
                    }
                    None => {
                        bail!("error in the machine");
                    }
                }
            });
            nodes.push(Node {
                party: i.into(),
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
        let final_states = results
            .into_iter()
            .map(|x| x.unwrap().unwrap())
            .collect::<Vec<_>>();
        let whole_public_keys = final_states
            .iter()
            .map(|fs| fs.multiparty_shared_info.public_key.get_element())
            .collect::<HashSet<_>>();

        assert_eq!(
            whole_public_keys.len(),
            1,
            "public keys are not same: {:?}",
            whole_public_keys
        );

        let public_key = whole_public_keys.into_iter().collect::<Vec<_>>()[0];

        let secret_shares = final_states
            .iter()
            .map(|fs| fs.multiparty_shared_info.secret_share)
            .collect::<Vec<_>>();

        let _all_x_i = secret_shares.iter().map(|k| k.1).collect::<Vec<_>>();

        // check if reassembled private key generates correct public key
        let sum_of_private_keys = shared_wallet_reference
            .lock()
            .expect("cant lock mutex")
            .records
            .values()
            .fold(FE::zero(), |acc, keys| acc + keys.u_i);

        let g: GE = ECPoint::generator();
        let expected_pk: GE = g * sum_of_private_keys;
        assert_eq!(
            expected_pk.get_element(),
            public_key,
            "whole public key does not match whole private key"
        );

        // check if whole private key can be reassembled via polynomial's reconstruction
        let x = reconstruct(&secret_shares);
        assert_eq!(
            x, sum_of_private_keys,
            "reconstructed private key is not correct"
        );

        // shares can be shrunk to t+1 elements
        let mut secret_shares_copy = secret_shares.clone();
        secret_shares_copy.remove(0);
        let x0 = reconstruct(&secret_shares_copy);
        assert_eq!(x, x0, "cant reconstruct same private key with less shares");

        let mut secret_shares_copy = secret_shares.clone();
        secret_shares_copy.remove(1);
        let x1 = reconstruct(&secret_shares_copy);
        assert_eq!(x, x1, "cant reconstruct same private key with less shares");

        let mut secret_shares_copy = secret_shares.clone();
        secret_shares_copy.remove(2);
        let x2 = reconstruct(&secret_shares_copy);
        assert_eq!(x, x2, "cant reconstruct same private key with less shares");

        let own_paillier_keys = final_states
            .iter()
            .map(|x| x.multiparty_shared_info.own_he_keys.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            own_paillier_keys
                .iter()
                .filter(|&pk| *pk == PaillierKeys::zero())
                .count(),
            0
        );

        let foreign_paillier_keys = final_states
            .iter()
            .flat_map(|x| x.multiparty_shared_info.party_he_keys.values())
            .collect::<Vec<_>>();

        assert_eq!(
            foreign_paillier_keys
                .iter()
                .filter(|&&pk| pk.n == BigInt::zero() || pk.nn == BigInt::zero())
                .count(),
            0
        );

        Ok(())
    }

    pub fn reconstruct(secret_shares: &[SecretShare]) -> FE {
        //assert!(shares.len() >= self.reconstruct_limit());
        let (points, shares): (Vec<FE>, Vec<FE>) = secret_shares
            .iter()
            .map(|(x, y)| {
                let index_bn = BigInt::from(*x as u64);
                let x_coord: FE = ECScalar::from(&index_bn);
                (x_coord, y)
            })
            .unzip();
        VerifiableSS::lagrange_interpolation_at_zero(&points, &shares)
    }

    pub fn _print_output(final_states: &[FinalState]) {
        let v = final_states
            .iter()
            .map(|x| {
                (
                    x.multiparty_shared_info.own_point(),
                    x.multiparty_shared_info.party_to_point_map.points.clone(),
                )
            })
            .collect::<Vec<_>>();
        let mut outfile = File::create("test-keys.txt").unwrap();
        let s = serde_json::to_string(&v).unwrap();
        outfile.write_all(s.as_bytes()).unwrap();
    }
}
