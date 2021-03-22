use anyhow::{anyhow, bail};
use crossbeam_channel::{Receiver, Sender};
use curv::elliptic::curves::secp256_k1::Secp256k1Scalar;
use ecdsa_mpc::algorithms::zkp::{ZkpSetup, DEFAULT_GROUP_ORDER_BIT_LENGTH};
use ecdsa_mpc::ecdsa::keygen::{
    FinalState, KeyGeneratorTraits, Phase1, SecretKeyLoader, SecretKeyLoaderError,
};
use ecdsa_mpc::ecdsa::messages::keygen::InMsg;
use ecdsa_mpc::ecdsa::messages::keygen::OutMsg;
use ecdsa_mpc::ecdsa::{InitialKeys, InitialPublicKeys};
use ecdsa_mpc::protocol::{Address, InputMessage, PartyIndex};
use ecdsa_mpc::state_machine::sync_channels::StateMachine;
use ecdsa_mpc::Parameters;
use paillier::DecryptionKey;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::{env, thread};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let _ = env_logger::builder().try_init();

    if args.len() < 4 {
        println!("usage: {} min_number_of_signers share_count output_file_name_prefix  [--use-range-proofs]",args[0]);
        bail!("too few arguments")
    }

    let generate_range_proof_setup = match args.get(4) {
        Some(s) if s == "--use-range-proofs" => true,
        _ => false,
    };

    keygen_helper(
        args[1].parse()?,
        args[2].parse()?,
        &args[3],
        generate_range_proof_setup,
    )
}

fn keygen_helper(
    min_signers: usize,
    share_count: usize,
    filename_prefix: &String,
    generate_range_proof_setup: bool,
) -> anyhow::Result<()> {
    let params = Parameters::new(min_signers, share_count)?;

    let parties = (0..share_count)
        .map(|i| PartyIndex::from(i))
        .collect::<Vec<_>>();

    let mut nodes = Vec::new();
    let mut node_results = Vec::new();
    let wallet = Wallet::new(HashMap::new());
    let shared_wallet_reference = Arc::new(Mutex::new(wallet));

    for i in 0..share_count {
        let range_proof_setup = if generate_range_proof_setup {
            Some(ZkpSetup::random(DEFAULT_GROUP_ORDER_BIT_LENGTH))
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
                PartyIndex::from(i),
                Arc::new(Box::new(secret_loader)),
                None,
            )?);
            let mut machine = StateMachine::<KeyGeneratorTraits>::new(start_state, &rx, &tx);
            match machine.execute() {
                Some(Ok(fs)) => Ok(fs),
                Some(Err(e)) => bail!("error {:?}", e),
                None => bail!("error in the machine"),
            }
        });
        nodes.push(Node {
            party: PartyIndex::from(i),
            egress,
            ingress,
        });
        node_results.push(NodeResult {
            index: i,
            join_handle,
        })
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

    let results = node_results
        .into_iter()
        .map(|h| (h.index, h.join_handle.join()))
        .collect::<Vec<_>>();

    return if results
        .iter()
        .any(|(_, r)| r.is_err() || r.as_ref().unwrap().is_err())
    {
        results.iter().for_each(|r| match r {
            (_, Ok(result)) => match result {
                Ok(final_state) => log::error!("{:?}", final_state),
                Err(e) => log::error!("{:?}", e),
            },
            (_, Err(e)) => log::error!("{:?}", e),
        });
        Err(anyhow!("Some state machines returned error"))
    } else {
        for (index, result) in results.into_iter() {
            // safe to unwrap because results with errors cause the early exit
            let final_state = result.unwrap().unwrap();
            let path = format!("{}.{}.json", filename_prefix, index);
            let mut file = File::create(&path)?;
            file.write_all(
                serde_json::to_string_pretty(&final_state.multiparty_shared_info)?.as_bytes(),
            )?;
        }
        Ok(())
    };
}

struct Node {
    party: PartyIndex,
    egress: Receiver<OutMsg>,
    ingress: Sender<InMsg>,
}

struct NodeResult {
    index: usize,
    join_handle: JoinHandle<anyhow::Result<FinalState>>,
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
