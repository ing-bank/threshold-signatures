# Multiparty threshold ECDSA scheme

## Introduction

The project contains the implementation of the multiparty threshold signature scheme constructed by Rosario Gennaro and Steven Goldfeder [1].
The scheme consists of three algorithms performed in a distributed context: a key generation with N parties,
an arbitrary message signing with a subgroup of [(t+1) of N] parties holding the key,
and the key resharing with (t+1) parties resulting in a new group of M players holding new shares of the same private signing key.

This README file focuses on sharing detailed technical information about the library. Check our whitepaper [5] for theoretical backgrounds.  

The library has been reviewed by Kudelski Security company, see [The security risk assessment report](/docs/report_ing_tss_1.0.pdf).

## Motivation

Elliptic curve digital signature algorithm (ECDSA) is used extensively for crypto-currencies such as Bitcoin and  Ethereum to sign transactions.  
Multiparty threshold signing adds a possibility to create crypto-currency wallets that are controlled by multiple
parties. Transactions which originate from these wallets require collaborative work to sign.
Threshold signing produces standard signature output,
and it preserves the privacy of signers by not disclosing their identities, unlike multi-signature does.
The algorithm used in this product eliminates a central dealer( the party which generates the full key and distributes shards of it to parties). 

As the MPC TS technology has become increasingly popular in the last 2 years, there are quite a few open-source implementations.
The detailed review of them can be found in [6].
Our version improves existing solutions by addition of several key features:
* The protocols collect all results of every verification step instead of aborting that step when a first error occurs.
 All errors are packed in a container and reported back to a caller of the machine after the machine stops. 
 Every error is associated with party id (the origin of the error) so that the application may identify malicious behavior or an active attack pattern. 
* Parties are identified in the protocol by PartyId structure. It makes a party identifier unique and independent from other parameters of the protocol, such as x-coordinate in Shamir secret sharing. 
* The list of ids of parties that generated a key is stored next to that key. It allows the signing algorithm to choose a quorum from parties that are known to be online.
* Protocol timeout detection is supported by the state machine.     
* The initial partial private key is not copied to the protocol memory. 
Instead, the machine fetches the key via the SecureKeyLoader interface from an extern secure vault.
Fetching happens when the key is needed for the generation of shares, and the key bytes are zeroed afterward.
* The original protocol is extended with key re-sharing algorithm.       
 
We also designed the library with the separation of concern (SoC) principle in mind. 
This library encompasses the complete protocol logic that includes party identity management, error reporting, and timeout detection. These activities are not delegated to the application, unlike in some other implementations. 
Only a basic network layer has to be added to wrap the library into a standalone application. This layer has to maintain the mapping between party id and corresponding OS-level connector (e.g. socket),
and to parse the *destination* attribute of any message.
In addition to that, peer-directed messages have to be encrypted and decrypted. The library code does not contain an encryption schema for secret messages,
as that would restrict schema choices and add schema's key management duties.
 
The set of responsibilities of the library layer is determined to the following:
* use broadcast message type to share messages with all parties. The network layer knows which parties are involved in a session, so it forwards the message to all of them.
* address peer-to-peer generated messages to correct parties using partyId.
* check the attribute *source* of type PartyId in every message,  which turns useful for the detection of duplicated or lost messages.
* do all crypto work.

We also paid attention to the usage of :
* broad range of language constructions offered by Rust, e.g. ?-operator, match with conditions, etc. 
* pure functional programming style in coding to improve verifiability of algorithms. 
* nested error code schemas. 
* futures and async/await pattern for running every algorithm.
* very detailed optional function call tracing.


## Signature schema
The ECDSA consist of 3 algorithms ([1], 2.1, 2.5):

* Key generation
* Signing 
* Verification

### Key generation

The initial partial key is sampled from randomness by each party,
so that the resulting public key is the product of partial public keys
and the resulting private key is the sum of partial private keys.

Private keys are shared with Shamir's secret sharing schema [2] where its signing threshold becomes the attribute of the resulting key.
Additional non-malleable commitment to a partial public key is shared to prevent the classic attack on [2]. 
 
Since the signing algorithm uses additive homomorphic encryption schema (AHE) [3],
the setup of range proofs [4] is required ([1] addendum A) at the key generation stage.

### Signing 

The ECDSA requires a random coefficient that needs to be multiplied by private key during the signing.
The result of multiplication has to be shared additively in case of a multi-party setup.
To get an additive sharing of the multiple, it is sufficient to get the additive sharing of each individual term, but each term contains secrets of two different parties.
To overcome the privacy problem the algorithm uses multiplication-to-addition (MtA) 2-party protocol ([1], 3). The MtA protocol uses the AHE scheme [3] with its public key shared before signing. 

In addition to that, several zero-knowledge proofs are generated at the last stages of the signing protocol
to prevent the algorithm from producing a wrong signature ([1], 4.2, phase 5). Every party receives the complete signature at the end. 

### Verification
The protocol outputs the standard signature which is publicly verifiable. The verification does not require interactions with parties.


## Execution model

The library implements the dedicated state machine to run protocols.
Each protocol is a sequence of phases, and each phase consists of three steps: optional message sending, waiting for input, and consuming the collected input.
The consumption results in either transitioning to another phase or stopping the machine and returning either the final result or a collection of error codes.
The machine may also be stopped by reaching a timeout, or it can be aborted by sending a special message to it. The aborted machine returns no result. 
  
Due to the asynchronous nature of protocols the state machine has a buffer for messages
which could be awaited by the next phases of the protocol but arrived too early. 

The state machine code can be executed concurrently by independent threads.
Every phase of each protocol has a local context that is not shared with other phases and instances of the protocol.
As a consequence, the MPC application can run multiple sessions of key generation and sign simultaneously.
Note that the library itself does not handle sessions, it is the main application that has to run multiple state machines and route network streams to/from these machines accordingly.

## Usage

### Library structure

The library consist of three main modules:  

* **ecdsa**, where the protocols are implemented  
* **state machine**, which drives a protocol through its phases
* **algorithms**, where range proofs are set up, generated and verified
   
   
### Examples

#### Key generation 

The example is taken from the test submodule of keygen module with some minor details omitted.

The input for the protocol contains:
*  Values of t and n in the threshold {t,n} 
*  Party index of the node
*  List of party indexes of all participants, including this node
*  Initial keys - public part   
*  Reference to a wallet: storage for initial keys
*  A secret loader which fetches keys from the wallet
*  Optional range proof setup ( Note: the signing protocol is proven to be insecure when used without range proofs. Current version of the library returns error if range proof setup is not presented to keygen protocol)
*  Optional protocol timeout (recommended to be provided). 
 
The first phase of the protocol is created by calling **Phase1::new()** method, which takes all the parameters above.

The state machine is created next, with the following input:

* Instance of Phase1
* Instance of stream and instance of sink.  

Two distinct versions of the state machine in this library support two types for stream/sink:
* either StreamExt and SinkExt types from futures crate
* or Sender and Receiver from crossbeam_channel crate.
       
```
   // set protocol parameters
   let params = Parameters {
                share_count: 3,
                threshold: 1,
            };
   // collect list of parties
   let parties : Vec<PartyIndex> = ...
   // determine the party index of this node  
   let own_party_index = ... 
   // create initial random keys
   let init_keys = InitialKeys::random();
   let init_pub_keys = InitialPublicKeys::from(&init_keys);
   // create some wallet (a peristence provider) and the secret loader
   // secret loader acts as proxy fetching secret keys from the wallet 
   // [see the example in ecds::keygen::test module]      
   let shared_wallet = MyWallet::new(init_keys);    
   let secret_loader = SecretKeyLoaderImpl::new(&shared_wallet, own_party_index);

   let start_state = Box::new(Phase1::new(
                    &params,
                    init_pub_keys,
                    range_proof_setup,
                    parties.as_slice(),
                    own_party_index,
                    Arc::new(Box::new(secret_loader)),
                    None,
                )?);
   
   
   // Channel to pick messages the state machine sends
   let (state_machine_sink, state_machine_stream) = mpsc::unbounded();
   // Channel to feed the machine
   let (protocol_sink, protocol_stream) = mpsc::unbounded();
   let state_machine = StateMachine::new(start_phase, protocol_stream, state_machine_sink);
   
   ...
   
    tokio::spawn(async move {
        let result = match state_machine.execute().await.transpose() {
            Ok(Some(fs)) => Outcome::Keygen(Ok(fs)),
            Ok(None) => {
               Outcome::Keygen(Err(ErrorState::new(vec![KeygenError::GeneralError {
                        desc: "Keygen did not produce a result".to_string(),
                    }])))
                }
            Err(err) => Outcome::Keygen(Err(err)),
            };
            ...
            
```

##### Signing

The input of the protocol contains:
* The hash of a message 
* The output of keygen protocol, MultiPartyInfo structure
* Party indexes of participants, including own party index. Note that the latter is stored in MultiPartyInfo. 

The sequence of actions for signing is similar to keygen: first, the phase object is created, and then the state machine is.
Similarly to the key generation protocol, state machine requires first phase and communication channels.

Note that the signing protocol expects a message to be hashed outside of this library (see module documentation in signature.rs).   

```
     let mut hasher = Sha256::new();
     hasher.input("The message we sign");
     let msg_hash = ECScalar::from(&BigInt::from(hasher.result().as_slice()));

     let start_phase: BoxedState<InMsg, OutMsg, MachineResult> = Box::new(Phase1::new(
                    &msg_hash,
                    multi_party_shared_info,
                    &quorum.parties,
                ));
                let mut main_machine =
                    StateMachine::new(start_phase, to_main_machine, from_main_machine);
                let machine_result = main_machine.execute().await;
                let outcome = match machine_result.transpose() {
                    Ok(Some(fs)) => Outcome::Signature(Ok(fs)),
                    Ok(None) => {
                        Outcome::Signature(Err(ErrorState::new(vec![SigningError::GeneralError {
                            desc: "Signing algorithm did not produce a result".to_string(),
                        }])))
                    }
                    Err(err) => Outcome::Signature(Err(err)),
                };
```   

### Building the documentation

The library uses LaTex mathematical symbols in the documentation so that embedded docs have to be built with predefined HTML header (included into the project):

```
cargo rustdoc  --  --html-in-header katex.html --document-private-items
```      

The nightly build of *rustdoc* is not required: the code is documented using traditional reference link style.

### Using examples

#### The simulator of the key generation protocol 

The complete result of the protocol can be obtained in JSON format by running the command:

```cargo run --example keygen min_number_of_signers total_number_of_signers output_file_name_prefix  [--use-range-proofs]```

The run results in creating  #total_number_of_signers# files containing MultiPartyInfo structure serialized into JSON.
File names can be tweaked by *output_file_name_prefix*.

Note: the signing protocol is proven to be **insecure when used without range proofs**. The keygen example quits with the error if the range proof setup option is not used)

#### The generator of zero knowledge range proof setup

Recall that the ZKRP setup requires safe primes, for which the algorithm is not particularly fast.
If the generation of new ZKRP setups for each new key has to be avoided, then setups have to be pre-computed.  
The following command generates as many as **n**  setups and prints them to the standard output:

``` cargo run  --release --example  zkp-setup n  >outfile.json ```
  

#### The safe prime generator

Safe primes used in ZKRP can also be generated independently by the following command, where n is desired number of pairs of safe primes:

``` cargo run  --release --example safe-primes n  >outfile.json ```


## Securing an application

* The library-wrapping application has to provide a secure reliable way of authenticating nodes during initial connection, as well as a secure messaging.
For example, the application can use TLS protocol to establish initial peer-to-peer connections between nodes known to each other  by their public certificates,
so that the authentication will be based on the certificate chain, and the security will be
provided by DHKE and block ciphers.  

* As shown in the examples above, the ecdsa protocol API does not support an authentication or authorization of the caller through API. API is designed without notion of an user of the node. 
As a result, any node in multiparty setup can initiate key generation, signing, or key refresh, unless other nodes employ a kind of authorization schema. 
In case a schema is put into place, the responsibility of the application layer will be to verify whether the initiator node has privileges to start a computation.
Such schema likely requires preliminary round(s) in the protocol, e.g. sending JoinSession message and receiving ACK/NACK messages. This pre-round is currently not implemented by the library, but 
the state machine code can be used alone for this purpose. 

## Other tech remarks

* The library uses the curve *secp256k1* only. Using other curves is possible but requires the code to be rebuilt.  
* The library does not implement a network transport layer.
* The library's internal architecture relies on the notion of a PartyID, an identifier of a party.
* The library emits messages of 2 types, broadcast and peer2peer so that the transport layer has to forward them to other parties accordingly.

* The application has to deliver broadcasts reliably so that when a party sends a broadcast it's guaranteed that each party receives the same message. 

## References
\[1\] Gennaro, R., Goldfeder, S.: [Fast multiparty threshold ecdsa with fast trustless setup.](https://eprint.iacr.org/2019/114.pdf)  

\[2\] Shamir, A.: How to share a secret. Communications of the ACM 22(11), 612–613 (1979)

\[3\] Paillier, P.: Public-key cryptosystems based on composite degree residuosity classes. In: International Conference on the Theory and Applications of Cryptographic Techniques. pp. 223–238. Springer

\[4\] Eiichiro Fujisaki, Tatsuaki Okamoto: Statistical zero knowledge protocols to prove modular polynomial relations. Advances in Cryptology — CRYPTO '97 pp16-30

\[5\] Tillem, G., Burundukov, O.: [Threshold signatures using Secure Multiparty Computation.](https://new.ingwb.com/binaries/content/assets/insights/themes/distributed-ledger-technology/ing-releases-multiparty-threshold-signing-library-to-improve-customer-security/threshold-signatures-using-secure-multiparty-computation.pdf)   

\[6\] Aumasson, J.P, Hamelink, A., Shlomovits, O.: [A Survey of ECDSA Threshold Signing.](https://eprint.iacr.org/2020/1390.pdf)

## License 
The product is released under the terms of the MIT license. See LICENSE for more information.

## How to contribute

See CONTRIBUTING.md

## Contacts

<oleg.burundukov@ing.com>

<blockchain@ing.com>
