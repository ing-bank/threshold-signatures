//! Finite state machine
//!
//! Finite state machine which executes a cryptographic protocol as a sequence of predetermined states.
//!
//! This version of the machine utilizes async/await model of RUST. The input and output queue types are from [`futures::channel::mpsc`]

use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::{SinkExt, StreamExt};
use tokio::time;

use crate::protocol::Instruction;
use crate::state_machine::{BoxedState, StateMachineTraits, Transition};
use std::collections::VecDeque;

/// Finite state machine
///
///  The machine is implemented as the template, which is instantiated with  three parameters:
///  * the type of machine input `T`
///  * the type of machine output `U`
///  * the type of the result machine returns `V`
///
/// The input and output of the machine can be of any arbitrary type.
/// It makes sense to define the type of the result as [`std::Result`]
/// so that a caller of the machine can distinguish good outcome of the protocol from its errors.
///
///
pub struct StateMachine<T>
where
    T: StateMachineTraits,
{
    state: BoxedState<T>,
    inqueue: UnboundedReceiver<Instruction<T::InMsg>>,
    outqueue: UnboundedSender<T::OutMsg>,
    retained: Vec<T::InMsg>,
    discarded: DiscardedDeck<T::InMsg>,
}

/// container for deferred messaged
///
/// When several distributed nodes execute same network protocol and each node sends and receives same message types, it is hard to achieve the scenario
/// where all nodes pace with same speed through the protocol. It is very common case when some nodes are faster then others so that their messages arrive to destinations early.   
/// To address that the state machine collects all messages discarded by current state object into the `discarded` container.
/// The contents of the container becomes available for *next* state object as priority input.
///
/// To prevent a state from checking already discarded messages at same stage of the protocol more than once, the container has two decks, one for having input for the state object and another for collecting discarded messages.
struct DiscardedDeck<T> {
    current: VecDeque<T>,
    next_state: VecDeque<T>,
}

impl<T> DiscardedDeck<T> {
    pub fn new() -> Self {
        Self {
            current: VecDeque::new(),
            next_state: VecDeque::new(),
        }
    }
    pub fn save(&mut self, m: T) {
        self.next_state.push_back(m);
    }
    pub fn pop(&mut self) -> Option<T> {
        self.current.pop_front()
    }
    pub fn flip(&mut self) {
        while let Some(m) = self.next_state.pop_front() {
            self.current.push_back(m)
        }
    }
}

impl<T> StateMachine<T>
where
    T: StateMachineTraits,
{
    /// Create and initialize new machine
    pub fn new(
        start_state: BoxedState<T>,
        inqueue: UnboundedReceiver<Instruction<T::InMsg>>,
        outqueue: UnboundedSender<T::OutMsg>,
    ) -> Self {
        StateMachine {
            state: start_state,
            inqueue,
            outqueue,
            retained: Vec::new(),
            discarded: DiscardedDeck::new(),
        }
    }

    /// Execute main loop of the machine.
    pub async fn execute(&mut self) -> Option<Result<T::FinalState, T::ErrorState>> {
        log::trace!("starting State Machine");

        self.state_post_transition().await;

        let driving_result = {
            let timeout = self.state.timeout();
            let driver = self.drive_to_completion();

            if let Some(t) = timeout {
                let timed_exec = time::timeout(t, driver).await;
                timed_exec.ok()
            } else {
                Some(driver.await)
            }
        };

        driving_result.unwrap_or_else(|| {
            Some(
                self.state
                    .timeout_outcome(self.retained.drain(..).collect()),
            )
        })
    }

    /// Drives the machine loop to completion.
    async fn drive_to_completion(&mut self) -> Option<Result<T::FinalState, T::ErrorState>> {
        loop {
            let transition = match self.discarded.pop() {
                // first a message is taken from the deck of discarded
                Some(m) => self.process_message(m),
                // inc case the deck is empty,  read from the channel
                None => match self.inqueue.next().await {
                    Some(Instruction::Data(m)) => self.process_message(m),
                    Some(Instruction::Terminate) => {
                        log::debug!("State machine: termination requested");
                        return None;
                    }
                    None => {
                        log::error!("State machine: stream terminated");
                        return None;
                    }
                },
            };

            if let Some(transition) = transition {
                match transition {
                    Transition::NewState(state) => {
                        let _ = std::mem::replace(&mut self.state, state);
                        self.state_post_transition().await;
                        self.discarded.flip();
                    }
                    Transition::FinalState(outcome) => return Some(outcome),
                }
            }
        }
    }

    /// internal function which processes the message according to the state machine algorithm
    fn process_message(&mut self, message: T::InMsg) -> Option<Transition<T>> {
        // Check message is expected.
        log::trace!("message received");
        if self.state.is_message_expected(&message, &self.retained) {
            // Message is expected. Retain it.
            self.retained.push(message);
        } else {
            // unexpected message.
            self.discarded.save(message);
            return None;
        }

        // check input is complete.
        if self.state.is_input_complete(&self.retained) {
            // Progress to the next state.
            let transition = self.state.consume(self.retained.drain(..).collect());
            Some(transition)
        } else {
            // More input is required.
            None
        }
    }

    /// Sends out all messages generated after transition from phase to phase.
    async fn state_post_transition(&mut self) {
        if let Some(output) = self.state.start() {
            for m in output {
                if let Err(err) = self.outqueue.send(m).await {
                    log::error!("State machine cannot send out message: {:?}", err);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Address, InputMessage, OutputMessage};
    use std::time::Duration;

    use crate::state_machine::async_channels::tests::MessageType::*;
    use crate::state_machine::async_channels::tests::SubPhase::*;
    use crate::state_machine::State;
    use crate::state_machine::Transition::*;

    #[derive(Debug)]
    struct Final(i64);
    #[derive(Debug)]
    enum MachineError {
        _GenericError,
        TimeoutError,
    }

    struct TestTraits;

    impl StateMachineTraits for TestTraits {
        type InMsg = InputMessage<MessageType>;
        type OutMsg = OutputMessage<MessageType>;
        type FinalState = Final;
        type ErrorState = MachineError;
    }

    type In = InputMessage<MessageType>;
    type Out = OutputMessage<MessageType>;
    type MachineResult = Result<Final, MachineError>;

    #[allow(non_camel_case_types)]
    #[derive(PartialEq)]
    enum MessageType {
        P1_Input,
        P2_Input,
        P3_Input,
        Machine_Ready,
    }

    enum SubPhase {
        P1,
        P2,
        P3,
    }

    struct MultiPhase {
        sub_phase: SubPhase,
    }

    impl MultiPhase {
        pub fn new() -> Self {
            MultiPhase { sub_phase: P1 }
        }
    }

    impl State<TestTraits> for MultiPhase {
        fn start(&mut self) -> Option<Vec<Out>> {
            Some(vec![OutputMessage {
                recipient: Address::Broadcast,
                body: Machine_Ready,
            }])
        }

        fn is_message_expected(&self, msg: &In, _current_msg_set: &[In]) -> bool {
            match self.sub_phase {
                P1 => {
                    if msg.body == P1_Input {
                        return true;
                    }
                }
                P2 => {
                    if msg.body == P2_Input {
                        return true;
                    }
                }
                P3 => {
                    if msg.body == P3_Input {
                        return true;
                    }
                }
            }
            false
        }

        fn is_input_complete(&self, current_msg_set: &[In]) -> bool {
            current_msg_set.len() == 3
        }

        fn consume(&self, _current_msg_set: Vec<In>) -> Transition<TestTraits> {
            match self.sub_phase {
                P3 => FinalState(Ok(Final(0))),
                P1 => NewState(Box::new(MultiPhase { sub_phase: P2 })),
                P2 => NewState(Box::new(MultiPhase { sub_phase: P3 })),
            }
        }

        fn timeout(&self) -> Option<Duration> {
            None
        }

        fn timeout_outcome(&self, _current_msg_set: Vec<In>) -> MachineResult {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn one_phase_no_timeout() {
        // Define relevant phases.
        struct Phase;

        impl State<TestTraits> for Phase {
            fn start(&mut self) -> Option<Vec<Out>> {
                None
            }

            fn is_message_expected(&self, _msg: &In, _current_msg_set: &[In]) -> bool {
                true
            }

            fn is_input_complete(&self, current_msg_set: &[In]) -> bool {
                current_msg_set.len() > 0
            }

            fn consume(&self, _current_msg_set: Vec<In>) -> Transition<TestTraits> {
                FinalState(Ok(Final(0)))
            }

            fn timeout(&self) -> Option<Duration> {
                None
            }

            fn timeout_outcome(&self, _current_msg_set: Vec<In>) -> MachineResult {
                unimplemented!()
            }
        }
        // Complete definition of phases.

        let _ = env_logger::try_init();
        let (mut ingress, rx) = futures::channel::mpsc::unbounded();
        let (tx, _egress) = futures::channel::mpsc::unbounded();

        let start_state = Box::new(Phase);
        let mut machine = StateMachine::<TestTraits>::new(start_state, rx, tx);
        let _ = ingress
            .send(Instruction::Data(In {
                sender: Default::default(),
                body: MessageType::P1_Input,
            }))
            .await;

        let result = machine.execute().await;
        assert!({
            match result {
                Some(x) => x.is_ok(),
                None => false,
            }
        });
    }

    #[tokio::test]
    async fn one_phase_with_timeout() {
        // Define relevant phases.
        struct Phase;

        impl State<TestTraits> for Phase {
            fn start(&mut self) -> Option<Vec<Out>> {
                None
            }

            fn is_message_expected(&self, _msg: &In, _current_msg_set: &[In]) -> bool {
                true
            }

            fn is_input_complete(&self, current_msg_set: &[In]) -> bool {
                current_msg_set.len() > 0
            }

            fn consume(&self, _current_msg_set: Vec<In>) -> Transition<TestTraits> {
                FinalState(Ok(Final(0)))
            }

            fn timeout(&self) -> Option<Duration> {
                Some(Duration::from_millis(100))
            }

            fn timeout_outcome(&self, _current_msg_set: Vec<In>) -> MachineResult {
                Err(MachineError::TimeoutError)
            }
        }
        // Complete definition of phases.

        let _ = env_logger::try_init();
        let (_ingress, rx) = futures::channel::mpsc::unbounded();
        let (tx, _egress) = futures::channel::mpsc::unbounded();

        let start_state = Box::new(Phase);
        let mut machine = StateMachine::<TestTraits>::new(start_state, rx, tx);
        let result = machine.execute().await;
        assert!(matches!(result, Some(Err(MachineError::TimeoutError))));
    }

    #[tokio::test]
    async fn three_phase_no_timeout_async() {
        let _ = env_logger::try_init();

        let (mut ingress, rx) = futures::channel::mpsc::unbounded();
        let (tx, _egress) = futures::channel::mpsc::unbounded();

        let start_state = Box::new(MultiPhase::new());

        let (tx_result, rx_result) = futures::channel::oneshot::channel();

        tokio::spawn(async {
            let mut machine = StateMachine::<TestTraits>::new(start_state, rx, tx);
            log::info!("starting machine");
            let result = machine.execute().await;
            log::info!("machine stopped");
            tx_result.send(result).unwrap();
            ()
        });

        // uncomment to let machine start up first
        // let x = egress.next().await;

        for msg_type in vec![
            P1_Input, P2_Input, P3_Input, P1_Input, P2_Input, P1_Input, P3_Input, P2_Input,
            P3_Input,
        ] {
            let _ = ingress
                .send(Instruction::Data(InputMessage {
                    sender: Default::default(),
                    body: msg_type,
                }))
                .await;
            log::trace!("message sent");
        }

        let result = rx_result.await;
        match result {
            Ok(r) => assert!({
                match r {
                    Some(x) => {
                        log::info!("{:?}", x);
                        x.is_ok()
                    }
                    None => false,
                }
            }),
            Err(e) => log::error!("{}", e),
        }
    }

    #[tokio::test]
    async fn three_phase_no_timeout_async_termination() {
        let _ = env_logger::try_init();

        let (mut ingress, rx) = futures::channel::mpsc::unbounded();
        let (tx, _egress) = futures::channel::mpsc::unbounded();

        let start_state = Box::new(MultiPhase::new());

        let (tx_result, rx_result) = futures::channel::oneshot::channel();

        tokio::spawn(async {
            let mut machine = StateMachine::<TestTraits>::new(start_state, rx, tx);
            log::info!("starting machine");
            let result = machine.execute().await;
            log::info!("machine stopped");
            tx_result.send(result).unwrap();
            ()
        });

        // Send to SM a reduced set of messages,
        // this set is enough to let SM progress beyond the first stage,
        // but not further than the second stage.
        for msg_type in vec![P1_Input, P2_Input, P3_Input, P1_Input, P2_Input, P1_Input] {
            let _ = ingress
                .send(Instruction::Data(InputMessage {
                    sender: Default::default(),
                    body: msg_type,
                }))
                .await;
            log::trace!("message sent");
        }

        let _ = ingress.send(Instruction::Terminate).await;

        assert!(match rx_result.await {
            // We should end up with no result.
            Ok(r) => r.is_none(),
            Err(e) => {
                log::error!("{}", e);
                false
            }
        })
    }
}
