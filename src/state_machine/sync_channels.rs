//!  Finite state machine
//!
//!  Finite state machine which executes a cryptographic protocol as a sequence of predetermined states.
//!  Unlike its async version, this machine uses receiver and sender queue types from crate `crossbeam_channel`
//!  See details in similar [`Async state machine`]
//!
//!
//! [`Async state machine`]: ../async_channels/index.html
//!
use crate::state_machine::{BoxedState, StateMachineTraits, Transition};
use crossbeam_channel::{after, Receiver, Sender};
use std::collections::VecDeque;
use std::time::Instant;

/// Finite state machine
///
/// See [`async_channels::StateMachine`](../async_channels/struct.StateMachine.html)
pub struct StateMachine<'a, T>
where
    T: StateMachineTraits,
{
    state: BoxedState<T>,
    inqueue: &'a Receiver<T::InMsg>,
    outqueue: &'a Sender<T::OutMsg>,
    timeout: Option<Receiver<Instant>>,
    retained: Vec<T::InMsg>,
    discarded: DiscardedDeck<T::InMsg>,
}

/// container for deferred messaged
///
/// See [`async_channels::DiscardedDeck`](../async_channels/struct.DiscardedDeck.html)
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

impl<'a, T: StateMachineTraits> StateMachine<'a, T> {
    pub fn new(
        start_state: BoxedState<T>,
        inqueue: &'a Receiver<T::InMsg>,
        outqueue: &'a Sender<T::OutMsg>,
    ) -> Self {
        StateMachine {
            state: start_state,
            inqueue,
            outqueue,
            timeout: None,
            retained: Vec::new(),
            discarded: DiscardedDeck::new(),
        }
    }

    pub fn execute(&mut self) -> Option<Result<T::FinalState, T::ErrorState>> {
        log::trace!("starting State Machine");

        self.state_prepare();

        loop {
            let transition = match self.discarded.pop() {
                // first a message is taken from the deck of discarded
                Some(m) => self.process_message(m),
                // inc case the deck is empty,  read from the channel
                None => match self.timeout.as_ref() {
                    Some(timeout_receiver) => crossbeam_channel::select! {
                        recv(self.inqueue) -> result =>
                            result.map_err(|e| log::error!("SM with timeout: receive error {:?}", e))
                            .map(| message| self.process_message(message) ).ok().flatten(),
                        recv(timeout_receiver) -> _ => return Some(self.state.timeout_outcome(self.retained.drain(..).collect()))
                    },
                    None => {
                        match self.inqueue.recv() {
                            Ok(m) => self.process_message(m),
                            Err(e) => {
                                log::error!("SM with no timeout: receive error {:?}", e);
                                //early exit required to avoid infinite loop after first RecvError
                                return None;
                            }
                        }
                    }
                },
            };
            if let Some(transition) = transition {
                match transition {
                    Transition::NewState(state) => {
                        let _ = std::mem::replace(&mut self.state, state);
                        self.state_prepare();
                        self.discarded.flip();
                    }
                    Transition::FinalState(outcome) => return Some(outcome),
                }
            }
        }
    }

    fn process_message(&mut self, message: T::InMsg) -> Option<Transition<T>> {
        // Check message is expected.
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

    fn state_prepare(&mut self) {
        self.timeout = self.state.timeout().map(after);
        if let Some(output) = self.state.start() {
            for m in output {
                if let Err(err) = self.outqueue.send(m) {
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
    use std::thread;
    use std::time::Duration;

    use crate::state_machine::State;
    use crate::state_machine::Transition::FinalState;

    struct Phase();

    struct Final(i64);

    #[derive(PartialEq)]
    enum MachineError {
        _GenericError,
        TimeoutError,
    }

    enum MessageType {
        Init(),
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

    impl State<TestTraits> for Phase {
        fn start(&mut self) -> Option<Vec<Out>> {
            None
        }

        fn is_message_expected(&self, _msg: &In, _current_msg_set: &[In]) -> bool {
            true
        }

        fn is_input_complete(&self, _current_msg_set: &[In]) -> bool {
            true
        }

        fn consume(&self, _current_msg_set: Vec<In>) -> Transition<TestTraits> {
            FinalState(Ok(Final(0)))
        }

        fn timeout(&self) -> Option<Duration> {
            None
        }

        fn timeout_outcome(&self, _current_msg_set: Vec<In>) -> Result<Final, MachineError> {
            unimplemented!()
        }
    }

    #[test]
    fn one_phase_no_timeout() {
        let (ingress, rx) = crossbeam_channel::unbounded();
        let (tx, _egress) = crossbeam_channel::unbounded();
        let start_state = Box::new(Phase());
        let mut machine = StateMachine::<TestTraits>::new(start_state, &rx, &tx);
        ingress
            .send(In {
                sender: Default::default(),
                body: MessageType::Init(),
            })
            .unwrap();
        let result = machine.execute();
        assert!({
            match result {
                Some(x) => x.is_ok(),
                None => false,
            }
        });
    }

    impl State<TestTraits> for TimedPhase {
        fn start(&mut self) -> Option<Vec<Out>> {
            Some(vec![Out {
                recipient: Address::Broadcast,
                body: MessageType::Init(),
            }])
        }

        fn is_message_expected(&self, _msg: &In, _current_msg_set: &[In]) -> bool {
            true
        }

        fn is_input_complete(&self, _current_msg_set: &[In]) -> bool {
            true
        }

        fn consume(&self, _current_msg_set: Vec<In>) -> Transition<TestTraits> {
            FinalState(Ok(Final(0)))
        }

        fn timeout(&self) -> Option<Duration> {
            Some(self.0)
        }

        fn timeout_outcome(&self, _current_msg_set: Vec<In>) -> MachineResult {
            Err(MachineError::TimeoutError)
        }
    }

    struct TimedPhase(Duration);

    #[test]
    fn timed_out() {
        let _ = env_logger::builder().is_test(true).try_init();

        let timeout_in_seconds = 3;
        let (ingress, rx) = crossbeam_channel::unbounded();
        let (tx, egress) = crossbeam_channel::unbounded();
        let start_state = Box::new(TimedPhase(Duration::from_secs(timeout_in_seconds)));
        let mut machine = StateMachine::<TestTraits>::new(start_state, &rx, &tx);

        thread::spawn(move || {
            log::info!("client thread started");
            // wait till the machine starts
            let _ = egress.recv();
            log::info!("machine started");
            thread::sleep(Duration::from_secs(timeout_in_seconds + 2));
            log::info!("sending message");
            ingress
                .send(In {
                    sender: Default::default(),
                    body: MessageType::Init(),
                })
                .expect("Cannot send to a state machine in the thread");
        });

        let result = machine.execute();
        log::info!("machine finished");
        assert!({
            match result {
                Some(x) => match x.err() {
                    Some(e) => e == MachineError::TimeoutError,
                    None => false,
                },
                None => false,
            }
        });
    }
}
