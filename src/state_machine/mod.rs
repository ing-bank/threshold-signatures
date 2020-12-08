//!  Finite state machine
//!
//!  Finite state machine which executes a cryptographic protocol as a sequence of predetermined states.
//!  Each state has to be mapped to a state object, which implements trait [`State`].
//!  The machine sends/receives output/input to/from a networking layer, which is not included in this library. Instead, the machine gets two channels at the start to receive and to send messages respectively.
//!
//! The machine act as a wrapper between network layer and state objects. At the high level machine performs following steps for each state:
//!  * it sends optional output to a network
//!  * it receives and collects input until the state indicates that sufficient number of messages for current stage of a protocol is received
//!  * the machine let the state consume entire relevant input. Irrelevant messages are collected into discarded deck.
//!  * the machine checks if the result of consumption is the new state object or [`Final State`] type. The former substitutes current state object in the machine, while the latter cause the machine to terminate.
//!  * if discarded deck is not empty, and the machine continues, it processes messages from this deck first with new state object.
//!
//!
//! # Async model and futures
//!
//! The module contains two implementations of the state machine, one which deals with async queues and another , which uses more traditional synchronous queues from `crossbeam_channel` crate. All remaining properties of these machines are identical.
//!
//!  # Implementation details
//!
//!  First time the state object becomes the current, the machine will output the result of `start` method to a network. After that the machine enters the loop where it receives messages from its input channel and feeds them to
//!  `is_message_expected` method of the trait [`State`]. If the function returns true, then the message will be stored in the machine's container `retained`, otherwise the message is stored into container `discarded`.
//!  If the message was stored to `retained`, the machine immediately calls `is_input_complete`. This method results with True if the state has received all expected input. The machine act on this condition
//!  by calling `consume` method, otherwise it continues listening for input messages. The `consume` method returns [`Transition`]. IF its value is `Transition:::NewState`,
//!  the value becomes new state object in the machine. If its value is `Transition::FinalState`, this value is returned by the machine and the machine terminates.
//!
//!  The machine supports timeouts in the protocol. The `timeout` method of corresponding state object has to return `Some` Duration so that when this object becomes current state object the duration will be stored internally by the machine.
//!  The machine will check then if this duration is expired before  `is_input_complete` returns true.
//!  In this case the machine stops and returns the value provided by `timeout_outcome` method of the current state object.
//!
//! [`State`]: trait.State.html
//! [`Transition`]: enum.Transition.html
//!
pub mod async_channels;
pub mod sync_channels;

use std::fmt::{Debug, Error, Formatter};
use std::time::Duration;

pub trait StateMachineTraits {
    type InMsg;
    type OutMsg;
    type FinalState;
    type ErrorState;
}

#[derive(Debug)]
pub enum Transition<T>
where
    T: StateMachineTraits,
{
    NewState(BoxedState<T>),
    FinalState(Result<T::FinalState, T::ErrorState>),
}

// State has to be `Send` to be used with asynchronous channels,
// because it will be sent between thread in tokio pool.
pub type BoxedState<T> = Box<dyn State<T> + Send>;

impl<T> Debug for BoxedState<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "BoxedState")
    }
}

///   State interface
pub trait State<T>
where
    T: StateMachineTraits,
{
    fn start(&mut self) -> Option<Vec<T::OutMsg>>;
    fn is_message_expected(&self, msg: &T::InMsg, current_msg_set: &[T::InMsg]) -> bool;
    fn is_input_complete(&self, current_msg_set: &[T::InMsg]) -> bool;
    fn consume(&self, current_msg_set: Vec<T::InMsg>) -> Transition<T>;

    fn timeout(&self) -> Option<Duration> {
        None
    }
    fn timeout_outcome(
        &self,
        current_msg_set: Vec<T::InMsg>,
    ) -> Result<T::FinalState, T::ErrorState>;
}

/////////////////////////////////////////////////////////////////////////
