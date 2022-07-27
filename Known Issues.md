# Known issues

## State machine

If is_message_expected() returns false, there is no way the state machine can decide whether incoming packet should be queued
for future rounds or discarded entirely. The ability to discard messages would facilitate better defense against DDOS attacks. 
Currently, is_message_expected() returns false if a message type is not relevant to the current phase,
the message is duplicated, or it is sent by a party which is not in the list of parties performing the protocol.
These message types become deferred so that they do not affect the result of computation in the current round.
Messages with wrong source or duplicated ones will eventually be discarded at the end of the protocol.
However, these messages occupy a place in the DiscardedDeck queue, which may lead to a memory starvation.


