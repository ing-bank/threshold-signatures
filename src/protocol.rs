//! Defines some common data types

#![allow(clippy::large_enum_variant)]
use core::cmp::Ordering;
use core::fmt::{Error, Formatter};
use hex::FromHexError;
use serde::de::Visitor;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use anyhow::bail;
use std::cmp::Ordering::{Equal, Greater, Less};
use std::fmt::{Debug, Display};

/// Index of a party in multi-party computation
///
/// Abstract index whose binding to a network address has to be defined outside of the crate.
/// Uses 32 byte slice to fit a public 256 bit key of an elliptic curve schema.
#[derive(Clone, Copy, Hash, Eq, PartialEq)]
pub struct PartyIndex(pub [u8; 32]);

impl PartyIndex {
    pub fn from_slice(slice: &[u8]) -> anyhow::Result<Self> {
        if slice.len() != 32 {
            bail!("Slice is required to be 32 bytes long");
        }

        Ok({
            let mut result = [0u8; 32];
            result.clone_from_slice(slice);
            PartyIndex(result)
        })
    }

    fn write_as_hex_str(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        self.0.iter().rev().try_for_each(|x| write!(f, "{:02X}", x))
    }
}

impl Default for PartyIndex {
    fn default() -> Self {
        PartyIndex([0u8; 32])
    }
}

impl Display for PartyIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        self.write_as_hex_str(f)
    }
}

impl Debug for PartyIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        self.write_as_hex_str(f)
    }
}

impl From<usize> for PartyIndex {
    fn from(x: usize) -> Self {
        let mut result = [0u8; 32];
        let bytes = x.to_le_bytes();
        result[..bytes.len()].clone_from_slice(&bytes);
        PartyIndex(result)
    }
}

impl Ord for PartyIndex {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.eq(other) {
            return Equal;
        }
        if self.0.iter().lt(other.0.iter()) {
            Less
        } else {
            Greater
        }
    }
}

impl PartialOrd for PartyIndex {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for PartyIndex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}", self))
    }
}

impl<'a> Deserialize<'a> for PartyIndex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        struct MyVisitor;

        impl<'a> Visitor<'a> for MyVisitor {
            type Value = PartyIndex;

            fn expecting(&self, formatter: &mut Formatter) -> Result<(), Error> {
                formatter.write_str("a 32 byte array in hex notation")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let mut bytes = hex::decode(v).map_err(|e| match e {
                    FromHexError::InvalidHexCharacter { c, index } => E::invalid_value(
                        de::Unexpected::Char(c),
                        &format!("Unexpected character {:?} as position {}", c, index).as_str(),
                    ),
                    FromHexError::InvalidStringLength => {
                        E::invalid_length(v.len(), &"Unexpected length of hex string")
                    }
                    FromHexError::OddLength => {
                        E::invalid_length(v.len(), &"Odd length of hex string")
                    }
                })?;
                bytes.reverse();
                let mut result = [0u8; 32];
                result.clone_from_slice(&bytes);
                Ok(PartyIndex(result))
            }
        }

        deserializer.deserialize_str(MyVisitor)
    }
}

/// Message destination address type
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum Address {
    Peer(PartyIndex),
    Broadcast,
}

/// Incoming message wrapper
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InputMessage<BodyType> {
    pub sender: PartyIndex,
    pub body: BodyType,
}

/// Outgoing message wrapper
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OutputMessage<BodyType> {
    pub recipient: Address,
    pub body: BodyType,
}

/// Special wrapper for an input of a state machine. Enables termination of the machine via sending a message to it  
#[derive(Debug, Clone)]
pub enum Instruction<T> {
    Data(T),
    Terminate,
}

#[cfg(test)]
mod tests {
    use super::PartyIndex;

    #[test]
    fn serde() -> anyhow::Result<()> {
        let x = PartyIndex::from(65535 as usize);

        let y = serde_json::to_string(&x)?;

        assert_eq!(
            y,
            "\"000000000000000000000000000000000000000000000000000000000000FFFF\""
        );

        let result: PartyIndex = serde_json::from_str(&y)?;

        assert_eq!(result, x);

        let result: PartyIndex = serde_json::from_str(
            "\"0000000000000000000000000000000000000000000000000000000000000002\"",
        )?;

        assert_eq!(result, PartyIndex::from(2));
        Ok(())
    }
}
