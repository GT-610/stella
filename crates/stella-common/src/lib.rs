//! Shared platform-neutral value types for Stella.

#![forbid(unsafe_code)]

use std::{fmt, str::FromStr};

use thiserror::Error;

const IDENTIFIER_LENGTH: usize = 16;

/// Error returned while parsing a canonical hexadecimal value.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum HexParseError {
    /// The text has the wrong number of bytes.
    #[error("expected {expected} bytes of hexadecimal text, got {actual}")]
    InvalidLength {
        /// Required text length.
        expected: usize,
        /// Supplied text length.
        actual: usize,
    },
    /// A byte is not an ASCII hexadecimal digit.
    #[error("invalid hexadecimal digit at byte offset {index}")]
    InvalidDigit {
        /// Byte offset of the invalid digit.
        index: usize,
    },
    /// A MAC address separator is missing or invalid.
    #[error("invalid MAC address separator at byte offset {index}")]
    InvalidSeparator {
        /// Byte offset of the invalid separator.
        index: usize,
    },
}

fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N], HexParseError> {
    let expected = N * 2;
    if text.len() != expected {
        return Err(HexParseError::InvalidLength {
            expected,
            actual: text.len(),
        });
    }

    let bytes = text.as_bytes();
    let mut output = [0_u8; N];
    for (index, output_byte) in output.iter_mut().enumerate() {
        let high_index = index * 2;
        let low_index = high_index + 1;
        let high = decode_nibble(bytes[high_index], high_index)?;
        let low = decode_nibble(bytes[low_index], low_index)?;
        *output_byte = (high << 4) | low;
    }
    Ok(output)
}

fn decode_nibble(byte: u8, index: usize) -> Result<u8, HexParseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(HexParseError::InvalidDigit { index }),
    }
}

fn format_hex<const N: usize>(bytes: &[u8; N], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

macro_rules! identifier_type {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; Self::LENGTH]);

        impl $name {
            /// Length of this identifier in bytes.
            pub const LENGTH: usize = IDENTIFIER_LENGTH;

            /// Creates an identifier from its canonical bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
                Self(bytes)
            }

            /// Borrows the canonical identifier bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
                &self.0
            }

            /// Returns the canonical identifier bytes.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; Self::LENGTH] {
                self.0
            }

            /// Returns whether every identifier byte is zero.
            #[must_use]
            pub fn is_zero(&self) -> bool {
                self.0.iter().all(|byte| *byte == 0)
            }
        }

        impl From<[u8; Self::LENGTH]> for $name {
            fn from(bytes: [u8; Self::LENGTH]) -> Self {
                Self::from_bytes(bytes)
            }
        }

        impl From<$name> for [u8; $name::LENGTH] {
            fn from(identifier: $name) -> Self {
                identifier.into_bytes()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                format_hex(&self.0, formatter)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}({self})", stringify!($name))
            }
        }

        impl FromStr for $name {
            type Err = HexParseError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                decode_hex(text).map(Self::from_bytes)
            }
        }
    };
}

identifier_type!(NodeId, "Stable identifier of a Stella node identity.");
identifier_type!(
    ControllerId,
    "Stable identifier of a Stella controller signing identity."
);
identifier_type!(
    NetworkId,
    "Stable identifier of an isolated Stella virtual network."
);
identifier_type!(
    GrantSerial,
    "Controller-unique serial of a signed membership grant."
);
identifier_type!(
    RelayId,
    "Stable identifier of a Stella-compatible relay service."
);

/// Six-byte IEEE 802 MAC address.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MacAddress([u8; Self::LENGTH]);

impl MacAddress {
    /// Length of a MAC address in bytes.
    pub const LENGTH: usize = 6;

    /// Ethernet broadcast destination.
    pub const BROADCAST: Self = Self([0xff; Self::LENGTH]);

    /// Creates a MAC address from canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrows the canonical address bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    /// Returns the canonical address bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }

    /// Returns whether all address bytes are zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }

    /// Returns whether the IEEE group bit is set.
    #[must_use]
    pub const fn is_group(&self) -> bool {
        self.0[0] & 1 == 1
    }

    /// Returns whether this is the all-ones broadcast address.
    #[must_use]
    pub const fn is_broadcast(&self) -> bool {
        let bytes = self.0;
        bytes[0] == 0xff
            && bytes[1] == 0xff
            && bytes[2] == 0xff
            && bytes[3] == 0xff
            && bytes[4] == 0xff
            && bytes[5] == 0xff
    }

    /// Returns whether this is multicast but not broadcast.
    #[must_use]
    pub const fn is_multicast(&self) -> bool {
        self.is_group() && !self.is_broadcast()
    }

    /// Returns whether this is a non-zero individual address.
    #[must_use]
    pub fn is_valid_unicast(&self) -> bool {
        !self.is_group() && !self.is_zero()
    }

    /// Returns whether the locally administered bit is set.
    #[must_use]
    pub const fn is_locally_administered(&self) -> bool {
        self.0[0] & 2 == 2
    }

    /// Classifies this address as a destination.
    #[must_use]
    pub const fn destination_class(&self) -> EthernetDestination {
        if self.is_broadcast() {
            EthernetDestination::Broadcast
        } else if self.is_group() {
            EthernetDestination::Multicast
        } else {
            EthernetDestination::Unicast
        }
    }
}

impl From<[u8; Self::LENGTH]> for MacAddress {
    fn from(bytes: [u8; Self::LENGTH]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<MacAddress> for [u8; MacAddress::LENGTH] {
    fn from(address: MacAddress) -> Self {
        address.into_bytes()
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if index > 0 {
                formatter.write_str(":")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "MacAddress({self})")
    }
}

impl FromStr for MacAddress {
    type Err = HexParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.len() == Self::LENGTH * 2 {
            return decode_hex(text).map(Self::from_bytes);
        }

        let expected = Self::LENGTH * 3 - 1;
        if text.len() != expected {
            return Err(HexParseError::InvalidLength {
                expected,
                actual: text.len(),
            });
        }

        let bytes = text.as_bytes();
        let separator = bytes[2];
        if separator != b':' && separator != b'-' {
            return Err(HexParseError::InvalidSeparator { index: 2 });
        }

        let mut compact = [0_u8; Self::LENGTH * 2];
        for index in 0..Self::LENGTH {
            let input = index * 3;
            if index > 0 && bytes[input - 1] != separator {
                return Err(HexParseError::InvalidSeparator { index: input - 1 });
            }
            compact[index * 2] = bytes[input];
            compact[index * 2 + 1] = bytes[input + 1];
        }

        let compact =
            std::str::from_utf8(&compact).map_err(|_| HexParseError::InvalidDigit { index: 0 })?;
        decode_hex(compact).map(Self::from_bytes)
    }
}

/// Ethernet destination class used by the virtual switching decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EthernetDestination {
    /// Individual destination address.
    Unicast,
    /// Group destination other than all-ones broadcast.
    Multicast,
    /// All-ones broadcast destination.
    Broadcast,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{
        ControllerId, EthernetDestination, GrantSerial, HexParseError, MacAddress, NetworkId,
        NodeId, RelayId,
    };

    #[test]
    fn identifiers_round_trip_bytes_and_text() {
        let bytes = [0xab; NodeId::LENGTH];
        let node = NodeId::from_bytes(bytes);

        assert_eq!(node.as_bytes(), &bytes);
        assert_eq!(node.into_bytes(), bytes);
        assert_eq!(node.to_string(), "abababababababababababababababab");
        assert_eq!(NodeId::from_str(&node.to_string()), Ok(node));
        assert_eq!(format!("{node:?}"), format!("NodeId({node})"));
        assert!(!node.is_zero());
        assert!(NodeId::from_bytes([0; NodeId::LENGTH]).is_zero());
    }

    #[test]
    fn identifier_types_remain_distinct_and_convert_bytes() {
        let bytes = [7; NetworkId::LENGTH];
        let network = NetworkId::from(bytes);
        let controller = ControllerId::from(bytes);
        let serial = GrantSerial::from(bytes);
        let relay = RelayId::from(bytes);

        assert_eq!(<[u8; NetworkId::LENGTH]>::from(network), bytes);
        assert_eq!(controller.to_string(), network.to_string());
        assert_eq!(serial.to_string(), network.to_string());
        assert_eq!(relay.to_string(), network.to_string());
    }

    #[test]
    fn hexadecimal_parser_accepts_uppercase() {
        let parsed = NodeId::from_str("ABCDEFABCDEFABCDEFABCDEFABCDEFAB");

        assert_eq!(
            parsed.map(|value| value.to_string()),
            Ok(String::from("abcdefabcdefabcdefabcdefabcdefab"))
        );
    }

    #[test]
    fn hexadecimal_parser_rejects_length_and_digit() {
        assert_eq!(
            NodeId::from_str("00"),
            Err(HexParseError::InvalidLength {
                expected: 32,
                actual: 2,
            })
        );
        assert_eq!(
            NodeId::from_str("0000000000000000000000000000000x"),
            Err(HexParseError::InvalidDigit { index: 31 })
        );
    }

    #[test]
    fn mac_address_accepts_canonical_and_compact_forms() {
        let expected = MacAddress::from_bytes([0x02, 0, 0, 0, 0, 1]);

        assert_eq!(MacAddress::from_str("02:00:00:00:00:01"), Ok(expected));
        assert_eq!(MacAddress::from_str("02-00-00-00-00-01"), Ok(expected));
        assert_eq!(MacAddress::from_str("020000000001"), Ok(expected));
        assert_eq!(expected.to_string(), "02:00:00:00:00:01");
        assert_eq!(format!("{expected:?}"), "MacAddress(02:00:00:00:00:01)");
        assert_eq!(expected.as_bytes(), &[0x02, 0, 0, 0, 0, 1]);
        assert_eq!(
            <[u8; MacAddress::LENGTH]>::from(expected),
            [0x02, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn mac_address_rejects_bad_separators_and_digits() {
        assert_eq!(
            MacAddress::from_str("02.00.00.00.00.01"),
            Err(HexParseError::InvalidSeparator { index: 2 })
        );
        assert_eq!(
            MacAddress::from_str("02:00-00:00:00:01"),
            Err(HexParseError::InvalidSeparator { index: 5 })
        );
        assert_eq!(
            MacAddress::from_str("02:00:00:00:00:0z"),
            Err(HexParseError::InvalidDigit { index: 11 })
        );
        assert_eq!(
            MacAddress::from_str("02:00"),
            Err(HexParseError::InvalidLength {
                expected: 17,
                actual: 5,
            })
        );
    }

    #[test]
    fn mac_address_classification_matches_ieee_bits() {
        let unicast = MacAddress::from_bytes([0x02, 0, 0, 0, 0, 1]);
        let multicast = MacAddress::from_bytes([0x01, 0, 0x5e, 0, 0, 1]);
        let zero = MacAddress::from_bytes([0; MacAddress::LENGTH]);

        assert!(unicast.is_valid_unicast());
        assert!(unicast.is_locally_administered());
        assert_eq!(unicast.destination_class(), EthernetDestination::Unicast);
        assert!(multicast.is_group());
        assert!(multicast.is_multicast());
        assert!(!multicast.is_broadcast());
        assert_eq!(
            multicast.destination_class(),
            EthernetDestination::Multicast
        );
        assert!(MacAddress::BROADCAST.is_broadcast());
        assert_eq!(
            MacAddress::BROADCAST.destination_class(),
            EthernetDestination::Broadcast
        );
        assert!(zero.is_zero());
        assert!(!zero.is_valid_unicast());
    }
}
