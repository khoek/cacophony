use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RtpPayloadType(u8);

impl RtpPayloadType {
    pub const MAX: u8 = 0x7f;

    pub const fn new(value: u8) -> Option<Self> {
        if value <= Self::MAX {
            Some(Self(value))
        } else {
            None
        }
    }

    pub(crate) const fn new_const(value: u8) -> Self {
        match Self::new(value) {
            Some(value) => value,
            None => panic!("RTP payload type must fit in seven bits"),
        }
    }

    pub const fn from_marker_byte(byte: u8) -> Self {
        Self(byte & Self::MAX)
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }

    pub const fn marker_byte(self, marker: bool) -> u8 {
        self.0 | if marker { 0x80 } else { 0 }
    }
}

impl fmt::Display for RtpPayloadType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<RtpPayloadType> for u8 {
    fn from(payload_type: RtpPayloadType) -> Self {
        payload_type.0
    }
}

impl Serialize for RtpPayloadType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.0)
    }
}

impl<'de> Deserialize<'de> for RtpPayloadType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::new(value).ok_or_else(|| D::Error::custom("RTP payload type must fit in seven bits"))
    }
}
