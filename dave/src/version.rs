use std::{fmt, num::NonZeroU16};

use crate::error::UnsupportedProtocolVersion;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum DaveProtocolVersion {
    V1 = 1,
}

impl DaveProtocolVersion {
    pub const CURRENT: Self = Self::V1;

    pub fn new(version: NonZeroU16) -> Result<Self, UnsupportedProtocolVersion> {
        match version.get() {
            1 => Ok(Self::V1),
            _ => Err(UnsupportedProtocolVersion(version)),
        }
    }

    pub const fn get(self) -> u16 {
        self as u16
    }

    pub const fn nonzero(self) -> NonZeroU16 {
        match self {
            Self::V1 => NonZeroU16::new(1).unwrap(),
        }
    }
}

impl TryFrom<NonZeroU16> for DaveProtocolVersion {
    type Error = UnsupportedProtocolVersion;

    fn try_from(version: NonZeroU16) -> Result<Self, Self::Error> {
        Self::new(version)
    }
}

impl From<DaveProtocolVersion> for NonZeroU16 {
    fn from(version: DaveProtocolVersion) -> Self {
        version.nonzero()
    }
}

impl fmt::Display for DaveProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(f)
    }
}

pub const DAVE_PROTOCOL_VERSION: DaveProtocolVersion = DaveProtocolVersion::CURRENT;
