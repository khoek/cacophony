use std::fmt;

use serde::{Deserialize, Deserializer};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RedactedSecret<T>(Zeroizing<T>)
where
    T: Zeroize;

impl<T> RedactedSecret<T>
where
    T: Zeroize,
{
    pub(crate) fn new(value: T) -> Self {
        Self(Zeroizing::new(value))
    }

    pub(crate) fn expose(&self) -> &T {
        &self.0
    }
}

impl RedactedSecret<String> {
    pub(crate) fn as_str(&self) -> &str {
        self.expose()
    }
}

impl RedactedSecret<Vec<u8>> {
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.expose()
    }
}

impl RedactedSecret<[u8; 32]> {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.expose()[..]
    }
}

impl<T> Default for RedactedSecret<T>
where
    T: Default + Zeroize,
{
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> fmt::Debug for RedactedSecret<T>
where
    T: Zeroize,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<'de, T> Deserialize<'de> for RedactedSecret<T>
where
    T: Deserialize<'de> + Zeroize,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::new)
    }
}
