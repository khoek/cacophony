use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassthroughMode {
    Enabled,
    DisabledAfter(Duration),
}

impl PassthroughMode {
    pub const fn enabled() -> Self {
        Self::Enabled
    }

    pub const fn disabled_after(transition_expiry: Duration) -> Self {
        Self::DisabledAfter(transition_expiry)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PlaintextPassthrough {
    until: Option<Instant>,
}

impl PlaintextPassthrough {
    pub(crate) fn disabled() -> Self {
        Self {
            until: Some(Instant::now()),
        }
    }

    pub(crate) const fn from_until(until: Option<Instant>) -> Self {
        Self { until }
    }

    pub(crate) const fn until(self) -> Option<Instant> {
        self.until
    }

    pub(crate) fn apply(&mut self, mode: PassthroughMode) {
        match mode {
            PassthroughMode::Enabled => self.until = None,
            PassthroughMode::DisabledAfter(transition_expiry) => {
                let expiry = Instant::now() + transition_expiry;
                self.until = Some(match self.until {
                    Some(old) => old.min(expiry),
                    None => expiry,
                });
            }
        }
    }

    pub(crate) fn allows_plaintext(self) -> bool {
        self.until.is_none_or(|expiry| expiry > Instant::now())
    }
}
