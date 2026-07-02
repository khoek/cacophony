#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Uleb128 {
    value: u64,
}

impl Uleb128 {
    pub const fn new(value: u64) -> Self {
        Self { value }
    }

    pub const fn value(self) -> u64 {
        self.value
    }

    pub fn encoded_len(self) -> usize {
        let mut value = self.value;
        let mut size = 1;
        while value >= 0x80 {
            value >>= 7;
            size += 1;
        }
        size
    }

    pub fn write_to(self, output: &mut [u8]) -> Option<usize> {
        let mut value = self.value;
        let mut written = 0;
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            *output.get_mut(written)? = if value == 0 { byte } else { byte | 0x80 };
            written += 1;
            if value == 0 {
                return Some(written);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedUleb128 {
    value: Uleb128,
    len: usize,
}

impl DecodedUleb128 {
    pub const fn value(self) -> u64 {
        self.value.value()
    }

    pub const fn encoded(self) -> Uleb128 {
        self.value
    }

    pub const fn encoded_len(self) -> usize {
        self.len
    }

    pub fn read(input: &[u8]) -> Option<DecodedUleb128> {
        let mut value = 0_u64;
        for (index, byte) in input.iter().copied().enumerate() {
            if index == 9 {
                if byte > 1 {
                    return None;
                }
                value |= u64::from(byte) << 63;
                return Some(DecodedUleb128 {
                    value: Uleb128::new(value),
                    len: index + 1,
                });
            }
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                return Some(DecodedUleb128 {
                    value: Uleb128::new(value),
                    len: index + 1,
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{DecodedUleb128, Uleb128};

    #[test]
    fn reads_full_u64_range() {
        let mut bytes = [0; 10];
        let len = Uleb128::new(u64::MAX).write_to(&mut bytes).unwrap();

        assert_eq!(len, 10);
        assert_eq!(DecodedUleb128::read(&bytes).unwrap().value(), u64::MAX);
        assert_eq!(DecodedUleb128::read(&bytes).unwrap().encoded_len(), 10);
    }

    #[test]
    fn rejects_overflowing_tenth_byte() {
        assert_eq!(DecodedUleb128::read(&[0xff; 10]), None);
        assert_eq!(
            DecodedUleb128::read(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2]),
            None
        );
    }

    #[test]
    fn rejects_unterminated_values() {
        assert_eq!(DecodedUleb128::read(&[0x80]), None);
        assert_eq!(DecodedUleb128::read(&[0x80; 9]), None);
    }
}
