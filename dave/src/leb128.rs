pub(crate) fn size(mut value: u64) -> usize {
    let mut size = 1;
    while value >= 0x80 {
        value >>= 7;
        size += 1;
    }
    size
}

pub(crate) fn write(mut value: u64, output: &mut [u8]) -> Option<usize> {
    let mut written = 0;
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        let next = if value == 0 { byte } else { byte | 0x80 };
        *output.get_mut(written)? = next;
        written += 1;
        if value == 0 {
            return Some(written);
        }
    }
}

pub(crate) fn read(input: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0_u64;
    for (index, byte) in input.iter().copied().enumerate() {
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}
