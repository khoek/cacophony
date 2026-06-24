#[derive(Debug, Default)]
pub(crate) struct ReusableBuffer {
    bytes: Vec<u8>,
}

impl ReusableBuffer {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub(crate) fn as_vec_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }

    pub(crate) fn clear(&mut self) {
        self.bytes.clear();
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn resize(&mut self, new_len: usize, value: u8) {
        self.bytes.resize(new_len, value);
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        self.bytes.truncate(len);
    }

    pub(crate) fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }

    pub(crate) fn recycle_largest(&mut self, mut bytes: Vec<u8>) {
        bytes.clear();
        if bytes.capacity() > self.bytes.capacity() {
            self.bytes = bytes;
        }
    }
}
