pub const H26X_LONG_START_CODE: [u8; 4] = [0, 0, 0, 1];
pub const H26X_SHORT_START_SEQUENCE_BYTES: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct H26xNalu {
    pub start: usize,
    pub start_code_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnnexBFrame<'a> {
    frame: &'a [u8],
}

impl<'a> AnnexBFrame<'a> {
    pub const fn new(frame: &'a [u8]) -> Self {
        Self { frame }
    }

    pub fn find_next_nalu(self, search_start: usize) -> Option<H26xNalu> {
        let frame = self.frame;
        if frame.len() < H26X_SHORT_START_SEQUENCE_BYTES {
            return None;
        }
        let mut index = search_start;
        while index < frame.len() - H26X_SHORT_START_SEQUENCE_BYTES {
            if frame[index + 2] > 1 {
                index += H26X_SHORT_START_SEQUENCE_BYTES;
            } else if frame[index + 2] == 1 {
                if frame[index] == 0 && frame[index + 1] == 0 {
                    return Some(H26xNalu {
                        start: index + H26X_SHORT_START_SEQUENCE_BYTES,
                        start_code_len: if index >= 1 && frame[index - 1] == 0 {
                            4
                        } else {
                            3
                        },
                    });
                }
                index += H26X_SHORT_START_SEQUENCE_BYTES;
            } else {
                index += 1;
            }
        }
        None
    }

    pub fn nalus(self) -> AnnexBNalus<'a> {
        AnnexBNalus {
            frame: self.frame,
            next: self.find_next_nalu(0),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnexBNalus<'a> {
    frame: &'a [u8],
    next: Option<H26xNalu>,
}

impl AnnexBNalus<'_> {
    pub const fn is_empty(&self) -> bool {
        self.next.is_none()
    }
}

impl<'a> Iterator for AnnexBNalus<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let nalu = self.next?;
            let next = AnnexBFrame::new(self.frame).find_next_nalu(nalu.start);
            let end = next
                .map(|next| next.start - next.start_code_len)
                .unwrap_or(self.frame.len());
            self.next = next;
            if end > nalu.start {
                return Some(&self.frame[nalu.start..end]);
            }
        }
    }
}
