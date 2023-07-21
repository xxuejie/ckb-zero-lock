use super::{Data, ERROR_CODE_PROOF_READER};
use alloc::vec::Vec;
use ckb_std::debug;
use core::cmp;
use merkle_cbt::{merkle_tree::Merge, MerkleProof};

const FIXED_BUF_SIZE: usize = 4096;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct FixedBuffer {
    data: [u8; FIXED_BUF_SIZE],
    valid_start: usize,
    valid_end: usize,
}

impl Default for FixedBuffer {
    fn default() -> Self {
        Self {
            data: [0u8; FIXED_BUF_SIZE],
            valid_start: 0,
            valid_end: 0,
        }
    }
}

impl FixedBuffer {
    fn fill(&mut self, data: &[u8]) -> usize {
        if self.valid_start > 0 {
            let new_end = self.valid_end - self.valid_start;
            self.data.copy_within(self.valid_start..self.valid_end, 0);
            self.valid_start = 0;
            self.valid_end = new_end;
        }
        let consumed = cmp::min(FIXED_BUF_SIZE - self.valid_end, data.len());
        self.data[self.valid_end..(self.valid_end + consumed)].copy_from_slice(&data[..consumed]);
        self.valid_end += consumed;
        consumed
    }

    fn data(&self) -> &[u8] {
        &self.data[self.valid_start..self.valid_end]
    }

    fn consume(&mut self, len: usize) {
        self.valid_start += len;
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum ReadState {
    HeaderIndex,
    IndicesLength,
    Indices,
    LemmasLength,
    Lemmas,
    Completed,
}

#[derive(Debug)]
pub struct ProofVisitor {
    state: ReadState,
    total: usize,

    buffer: FixedBuffer,

    header_index: u32,
    indices: Vec<u32>,
    lemmas: Vec<Data>,
}

impl Default for ProofVisitor {
    fn default() -> Self {
        Self {
            state: ReadState::HeaderIndex,
            total: 0,
            buffer: FixedBuffer::default(),
            header_index: u32::MAX,
            indices: Vec::new(),
            lemmas: Vec::new(),
        }
    }
}

impl ProofVisitor {
    pub fn build<M: Merge<Item = Data>>(self) -> Option<(u32, MerkleProof<Data, M>)> {
        if self.state != ReadState::Completed {
            debug!("Witness does not provide a complete merkle proof!");
            return None;
        }
        Some((
            self.header_index,
            MerkleProof::new(self.indices, self.lemmas),
        ))
    }

    fn process_internal_data(&mut self) -> i32 {
        loop {
            let mut changed = false;
            let data = self.buffer.data();
            match self.state {
                ReadState::HeaderIndex => {
                    if data.len() >= 4 {
                        let mut t = [0u8; 4];
                        t.copy_from_slice(&data[0..4]);
                        self.buffer.consume(4);
                        self.header_index = u32::from_le_bytes(t);
                        self.state = ReadState::IndicesLength;
                        changed = true;
                    }
                }
                ReadState::IndicesLength => {
                    if data.len() >= 4 {
                        let mut t = [0u8; 4];
                        t.copy_from_slice(&data[0..4]);
                        self.buffer.consume(4);
                        self.total = u32::from_le_bytes(t) as usize;
                        self.indices = Vec::with_capacity(self.total as usize);
                        self.state = ReadState::Indices;
                        changed = true;
                    }
                }
                ReadState::Indices => {
                    if self.indices.len() >= self.total {
                        self.state = ReadState::LemmasLength;
                        changed = true;
                    } else if data.len() >= 4 {
                        let mut t = [0u8; 4];
                        t.copy_from_slice(&data[0..4]);
                        self.buffer.consume(4);
                        self.indices.push(u32::from_le_bytes(t));
                        changed = true;
                    }
                }
                ReadState::LemmasLength => {
                    if data.len() >= 4 {
                        let mut t = [0u8; 4];
                        t.copy_from_slice(&data[0..4]);
                        self.buffer.consume(4);
                        self.total = u32::from_le_bytes(t) as usize;
                        self.lemmas = Vec::with_capacity(self.total as usize);
                        self.state = ReadState::Lemmas;
                        changed = true;
                    }
                }
                ReadState::Lemmas => {
                    if self.lemmas.len() >= self.total {
                        self.state = ReadState::Completed;
                        changed = true;
                    } else if data.len() >= 32 {
                        self.lemmas.push(Data::from_slice(&data[0..32]));
                        self.buffer.consume(32);
                        changed = true;
                    }
                }
                ReadState::Completed => break,
            }
            if !changed {
                break;
            }
        }
        0
    }

    pub fn process(&mut self, data: &[u8]) -> i32 {
        let mut consumed = 0;
        loop {
            consumed += self.buffer.fill(&data[consumed..]);
            let ret = self.process_internal_data();
            if ret != 0 {
                return ret;
            }
            if self.state == ReadState::Completed
                && (self.buffer.data().len() > 0 || consumed < data.len())
            {
                debug!("Merkle proof is fully parsed, but trailing data is found!");
                return ERROR_CODE_PROOF_READER;
            }
            if consumed >= data.len() {
                break;
            }
        }
        0
    }
}
