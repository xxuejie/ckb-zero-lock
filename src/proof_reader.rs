use super::Data;
use alloc::vec::Vec;
use ckb_std::{ckb_constants::Source, debug};
use core::cmp;
use core::ffi::c_void;
use core::slice::from_raw_parts;
use merkle_cbt::{merkle_tree::Merge, MerkleProof};

const ERROR_CODE: i32 = -70;

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
    IndicesLength,
    Indices,
    LemmasLength,
    Lemmas,
    Completed,
}

#[derive(Debug)]
struct StateVisitor {
    state: ReadState,
    total: usize,

    buffer: FixedBuffer,

    indices: Vec<u32>,
    lemmas: Vec<Data>,
}

impl Default for StateVisitor {
    fn default() -> Self {
        Self {
            state: ReadState::IndicesLength,
            total: 0,
            buffer: FixedBuffer::default(),
            indices: Vec::new(),
            lemmas: Vec::new(),
        }
    }
}

impl StateVisitor {
    fn build<M: Merge<Item = Data>>(self) -> MerkleProof<Data, M> {
        MerkleProof::new(self.indices, self.lemmas)
    }

    fn process_internal_data(&mut self) -> i32 {
        loop {
            let mut changed = false;
            let data = self.buffer.data();
            match self.state {
                ReadState::IndicesLength => {
                    if data.len() >= 4 {
                        let mut t = [0u8; 4];
                        t.copy_from_slice(&data[0..4]);
                        self.buffer.consume(4);
                        self.total = u32::from_le_bytes(t) as usize;
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

    fn process(&mut self, data: &[u8]) -> i32 {
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
                return ERROR_CODE;
            }
            if consumed >= data.len() {
                break;
            }
        }
        0
    }
}

pub type Accessor = unsafe extern "C" fn(*const u8, usize, *mut c_void) -> i32;

extern "C" {
    fn cwhr_rust_read_witness_lock(
        index: usize,
        source: usize,
        accessor: Accessor,
        context: *mut c_void,
    ) -> i32;
}

#[no_mangle]
unsafe extern "C" fn visit_data(data: *const u8, length: usize, context: *mut c_void) -> i32 {
    let data = from_raw_parts(data, length);
    let visitor = &mut *(context as *mut StateVisitor);
    visitor.process(data)
}

pub fn parse_merkle_proof<M: Merge<Item = Data>>(
    index: usize,
    source: Source,
) -> Option<MerkleProof<Data, M>> {
    let mut visitor = StateVisitor::default();
    let result = unsafe {
        cwhr_rust_read_witness_lock(
            index,
            source as usize,
            visit_data,
            &mut visitor as *mut StateVisitor as *mut _,
        )
    };
    if result != 0 {
        debug!(
            "Error reading merkle proof from witness! Return code: {}",
            result
        );
        return None;
    }
    if visitor.state != ReadState::Completed {
        debug!("Witness does not provide a complete merkle proof!");
        return None;
    }
    Some(visitor.build())
}
