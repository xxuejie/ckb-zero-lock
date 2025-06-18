#[cfg(test)]
mod tests;

use ckb_chain_spec::consensus::{ConsensusBuilder, TYPE_ID_CODE_HASH};
use ckb_hash::{blake2b_256, new_blake2b};
use ckb_script::{TransactionScriptsVerifier, TxVerifyEnv};
use ckb_traits::{CellDataProvider, ExtensionProvider, HeaderProvider};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellMetaBuilder, ResolvedTransaction},
        hardfork::{HardForks, CKB2021, CKB2023},
        Capacity, DepType, EpochExt, HeaderBuilder, HeaderView, ScriptHashType, TransactionBuilder,
    },
    packed::{self, Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
};
use lazy_static::lazy_static;
use merkle_cbt::{merkle_tree::Merge, MerkleTree, CBMT};
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::sync::Arc;

lazy_static! {
    pub static ref ZERO_LOCK_PATH: String = std::env::var("ZERO_LOCK_PATH").unwrap_or_else(|_| {
        format!(
            "{}/../target/riscv64imac-unknown-none-elf/release/ckb-zero-lock",
            env!("CARGO_MANIFEST_DIR"),
        )
    });
    pub static ref ZERO_LOCK_BIN: Bytes =
        Bytes::from(std::fs::read(&*ZERO_LOCK_PATH).expect("read"));
    pub static ref ALWAYS_SUCCESS_BIN: Bytes =
        Bytes::from(ckb_always_success_script::ALWAYS_SUCCESS.to_vec());
}

#[derive(Default, Clone)]
pub struct DummyDataLoader {
    pub cells: HashMap<OutPoint, (CellOutput, Bytes)>,
    pub headers: HashMap<Byte32, HeaderView>,
    pub extensions: HashMap<Byte32, Bytes>,
}

impl CellDataProvider for DummyDataLoader {
    fn get_cell_data(&self, out_point: &OutPoint) -> Option<Bytes> {
        self.cells.get(out_point).map(|(_, data)| data.clone())
    }

    fn get_cell_data_hash(&self, out_point: &OutPoint) -> Option<Byte32> {
        self.cells
            .get(out_point)
            .map(|(_, data)| CellOutput::calc_data_hash(data))
    }
}

impl HeaderProvider for DummyDataLoader {
    fn get_header(&self, block_hash: &Byte32) -> Option<HeaderView> {
        self.headers.get(block_hash).cloned()
    }
}

impl ExtensionProvider for DummyDataLoader {
    fn get_block_extension(&self, hash: &Byte32) -> Option<packed::Bytes> {
        self.extensions.get(hash).map(|data| data.pack())
    }
}

pub fn random_out_point() -> OutPoint {
    let tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        buf.pack()
    };
    OutPoint::new(tx_hash, 0)
}

pub fn random_type_id_script() -> Script {
    let mut rng = thread_rng();
    let args = {
        let mut buf = vec![0u8; 32];
        rng.fill(&mut buf[..]);
        buf.pack()
    };
    Script::new_builder()
        .code_hash(TYPE_ID_CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(args)
        .build()
}

pub fn insert_cell(dummy: &mut DummyDataLoader, cell_meta: &CellMeta) {
    dummy.cells.insert(
        cell_meta.out_point.clone(),
        (
            cell_meta.cell_output.clone(),
            cell_meta.mem_cell_data.clone().unwrap(),
        ),
    );
}

pub fn script_cell(dummy: &mut DummyDataLoader, script_data: &Bytes) -> CellMeta {
    let out_point = random_out_point();
    let cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(script_data.len())
                .expect("script capacity")
                .pack(),
        )
        .build();
    let cell_meta = CellMetaBuilder::from_cell_output(cell, script_data.clone())
        .out_point(out_point)
        .build();
    insert_cell(dummy, &cell_meta);
    cell_meta
}

pub fn always_success_cell(dummy: &mut DummyDataLoader, capacity_bytes: usize) -> CellMeta {
    let out_point = random_out_point();
    let lock = Script::new_builder()
        .code_hash(CellOutput::calc_data_hash(&ALWAYS_SUCCESS_BIN))
        .hash_type(ScriptHashType::Data2.into())
        .build();
    let cell = CellOutput::new_builder()
        .lock(lock)
        .capacity(
            Capacity::bytes(capacity_bytes)
                .expect("script capacity")
                .pack(),
        )
        .build();
    let cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(out_point)
        .build();
    insert_cell(dummy, &cell_meta);
    cell_meta
}

pub fn zero_lock_cell(
    dummy: &mut DummyDataLoader,
    data: &Bytes,
    type_script: Option<Script>,
) -> CellMeta {
    let out_point = random_out_point();
    let lock = Script::new_builder()
        .code_hash(CellOutput::calc_data_hash(&ZERO_LOCK_BIN))
        .hash_type(ScriptHashType::Data2.into())
        .build();
    let cell = CellOutput::new_builder()
        .lock(lock)
        .type_(type_script.pack())
        .capacity(Capacity::bytes(data.len()).expect("script capacity").pack())
        .build();
    let cell_meta = CellMetaBuilder::from_cell_output(cell, data.clone())
        .out_point(out_point)
        .build();
    insert_cell(dummy, &cell_meta);
    cell_meta
}

pub fn complete_tx(
    mut dummy: DummyDataLoader,
    builder: TransactionBuilder,
    input_cells: Vec<CellMeta>,
) -> (
    TransactionScriptsVerifier<DummyDataLoader>,
    Arc<ResolvedTransaction>,
    DummyDataLoader,
) {
    let rtx: Arc<ResolvedTransaction> = {
        let zero_lock_cell_meta = script_cell(&mut dummy, &ZERO_LOCK_BIN);
        let always_success_cell_meta = script_cell(&mut dummy, &ALWAYS_SUCCESS_BIN);

        let tx = builder
            .cell_dep(
                CellDep::new_builder()
                    .out_point(zero_lock_cell_meta.out_point.clone())
                    .dep_type(DepType::Code.into())
                    .build(),
            )
            .cell_dep(
                CellDep::new_builder()
                    .out_point(always_success_cell_meta.out_point.clone())
                    .dep_type(DepType::Code.into())
                    .build(),
            )
            .inputs(
                input_cells
                    .iter()
                    .map(|input| CellInput::new(input.out_point.clone(), 0)),
            )
            .build();

        Arc::new(ResolvedTransaction {
            transaction: tx,
            resolved_inputs: input_cells.clone(),
            resolved_cell_deps: vec![zero_lock_cell_meta, always_success_cell_meta],
            resolved_dep_groups: vec![],
        })
    };

    let consensus = Arc::new(
        ConsensusBuilder::default()
            .hardfork_switch(HardForks {
                ckb2021: CKB2021::new_dev_default(),
                ckb2023: CKB2023::new_dev_default(),
            })
            .build(),
    );
    let tip = HeaderBuilder::default().number(0.pack()).build();
    let tx_verify_env = Arc::new(TxVerifyEnv::new_submit(&tip));

    let mut groups = HashMap::new();
    for (i, input_cell) in input_cells.iter().enumerate() {
        let lock_hash = input_cell.cell_output.lock().calc_script_hash();
        groups
            .entry(lock_hash)
            .or_insert(format!("Lock script of input cell {}", i));
        if let Some(type_script) = input_cell.cell_output.type_().to_opt() {
            let type_hash = type_script.calc_script_hash();
            groups
                .entry(type_hash)
                .or_insert(format!("Type script of input cell {}", i));
        }
    }
    for (i, output_cell) in rtx
        .transaction
        .data()
        .raw()
        .outputs()
        .into_iter()
        .enumerate()
    {
        if let Some(type_script) = output_cell.type_().to_opt() {
            let type_hash = type_script.calc_script_hash();
            groups
                .entry(type_hash)
                .or_insert(format!("Type script of output cell {}", i));
        }
    }

    let verifier =
        TransactionScriptsVerifier::new(rtx.clone(), dummy.clone(), consensus, tx_verify_env);
    // Uncomment to debug tests:
    // verifier.set_debug_printer(move |hash: &Byte32, message: &str| {
    //     let prefix = match groups.get(hash) {
    //         Some(text) => text.clone(),
    //         None => format!("Script group: {:x}", hash),
    //     };
    //     eprintln!("{} DEBUG OUTPUT: {}", prefix, message);
    // });
    (verifier, rtx, dummy)
}

#[derive(Debug)]
pub struct Blake2bHash;

impl Merge for Blake2bHash {
    type Item = Byte32;

    fn merge(lhs: &Self::Item, rhs: &Self::Item) -> Self::Item {
        let mut hasher = new_blake2b();
        hasher.update(&lhs.as_bytes());
        hasher.update(&rhs.as_bytes());
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash[..]);
        Byte32::new(hash)
    }
}

pub fn hash_upgrade_data(
    old_cell: &CellMeta,
    new_cell: &CellMeta,
    input_type: Option<Bytes>,
    output_type: Option<Bytes>,
) -> Byte32 {
    let mut hasher = new_blake2b();
    hasher.update(&[1u8]);
    hasher.update(old_cell.out_point.as_slice());
    hasher.update(&blake2b_256(new_cell.mem_cell_data.as_ref().unwrap())[..]);
    hasher.update(new_cell.cell_output.as_slice());
    if let Some(input_type) = input_type {
        hasher.update(&[1u8]);
        hasher.update(
            &TryInto::<u32>::try_into(input_type.len())
                .unwrap()
                .to_le_bytes(),
        );
        hasher.update(&input_type);
    } else {
        hasher.update(&[0u8]);
    }
    if let Some(output_type) = output_type {
        hasher.update(&[1u8]);
        hasher.update(
            &TryInto::<u32>::try_into(output_type.len())
                .unwrap()
                .to_le_bytes(),
        );
        hasher.update(&output_type);
    } else {
        hasher.update(&[0u8]);
    }
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash[..]);
    Byte32::new(hash)
}

pub fn build_merkle_root_n_proof(
    all_leaves: &[(&CellMeta, &CellMeta)],
    selected: u32,
    header_index: u32,
    input_type: Option<Bytes>,
    output_type: Option<Bytes>,
) -> (Byte32, Bytes) {
    let mut hashed_leaves: Vec<Byte32> = Vec::with_capacity(all_leaves.len());
    for (i, (old_cell, new_cell)) in all_leaves.iter().enumerate() {
        let leaf = if i == header_index as usize {
            hash_upgrade_data(old_cell, new_cell, input_type.clone(), output_type.clone())
        } else {
            hash_upgrade_data(old_cell, new_cell, None, None)
        };
        hashed_leaves.push(leaf);
    }
    let tree: MerkleTree<Byte32, Blake2bHash> = CBMT::build_merkle_tree(&hashed_leaves);
    let proof = tree.build_proof(&[selected]).expect("build merkle proof");

    let mut data = vec![];
    data.extend(header_index.to_le_bytes());
    data.extend(
        TryInto::<u32>::try_into(proof.indices().len())
            .unwrap()
            .to_le_bytes(),
    );
    for index in proof.indices() {
        data.extend(index.to_le_bytes());
    }
    data.extend(
        TryInto::<u32>::try_into(proof.lemmas().len())
            .unwrap()
            .to_le_bytes(),
    );
    for lemma in proof.lemmas() {
        data.extend(lemma.as_slice());
    }

    let witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(data)).pack())
        .input_type(input_type.pack())
        .output_type(output_type.pack())
        .build();

    (tree.root(), witness.as_bytes())
}

pub fn bury_in_merkle_tree<R: Rng>(
    input_meta: &CellMeta,
    output_meta: &CellMeta,
    entries: u32,
    rng: &mut R,
    header_index: u32,
    input_type: Option<Bytes>,
    output_type: Option<Bytes>,
) -> (Byte32, Bytes) {
    let mut dummy_loader = DummyDataLoader::default();

    let other_entries: Vec<(CellMeta, CellMeta)> = (0..entries)
        .map(|_i| {
            let type_id = if rng.gen_bool(0.5) {
                Some(random_type_id_script())
            } else {
                None
            };
            let mut input_data = vec![1u8; rng.gen_range(1..100)];
            rng.fill(&mut input_data[..]);
            let input_data = input_data.into();
            let input_meta = zero_lock_cell(&mut dummy_loader, &input_data, type_id.clone());
            let mut output_data = vec![1u8; rng.gen_range(1..100)];
            rng.fill(&mut output_data[..]);
            let output_data = output_data.into();
            let output_meta = zero_lock_cell(&mut dummy_loader, &output_data, type_id);

            (input_meta, output_meta)
        })
        .collect();

    let mut leaves: Vec<(&CellMeta, &CellMeta)> =
        other_entries.iter().map(|(a, b)| (a, b)).collect();
    let index = rng.gen_range(0..leaves.len());
    leaves.insert(index, (&input_meta, &output_meta));

    build_merkle_root_n_proof(&leaves, index as u32, header_index, input_type, output_type)
}

pub fn header(dummy: &mut DummyDataLoader, merkle_root: &Byte32) -> Byte32 {
    let mut rng = thread_rng();
    let epoch_ext = EpochExt::new_builder()
        .number(10)
        .start_number(9500)
        .length(1010)
        .build();
    let header = HeaderBuilder::default()
        .number(10000.pack())
        .epoch(epoch_ext.number_with_fraction(10000).pack())
        .transactions_root({
            let mut d = [0u8; 32];
            rng.fill(&mut d);
            Byte32::new(d)
        })
        .build();
    let mut extension = vec![0u8; 180];
    rng.fill(&mut extension[..]);
    extension[128..160].copy_from_slice(&merkle_root.as_bytes());
    let hash = header.hash();
    dummy.headers.insert(hash.clone(), header);
    dummy
        .extensions
        .insert(hash.clone(), Bytes::from(extension));
    hash
}
