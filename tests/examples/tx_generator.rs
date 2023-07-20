use ckb_mock_tx_types::{MockCellDep, MockInfo, MockInput, MockTransaction, ReprMockTransaction};
use ckb_traits::{ExtensionProvider, HeaderProvider};
use ckb_types::{
    core::{cell::ResolvedTransaction, TransactionBuilder},
    prelude::*,
};
use ckb_zero_lock_tests::{
    bury_in_merkle_tree, complete_tx, header, random_type_id_script, zero_lock_cell,
    DummyDataLoader,
};
use rand::{rngs::StdRng, Rng, SeedableRng};

fn main() {
    let seed: u64 = match std::env::var("SEED") {
        Ok(val) => str::parse(&val).expect("parsing number"),
        Err(_) => std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
    };
    println!("Seed: {}", seed);

    let mut rng = StdRng::seed_from_u64(seed);

    let entries = rng.gen_range(1..1000);
    println!("Merkle root entries: {}", entries + 1);

    let mut dummy_loader = DummyDataLoader::default();
    let type_id = random_type_id_script();
    let old_contract = vec![1u8; 100].into();
    let input_cell_meta = zero_lock_cell(&mut dummy_loader, &old_contract, Some(type_id.clone()));
    let new_contract = vec![2u8; 100].into();
    let output_cell_meta = zero_lock_cell(&mut dummy_loader, &new_contract, Some(type_id));

    let (root, proof_witness) =
        bury_in_merkle_tree(&input_cell_meta, &output_cell_meta, entries, &mut rng);
    let header_dep = header(&mut dummy_loader, &root);

    println!(
        "Proof witness total length(in WitnessArgs format): {}",
        proof_witness.len()
    );

    let builder = TransactionBuilder::default()
        .output(output_cell_meta.cell_output.clone())
        .output_data(output_cell_meta.mem_cell_data.clone().unwrap().pack())
        .header_dep(header_dep)
        .witness(proof_witness.pack());

    let (_, rtx, dummy) = complete_tx(dummy_loader, builder, vec![input_cell_meta]);

    let mock_tx = build_mock_transaction(&rtx, &dummy).expect("build mock transaction");
    let repr_tx: ReprMockTransaction = mock_tx.into();
    let json = serde_json::to_string_pretty(&repr_tx).expect("json");

    let output_path = match std::env::var("OUTPUT") {
        Ok(val) => val,
        _ => "./tx.json".to_string(),
    };
    std::fs::write(output_path, &json).expect("write");
}

fn build_mock_transaction<DL: HeaderProvider + ExtensionProvider>(
    rtx: &ResolvedTransaction,
    dl: &DL,
) -> Result<MockTransaction, String> {
    let mut inputs = Vec::with_capacity(rtx.resolved_inputs.len());
    // TODO: dep group, cell's header
    for (i, input) in rtx.resolved_inputs.iter().enumerate() {
        inputs.push(MockInput {
            input: rtx
                .transaction
                .inputs()
                .get(i)
                .ok_or_else(|| format!("Cannot locate cell input {} in transaction", i))?,
            output: input.cell_output.clone(),
            data: input.mem_cell_data.clone().unwrap(),
            header: None,
        });
    }
    let mut cell_deps = Vec::with_capacity(rtx.resolved_cell_deps.len());
    for (i, dep) in rtx.resolved_cell_deps.iter().enumerate() {
        cell_deps.push(MockCellDep {
            cell_dep: rtx.transaction.cell_deps().get(i).ok_or_else(|| {
                format!(
                    "Cannot locate cell dep {}, maybe you are using a dep group?",
                    i
                )
            })?,
            output: dep.cell_output.clone(),
            data: dep.mem_cell_data.clone().unwrap(),
            header: None,
        });
    }
    let mut header_deps = Vec::with_capacity(rtx.transaction.header_deps().len());
    let mut extensions = Vec::new();
    for header_hash in rtx.transaction.header_deps_iter() {
        header_deps.push(
            dl.get_header(&header_hash)
                .ok_or_else(|| format!("Cannot find header {:x}!", header_hash))?,
        );
        if let Some(extension) = dl.get_block_extension(&header_hash) {
            extensions.push((header_hash, extension.unpack()));
        }
    }
    Ok(MockTransaction {
        mock_info: MockInfo {
            inputs,
            cell_deps,
            header_deps,
            extensions,
        },
        tx: rtx.transaction.data(),
    })
}
