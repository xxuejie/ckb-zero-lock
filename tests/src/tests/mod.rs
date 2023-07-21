use super::*;
use ckb_error::assert_error_eq;
use ckb_script::ScriptError;
use ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::WitnessArgs, prelude::*};
use proptest::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

const MAX_CYCLES: u64 = 60_000_000;

#[test]
fn test_zero_lock_exists() {
    assert!(ZERO_LOCK_BIN.len() > 0);
}

#[test]
fn test_single_zero_lock_upgrade() {
    let mut dummy_loader = DummyDataLoader::default();
    let type_id = random_type_id_script();
    let old_contract = vec![1u8; 100].into();
    let input_cell_meta = zero_lock_cell(&mut dummy_loader, &old_contract, Some(type_id.clone()));
    let new_contract = vec![2u8; 100].into();
    let output_cell_meta = zero_lock_cell(&mut dummy_loader, &new_contract, Some(type_id));

    let (root, proof_witness) =
        build_merkle_root_n_proof(&[(&input_cell_meta, &output_cell_meta)], 0);
    let header_dep = header(&mut dummy_loader, &root);

    let builder = TransactionBuilder::default()
        .output(output_cell_meta.cell_output.clone())
        .output_data(output_cell_meta.mem_cell_data.clone().unwrap().pack())
        .header_dep(header_dep)
        .witness(proof_witness.pack());

    let verifier = complete_tx(dummy_loader, builder, vec![input_cell_meta]).0;

    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_single_zero_lock_no_type_script_upgrade() {
    let mut dummy_loader = DummyDataLoader::default();
    let old_contract = vec![1u8; 100].into();
    let input_cell_meta = zero_lock_cell(&mut dummy_loader, &old_contract, None);
    let new_contract = vec![2u8; 100].into();
    let output_cell_meta = zero_lock_cell(&mut dummy_loader, &new_contract, None);

    let (root, proof_witness) =
        build_merkle_root_n_proof(&[(&input_cell_meta, &output_cell_meta)], 0);
    let header_dep = header(&mut dummy_loader, &root);

    let builder = TransactionBuilder::default()
        .output(output_cell_meta.cell_output.clone())
        .output_data(output_cell_meta.mem_cell_data.clone().unwrap().pack())
        .header_dep(header_dep)
        .witness(proof_witness.pack());

    let verifier = complete_tx(dummy_loader, builder, vec![input_cell_meta]).0;

    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_zero_lock_with_other_cells_upgrade() {
    let mut dummy_loader = DummyDataLoader::default();
    let type_id = random_type_id_script();
    let old_contract = vec![1u8; 100].into();
    let input_cell_meta = zero_lock_cell(&mut dummy_loader, &old_contract, Some(type_id.clone()));
    let new_contract = vec![2u8; 120].into();
    let output_cell_meta = zero_lock_cell(&mut dummy_loader, &new_contract, Some(type_id));

    let input_cell2 = always_success_cell(&mut dummy_loader, 150);
    let input_cell3 = always_success_cell(&mut dummy_loader, 200);
    let output_cell2 = always_success_cell(&mut dummy_loader, 320);

    let (root, proof_witness) =
        build_merkle_root_n_proof(&[(&input_cell_meta, &output_cell_meta)], 0);
    let header_dep = header(&mut dummy_loader, &root);

    let builder = TransactionBuilder::default()
        .output(output_cell_meta.cell_output.clone())
        .output_data(output_cell_meta.mem_cell_data.clone().unwrap().pack())
        .output(output_cell2.cell_output.clone())
        .output_data(output_cell2.mem_cell_data.clone().unwrap().pack())
        .header_dep(header_dep)
        .witness(proof_witness.pack());

    let verifier = complete_tx(
        dummy_loader,
        builder,
        vec![input_cell_meta, input_cell2, input_cell3],
    )
    .0;

    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_more_than_one_input_zero_lock_fails_verification() {
    let mut dummy_loader = DummyDataLoader::default();
    let old_contract = vec![1u8; 100].into();
    let input_cell_meta = zero_lock_cell(&mut dummy_loader, &old_contract, None);
    let new_contract = vec![2u8; 100].into();
    let output_cell_meta = zero_lock_cell(&mut dummy_loader, &new_contract, None);
    let old_contract2 = vec![3u8; 100].into();
    let input_cell_meta2 = zero_lock_cell(&mut dummy_loader, &old_contract2, None);

    let (root, proof_witness) =
        build_merkle_root_n_proof(&[(&input_cell_meta, &output_cell_meta)], 0);
    let header_dep = header(&mut dummy_loader, &root);

    let builder = TransactionBuilder::default()
        .output(output_cell_meta.cell_output.clone())
        .output_data(output_cell_meta.mem_cell_data.clone().unwrap().pack())
        .header_dep(header_dep)
        .witness(proof_witness.pack());

    let verifier = complete_tx(
        dummy_loader,
        builder,
        vec![input_cell_meta.clone(), input_cell_meta2],
    )
    .0;

    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::validation_failure(&input_cell_meta.cell_output.lock(), -61)
            .input_lock_script(0),
    );
}

#[test]
fn test_more_than_one_output_zero_lock_fails_verification() {
    let mut dummy_loader = DummyDataLoader::default();
    let old_contract = vec![1u8; 200].into();
    let input_cell_meta = zero_lock_cell(&mut dummy_loader, &old_contract, None);
    let new_contract = vec![2u8; 100].into();
    let output_cell_meta = zero_lock_cell(&mut dummy_loader, &new_contract, None);
    let new_contract2 = vec![3u8; 100].into();
    let output_cell_meta2 = zero_lock_cell(&mut dummy_loader, &new_contract2, None);

    let (root, proof_witness) =
        build_merkle_root_n_proof(&[(&input_cell_meta, &output_cell_meta)], 0);
    let header_dep = header(&mut dummy_loader, &root);

    let builder = TransactionBuilder::default()
        .output(output_cell_meta.cell_output.clone())
        .output_data(output_cell_meta.mem_cell_data.clone().unwrap().pack())
        .output(output_cell_meta2.cell_output.clone())
        .output_data(output_cell_meta2.mem_cell_data.clone().unwrap().pack())
        .header_dep(header_dep)
        .witness(proof_witness.pack());

    let verifier = complete_tx(dummy_loader, builder, vec![input_cell_meta.clone()]).0;

    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::validation_failure(&input_cell_meta.cell_output.lock(), -61)
            .input_lock_script(0),
    );
}

#[test]
fn test_input_zero_lock_at_other_indices() {
    let mut dummy_loader = DummyDataLoader::default();
    let type_id = random_type_id_script();
    let old_contract = vec![1u8; 100].into();
    let input_cell_meta = zero_lock_cell(&mut dummy_loader, &old_contract, Some(type_id.clone()));
    let new_contract = vec![2u8; 120].into();
    let output_cell_meta = zero_lock_cell(&mut dummy_loader, &new_contract, Some(type_id));

    let input_cell2 = always_success_cell(&mut dummy_loader, 150);
    let input_cell3 = always_success_cell(&mut dummy_loader, 200);
    let output_cell2 = always_success_cell(&mut dummy_loader, 320);

    let (root, proof_witness) =
        build_merkle_root_n_proof(&[(&input_cell_meta, &output_cell_meta)], 0);
    let header_dep = header(&mut dummy_loader, &root);

    let builder = TransactionBuilder::default()
        .output(output_cell_meta.cell_output.clone())
        .output_data(output_cell_meta.mem_cell_data.clone().unwrap().pack())
        .output(output_cell2.cell_output.clone())
        .output_data(output_cell2.mem_cell_data.clone().unwrap().pack())
        .header_dep(header_dep)
        .witness(Bytes::new().pack())
        .witness(proof_witness.pack());

    let verifier = complete_tx(
        dummy_loader,
        builder,
        vec![input_cell2, input_cell_meta, input_cell3],
    )
    .0;

    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_output_zero_lock_at_other_indices() {
    let mut dummy_loader = DummyDataLoader::default();
    let type_id = random_type_id_script();
    let old_contract = vec![1u8; 100].into();
    let input_cell_meta = zero_lock_cell(&mut dummy_loader, &old_contract, Some(type_id.clone()));
    let new_contract = vec![2u8; 120].into();
    let output_cell_meta = zero_lock_cell(&mut dummy_loader, &new_contract, Some(type_id));

    let input_cell2 = always_success_cell(&mut dummy_loader, 150);
    let input_cell3 = always_success_cell(&mut dummy_loader, 200);
    let output_cell2 = always_success_cell(&mut dummy_loader, 320);

    let (root, proof_witness) =
        build_merkle_root_n_proof(&[(&input_cell_meta, &output_cell_meta)], 0);
    let header_dep = header(&mut dummy_loader, &root);

    let builder = TransactionBuilder::default()
        .output(output_cell2.cell_output.clone())
        .output_data(output_cell2.mem_cell_data.clone().unwrap().pack())
        .output(output_cell_meta.cell_output.clone())
        .output_data(output_cell_meta.mem_cell_data.clone().unwrap().pack())
        .header_dep(header_dep)
        .witness(proof_witness.pack());

    let verifier = complete_tx(
        dummy_loader,
        builder,
        vec![input_cell_meta, input_cell2, input_cell3],
    )
    .0;

    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_missing_header_fails_verification() {
    let mut dummy_loader = DummyDataLoader::default();
    let type_id = random_type_id_script();
    let old_contract = vec![1u8; 100].into();
    let input_cell_meta = zero_lock_cell(&mut dummy_loader, &old_contract, Some(type_id.clone()));
    let new_contract = vec![2u8; 100].into();
    let output_cell_meta = zero_lock_cell(&mut dummy_loader, &new_contract, Some(type_id));

    let (root, proof_witness) =
        build_merkle_root_n_proof(&[(&input_cell_meta, &output_cell_meta)], 0);
    let _header_dep = header(&mut dummy_loader, &root);

    let builder = TransactionBuilder::default()
        .output(output_cell_meta.cell_output.clone())
        .output_data(output_cell_meta.mem_cell_data.clone().unwrap().pack())
        .witness(proof_witness.pack());

    let verifier = complete_tx(dummy_loader, builder, vec![input_cell_meta.clone()]).0;

    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::validation_failure(&input_cell_meta.cell_output.lock(), -61)
            .input_lock_script(0),
    );
}

proptest! {
    #[test]
    fn test_single_zero_lock_long_witness_upgrade(
        witness_extra_bytes in 1..409600usize,
        seed: u64,
    ) {
        let mut dummy_loader = DummyDataLoader::default();
        let type_id = random_type_id_script();
        let old_contract = vec![1u8; 100].into();
        let input_cell_meta = zero_lock_cell(&mut dummy_loader, &old_contract, Some(type_id.clone()));
        let new_contract = vec![2u8; 100].into();
        let output_cell_meta = zero_lock_cell(&mut dummy_loader, &new_contract, Some(type_id));

        let (root, proof_witness) =
            build_merkle_root_n_proof(&[(&input_cell_meta, &output_cell_meta)], 0);

        let proof_witness = {
            let mut rng = StdRng::seed_from_u64(seed);
            let mut bytes = vec![0u8; witness_extra_bytes];
            rng.fill(&mut bytes[..]);
            WitnessArgs::new_unchecked(proof_witness)
                .as_builder()
                .input_type(Some(Bytes::from(bytes)).pack())
                .build()
                .as_bytes()
        };

        let header_dep = header(&mut dummy_loader, &root);

        let builder = TransactionBuilder::default()
            .output(output_cell_meta.cell_output.clone())
            .output_data(output_cell_meta.mem_cell_data.clone().unwrap().pack())
            .header_dep(header_dep)
            .witness(proof_witness.pack());

        let verifier = complete_tx(dummy_loader, builder, vec![input_cell_meta]).0;

        let verify_result = verifier.verify(MAX_CYCLES);
        verify_result.expect("pass verification");
    }

    #[test]
    fn test_single_zero_lock_multiple_merkle_tree_entries_upgrade(
        entries in 1..30u32,
        seed: u64,
    ) {
        let mut dummy_loader = DummyDataLoader::default();
        let type_id = random_type_id_script();
        let old_contract = vec![1u8; 100].into();
        let input_cell_meta = zero_lock_cell(&mut dummy_loader, &old_contract, Some(type_id.clone()));
        let new_contract = vec![2u8; 100].into();
        let output_cell_meta = zero_lock_cell(&mut dummy_loader, &new_contract, Some(type_id));

        let mut rng = StdRng::seed_from_u64(seed);
        let (root, proof_witness) = bury_in_merkle_tree(
            &input_cell_meta,
            &output_cell_meta,
            entries,
            &mut rng,
        );
        let header_dep = header(&mut dummy_loader, &root);

        let builder = TransactionBuilder::default()
            .output(output_cell_meta.cell_output.clone())
            .output_data(output_cell_meta.mem_cell_data.clone().unwrap().pack())
            .header_dep(header_dep)
            .witness(proof_witness.pack());

        let verifier = complete_tx(dummy_loader, builder, vec![input_cell_meta]).0;

        let verify_result = verifier.verify(MAX_CYCLES);
        verify_result.expect("pass verification");
    }

    #[test]
    fn test_single_zero_lock_multiple_merkle_tree_entries_flip_root_bit_fails_verification(
        entries in 1..30u32,
        seed: u64,
        flip_bit in 0..256usize,
    ) {
        let mut dummy_loader = DummyDataLoader::default();
        let type_id = random_type_id_script();
        let old_contract = vec![1u8; 100].into();
        let input_cell_meta = zero_lock_cell(&mut dummy_loader, &old_contract, Some(type_id.clone()));
        let new_contract = vec![2u8; 100].into();
        let output_cell_meta = zero_lock_cell(&mut dummy_loader, &new_contract, Some(type_id));

        let mut rng = StdRng::seed_from_u64(seed);
        let (root, proof_witness) = bury_in_merkle_tree(
            &input_cell_meta,
            &output_cell_meta,
            entries,
            &mut rng,
        );

        let mut raw_root = [0u8; 32];
        raw_root.copy_from_slice(root.as_slice());
        raw_root[flip_bit / 8] ^= 1 << (flip_bit % 8);
        let root = raw_root.pack();

        let header_dep = header(&mut dummy_loader, &root);

        let builder = TransactionBuilder::default()
            .output(output_cell_meta.cell_output.clone())
            .output_data(output_cell_meta.mem_cell_data.clone().unwrap().pack())
            .header_dep(header_dep)
            .witness(proof_witness.pack());

        let verifier = complete_tx(dummy_loader, builder, vec![input_cell_meta.clone()]).0;

        let verify_result = verifier.verify(MAX_CYCLES);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::validation_failure(&input_cell_meta.cell_output.lock(), -61)
                .input_lock_script(0),
        );
    }

    #[test]
    fn test_single_zero_lock_multiple_merkle_tree_entries_flip_proof_bit_fails_verification(
        entries in 1..30u32,
        seed: u64,
        flip_bit: usize,
    ) {
        let mut dummy_loader = DummyDataLoader::default();
        let type_id = random_type_id_script();
        let old_contract = vec![1u8; 100].into();
        let input_cell_meta = zero_lock_cell(&mut dummy_loader, &old_contract, Some(type_id.clone()));
        let new_contract = vec![2u8; 100].into();
        let output_cell_meta = zero_lock_cell(&mut dummy_loader, &new_contract, Some(type_id));

        let mut rng = StdRng::seed_from_u64(seed);
        let (root, proof_witness) = bury_in_merkle_tree(
            &input_cell_meta,
            &output_cell_meta,
            entries,
            &mut rng,
        );

        let proof_witness = {
            let mut lock = WitnessArgs::new_unchecked(proof_witness)
                .as_reader().lock().to_opt().unwrap().as_slice().to_vec();
            let flip_bit = flip_bit % (lock.len() * 8);
            lock[flip_bit / 8] ^= 1 << (flip_bit % 8);

            WitnessArgs::new_builder().lock(Some(Bytes::from(lock)).pack())
                .build().as_bytes()
        };

        let header_dep = header(&mut dummy_loader, &root);

        let builder = TransactionBuilder::default()
            .output(output_cell_meta.cell_output.clone())
            .output_data(output_cell_meta.mem_cell_data.clone().unwrap().pack())
            .header_dep(header_dep)
            .witness(proof_witness.pack());

        let verifier = complete_tx(dummy_loader, builder, vec![input_cell_meta.clone()]).0;

        let verify_result = verifier.verify(MAX_CYCLES);
        assert!(format!("{}", verify_result.unwrap_err()).contains("Script(TransactionScriptError { source: Inputs[0].Lock, cause: ValidationFailure"));
    }

    #[test]
    fn test_single_zero_lock_multiple_merkle_tree_entries_truncate_proof_fails_verification(
        entries in 1..30u32,
        seed: u64,
        truncated_bytes: usize,
    ) {
        let mut dummy_loader = DummyDataLoader::default();
        let type_id = random_type_id_script();
        let old_contract = vec![1u8; 100].into();
        let input_cell_meta = zero_lock_cell(&mut dummy_loader, &old_contract, Some(type_id.clone()));
        let new_contract = vec![2u8; 100].into();
        let output_cell_meta = zero_lock_cell(&mut dummy_loader, &new_contract, Some(type_id));

        let mut rng = StdRng::seed_from_u64(seed);
        let (root, proof_witness) = bury_in_merkle_tree(
            &input_cell_meta,
            &output_cell_meta,
            entries,
            &mut rng,
        );

        let proof_witness = {
            let mut lock = WitnessArgs::new_unchecked(proof_witness)
                .as_reader().lock().to_opt().unwrap().as_slice().to_vec();
            let truncated_bytes = truncated_bytes % (lock.len() - 1) + 1;
            lock.truncate(truncated_bytes);

            WitnessArgs::new_builder().lock(Some(Bytes::from(lock)).pack())
                .build().as_bytes()
        };

        let header_dep = header(&mut dummy_loader, &root);

        let builder = TransactionBuilder::default()
            .output(output_cell_meta.cell_output.clone())
            .output_data(output_cell_meta.mem_cell_data.clone().unwrap().pack())
            .header_dep(header_dep)
            .witness(proof_witness.pack());

        let verifier = complete_tx(dummy_loader, builder, vec![input_cell_meta.clone()]).0;

        let verify_result = verifier.verify(MAX_CYCLES);
        assert!(format!("{}", verify_result.unwrap_err()).contains("Script(TransactionScriptError { source: Inputs[0].Lock, cause: ValidationFailure"));
    }
}
