use mnt_cycle_constraints::{
    comparison_estimate, estimate_pairing_relation, NativeFieldModel, RelationCostModel,
    TowerCosts, DEFAULT_ADDITION_STEPS, DEFAULT_MILLER_ROUNDS,
};

#[test]
fn extension_tower_costs_are_explicit_and_stable() {
    let costs = TowerCosts::from_native_model(NativeFieldModel::default());
    assert_eq!(costs.fp_mul, 1);
    assert_eq!(costs.fq2_mul, 3);
    assert_eq!(costs.fq2_sqr, 2);
    assert_eq!(costs.fq4_mul, 9);
    assert_eq!(costs.fq4_sqr, 4);
    assert_eq!(costs.fq4_sparse_line_mul, 6);
}

#[test]
fn default_pairing_relation_uses_mnt4_loop_shape() {
    let estimate = estimate_pairing_relation(
        RelationCostModel::default(),
        DEFAULT_MILLER_ROUNDS,
        DEFAULT_ADDITION_STEPS,
    );
    assert_eq!(estimate.miller_rounds, 377);
    assert_eq!(estimate.addition_steps, 124);
    assert_eq!(estimate.fq4_square_per_round, 4);
    assert_eq!(estimate.sparse_line_mul_per_round, 6);
    assert_eq!(estimate.miller_transition_constraints, 4_514);
    assert_eq!(estimate.line_cache_constraints, 19_554);
    assert_eq!(estimate.fe_residue_constraints, 110);
    assert_eq!(estimate.total_prepared_residue_constraints, 24_178);
}

#[test]
fn native_relation_model_is_below_emulated_reference_anchors() {
    let cmp = comparison_estimate();
    assert!(cmp.native_prepared_residue < cmp.bn254_emulated_pairing_reference);
    assert!(cmp.native_prepared_residue < cmp.sonobe_decider_reference);
}

#[test]
fn line_cache_relation_breakdown_is_explicit() {
    let breakdown = mnt_cycle_constraints::line_cache_relation_breakdown(
        mnt_cycle_constraints::RelationCostModel::default(),
        DEFAULT_MILLER_ROUNDS,
        DEFAULT_ADDITION_STEPS,
    );
    assert_eq!(breakdown.double_line_constraints, 15_834);
    assert_eq!(breakdown.addition_line_constraints, 3_720);
    assert_eq!(breakdown.total_constraints, 19_554);
    assert_eq!(breakdown.double_steps, 377);
    assert_eq!(breakdown.addition_steps, 124);
}

#[test]
fn miller_relation_breakdown_supports_single_and_multi_shared_accumulator() {
    let model = RelationCostModel::default();
    let single = mnt_cycle_constraints::miller_relation_breakdown(
        model,
        DEFAULT_MILLER_ROUNDS,
        DEFAULT_ADDITION_STEPS,
        1,
    );
    assert_eq!(single.shared_square_constraints, 1_508);
    assert_eq!(single.sparse_line_constraints, 3_006);
    assert_eq!(single.total_constraints, 4_514);

    let multi2 = mnt_cycle_constraints::miller_relation_breakdown(
        model,
        DEFAULT_MILLER_ROUNDS,
        DEFAULT_ADDITION_STEPS,
        2,
    );
    assert_eq!(multi2.shared_square_constraints, 1_508);
    assert_eq!(multi2.sparse_line_constraints, 6_012);
    assert_eq!(multi2.total_constraints, 7_520);

    let multi4 = mnt_cycle_constraints::miller_relation_breakdown(
        model,
        DEFAULT_MILLER_ROUNDS,
        DEFAULT_ADDITION_STEPS,
        4,
    );
    assert_eq!(multi4.total_constraints, 13_532);
}

#[test]
fn final_exponentiation_residue_breakdown_compares_against_direct_chain() {
    let model = RelationCostModel::default();
    let breakdown = mnt_cycle_constraints::final_exponentiation_residue_breakdown(model, 5, 753);
    assert_eq!(breakdown.residue_segments, 5);
    assert_eq!(breakdown.residue_constraints, 110);
    assert_eq!(breakdown.direct_chain_steps, 753);
    assert_eq!(breakdown.direct_chain_constraints, 6_777);
    assert!(breakdown.residue_constraints < breakdown.direct_chain_constraints);
}

#[test]
fn compiled_native_relation_is_real_r1cs_and_satisfied() {
    let report = mnt_cycle_constraints::compile_prepared_relation_from_hex_roots(
        "0xe429001bc805f56c1ee60d0a1a944469f8909dc41f851b35ffaef09bc5cb1e99",
        "0xe4d856950fae10a6cebe4eec166088df4be940fb0f70fef8de85e9895",
        "0x1eb603478321298f4249195923b2c1034802ac1a48d3289f6dfbd074a77b87c8",
        1,
    )
    .unwrap();
    assert!(report.is_satisfied);
    assert_eq!(report.public_inputs, 3);
    assert!(report.constraints > report.estimated_constraints);
    assert!(report.constraints < mnt_cycle_constraints::comparison_estimate().bn254_emulated_pairing_reference);
}

#[test]
fn compiled_native_relation_rejects_tampered_witness_root() {
    let public = mnt_cycle_constraints::NativeRelationPublicInputs::from_hex_roots(
        "0xe429001bc805f56c1ee60d0a1a944469f8909dc41f851b35ffaef09bc5cb1e99",
        "0xe4d856950fae10a6cebe4eec166088df4be940fb0f70fef8de85e9895",
        "0x1eb603478321298f4249195923b2c1034802ac1a48d3289f6dfbd074a77b87c8",
    )
    .unwrap();
    let witness = mnt_cycle_constraints::NativeRelationWitness::from_hex_roots(
        "0x0000000000000000000000000000000000000000000000000000000000000007",
        "0xe4d856950fae10a6cebe4eec166088df4be940fb0f70fef8de85e9895",
        "0x1eb603478321298f4249195923b2c1034802ac1a48d3289f6dfbd074a77b87c8",
    )
    .unwrap();
    let report = mnt_cycle_constraints::compile_prepared_relation(public, witness, 1).unwrap();
    assert!(!report.is_satisfied);
}
