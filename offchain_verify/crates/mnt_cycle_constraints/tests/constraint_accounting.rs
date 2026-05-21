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
