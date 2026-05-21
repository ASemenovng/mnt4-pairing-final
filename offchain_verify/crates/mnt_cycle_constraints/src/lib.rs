//! Native MNT4/MNT6-cycle constraint accounting for the dissertation prototype.
//!
//! This crate deliberately does not claim to be a production folding circuit.
//! It is a reproducible accounting layer: every reported number is obtained from
//! an explicit operation model for arithmetic that is native to the MNT cycle.
//! The purpose is to distinguish the current BN254 verifier-envelope from the
//! future MNT-native relation that will be folded.

use std::fmt::Write;

pub const DEFAULT_MILLER_ROUNDS: u64 = 377;
pub const DEFAULT_ADDITION_STEPS: u64 = 124;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeFieldModel {
    /// A native field multiplication is one multiplication constraint in R1CS.
    pub mul: u64,
    /// A native field addition is linear and is accounted as zero multiplication constraints.
    pub add: u64,
    /// A native field equality is linear and is accounted as zero multiplication constraints.
    pub eq: u64,
    /// Optional range/canonicality guard per public field element. The default report keeps it zero
    /// because arkworks-native field variables already live in the circuit scalar field.
    pub canonical_guard: u64,
}

impl Default for NativeFieldModel {
    fn default() -> Self {
        Self {
            mul: 1,
            add: 0,
            eq: 0,
            canonical_guard: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TowerCosts {
    pub fp_add: u64,
    pub fp_mul: u64,
    pub fq2_add: u64,
    pub fq2_mul: u64,
    pub fq2_sqr: u64,
    pub fq4_add: u64,
    pub fq4_mul: u64,
    pub fq4_sqr: u64,
    pub fq4_sparse_line_mul: u64,
}

impl TowerCosts {
    pub fn from_native_model(model: NativeFieldModel) -> Self {
        let fp_add = model.add;
        let fp_mul = model.mul;
        // Karatsuba multiplication in a quadratic extension:
        // (a0 + a1 u)(b0 + b1 u) uses v0=a0*b0, v1=a1*b1, v2=(a0+a1)(b0+b1).
        let fq2_mul = 3 * fp_mul;
        // Complex squaring in a quadratic extension uses two base-field multiplications.
        let fq2_sqr = 2 * fp_mul;
        let fq2_add = 2 * fp_add;
        // Fq4 is modeled as a quadratic extension over Fq2.
        let fq4_mul = 3 * fq2_mul;
        let fq4_sqr = 2 * fq2_sqr;
        let fq4_add = 2 * fq2_add;
        // Sparse line multiplication in the current MNT4 target field is modeled as two Fq2
        // multiplications by non-zero line components plus linear recombination.
        let fq4_sparse_line_mul = 2 * fq2_mul;
        Self {
            fp_add,
            fp_mul,
            fq2_add,
            fq2_mul,
            fq2_sqr,
            fq4_add,
            fq4_mul,
            fq4_sqr,
            fq4_sparse_line_mul,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelationCostModel {
    pub tower: TowerCosts,
    /// Cost of checking that one prepared doubling line is consistent with the current G2 state.
    pub line_cache_double_check: u64,
    /// Cost of checking that one prepared addition line is consistent with the current G2 state.
    pub line_cache_add_check: u64,
    /// Cost of one residue/relation segment replacing part of direct final exponentiation.
    pub fe_residue_segment: u64,
    /// Cost of one direct Fq4 multiplication/squaring step in a final-exponentiation chain.
    pub fe_direct_step: u64,
}

impl Default for RelationCostModel {
    fn default() -> Self {
        let tower = TowerCosts::from_native_model(NativeFieldModel::default());
        Self {
            tower,
            // Conservative algebraic accounting for affine/Jacobian line checks in Fq2.
            // It includes slope/line consistency and next-state consistency. These constants
            // are explicit model constants, not measured production circuit outputs.
            line_cache_double_check: 14 * tower.fq2_mul,
            line_cache_add_check: 10 * tower.fq2_mul,
            // Residue check segment: two Fq4 multiplications plus one Fq4 square.
            fe_residue_segment: 2 * tower.fq4_mul + tower.fq4_sqr,
            // Direct chain step: conservatively one Fq4 multiplication/square.
            fe_direct_step: tower.fq4_mul,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingRelationEstimate {
    pub miller_rounds: u64,
    pub addition_steps: u64,
    pub fq4_square_per_round: u64,
    pub sparse_line_mul_per_round: u64,
    pub miller_transition_constraints: u64,
    pub line_cache_constraints: u64,
    pub fe_residue_constraints: u64,
    pub direct_fe_reference_constraints: u64,
    pub total_prepared_residue_constraints: u64,
}

pub fn estimate_pairing_relation(
    model: RelationCostModel,
    miller_rounds: u64,
    addition_steps: u64,
) -> PairingRelationEstimate {
    let fq4_square_per_round = model.tower.fq4_sqr;
    let sparse_line_mul_per_round = model.tower.fq4_sparse_line_mul;
    let miller_transition_constraints = miller_rounds
        * (model.tower.fq4_sqr + model.tower.fq4_sparse_line_mul)
        + addition_steps * model.tower.fq4_sparse_line_mul;
    let line_cache_constraints = miller_rounds * model.line_cache_double_check
        + addition_steps * model.line_cache_add_check;
    let fe_residue_constraints = 5 * model.fe_residue_segment;
    // A conservative lower-complexity reference for a direct FE chain with 753 hard-part steps.
    // It is intentionally not used as the implementation target.
    let direct_fe_reference_constraints = 753 * model.fe_direct_step;
    let total_prepared_residue_constraints =
        miller_transition_constraints + line_cache_constraints + fe_residue_constraints;
    PairingRelationEstimate {
        miller_rounds,
        addition_steps,
        fq4_square_per_round,
        sparse_line_mul_per_round,
        miller_transition_constraints,
        line_cache_constraints,
        fe_residue_constraints,
        direct_fe_reference_constraints,
        total_prepared_residue_constraints,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComparisonEstimate {
    pub native_prepared_residue: u64,
    pub native_direct_fe_reference: u64,
    pub bn254_emulated_pairing_reference: u64,
    pub sonobe_decider_reference: u64,
}

pub fn comparison_estimate() -> ComparisonEstimate {
    let model = RelationCostModel::default();
    let estimate = estimate_pairing_relation(model, DEFAULT_MILLER_ROUNDS, DEFAULT_ADDITION_STEPS);
    ComparisonEstimate {
        native_prepared_residue: estimate.total_prepared_residue_constraints,
        native_direct_fe_reference: estimate.miller_transition_constraints
            + estimate.line_cache_constraints
            + estimate.direct_fe_reference_constraints,
        // External reference value from emulated-pairing literature for a BN254 pairing in BN254 R1CS.
        // It is kept as a comparison anchor, not as a value measured by this crate.
        bn254_emulated_pairing_reference: 1_393_318,
        // Sonobe documentation/reference experiments mention DeciderEthCircuit around nine million
        // constraints for the Ethereum decider contour. This is a comparison anchor.
        sonobe_decider_reference: 9_000_000,
    }
}

pub fn render_markdown_report() -> String {
    let model = RelationCostModel::default();
    let tower = model.tower;
    let estimate = estimate_pairing_relation(model, DEFAULT_MILLER_ROUNDS, DEFAULT_ADDITION_STEPS);
    let cmp = comparison_estimate();
    let mut out = String::new();
    writeln!(out, "# MNT-cycle native constraint accounting report\n").unwrap();
    writeln!(out, "This report is generated by `crates/mnt_cycle_constraints`. It is not a production folding circuit. It is a reproducible accounting model for the MNT-native relation layer that the future folding implementation should use.\n").unwrap();
    writeln!(out, "## Operation model\n").unwrap();
    writeln!(out, "| Operation | Multiplication constraints |").unwrap();
    writeln!(out, "|---|---:|").unwrap();
    writeln!(out, "| Native Fp multiplication | {} |", tower.fp_mul).unwrap();
    writeln!(out, "| Native Fp addition/equality | {} |", tower.fp_add).unwrap();
    writeln!(out, "| Fq2 multiplication, Karatsuba | {} |", tower.fq2_mul).unwrap();
    writeln!(out, "| Fq2 square | {} |", tower.fq2_sqr).unwrap();
    writeln!(out, "| Fq4 multiplication | {} |", tower.fq4_mul).unwrap();
    writeln!(out, "| Fq4 square | {} |", tower.fq4_sqr).unwrap();
    writeln!(out, "| Fq4 sparse line multiplication | {} |", tower.fq4_sparse_line_mul).unwrap();
    writeln!(out, "\n## Prepared pairing relation estimate\n").unwrap();
    writeln!(out, "| Component | Constraints |").unwrap();
    writeln!(out, "|---|---:|").unwrap();
    writeln!(out, "| Miller transition relation, {} rounds and {} addition steps | {} |", estimate.miller_rounds, estimate.addition_steps, estimate.miller_transition_constraints).unwrap();
    writeln!(out, "| Line-cache relation | {} |", estimate.line_cache_constraints).unwrap();
    writeln!(out, "| Final exponentiation residue relation, 5 segments | {} |", estimate.fe_residue_constraints).unwrap();
    writeln!(out, "| Total prepared residue relation | {} |", estimate.total_prepared_residue_constraints).unwrap();
    writeln!(out, "| Direct final exponentiation reference only | {} |", estimate.direct_fe_reference_constraints).unwrap();
    writeln!(out, "\n## Comparison anchors\n").unwrap();
    writeln!(out, "| Scenario | Constraints |").unwrap();
    writeln!(out, "|---|---:|").unwrap();
    writeln!(out, "| MNT-native prepared/residue relation model | {} |", cmp.native_prepared_residue).unwrap();
    writeln!(out, "| MNT-native model with direct FE reference | {} |", cmp.native_direct_fe_reference).unwrap();
    writeln!(out, "| BN254 emulated pairing reference | {} |", cmp.bn254_emulated_pairing_reference).unwrap();
    writeln!(out, "| Sonobe-like Ethereum decider reference | {} |", cmp.sonobe_decider_reference).unwrap();
    writeln!(out, "\n## Interpretation\n").unwrap();
    writeln!(out, "The current Solidity verifier remains a BN254 verification envelope for EVM compatibility. The numbers above are the intended MNT-native relation layer: it is the part that should later be folded over the MNT4/MNT6 cycle. The report therefore must not be read as a claim that the existing BN254 circuit proves the whole MNT4 pairing with this number of constraints.\n").unwrap();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tower_costs_follow_quadratic_extension_formulas() {
        let costs = TowerCosts::from_native_model(NativeFieldModel::default());
        assert_eq!(costs.fq2_mul, 3);
        assert_eq!(costs.fq2_sqr, 2);
        assert_eq!(costs.fq4_mul, 9);
        assert_eq!(costs.fq4_sqr, 4);
        assert_eq!(costs.fq4_sparse_line_mul, 6);
    }

    #[test]
    fn prepared_residue_relation_is_smaller_than_direct_fe_reference() {
        let model = RelationCostModel::default();
        let estimate = estimate_pairing_relation(model, DEFAULT_MILLER_ROUNDS, DEFAULT_ADDITION_STEPS);
        assert!(estimate.total_prepared_residue_constraints < estimate.miller_transition_constraints + estimate.line_cache_constraints + estimate.direct_fe_reference_constraints);
    }
}
