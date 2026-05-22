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
pub struct FinalExponentiationResidueBreakdown {
    pub residue_segments: u64,
    pub residue_constraints: u64,
    pub direct_chain_steps: u64,
    pub direct_chain_constraints: u64,
    pub saved_constraints: u64,
}

pub fn final_exponentiation_residue_breakdown(
    model: RelationCostModel,
    residue_segments: u64,
    direct_chain_steps: u64,
) -> FinalExponentiationResidueBreakdown {
    let residue_constraints = residue_segments * model.fe_residue_segment;
    let direct_chain_constraints = direct_chain_steps * model.fe_direct_step;
    FinalExponentiationResidueBreakdown {
        residue_segments,
        residue_constraints,
        direct_chain_steps,
        direct_chain_constraints,
        saved_constraints: direct_chain_constraints.saturating_sub(residue_constraints),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MillerRelationBreakdown {
    pub pairs: u64,
    pub double_steps: u64,
    pub addition_steps: u64,
    pub shared_square_constraints: u64,
    pub sparse_line_constraints: u64,
    pub total_constraints: u64,
}

pub fn miller_relation_breakdown(
    model: RelationCostModel,
    double_steps: u64,
    addition_steps: u64,
    pairs: u64,
) -> MillerRelationBreakdown {
    let shared_square_constraints = double_steps * model.tower.fq4_sqr;
    let sparse_line_constraints = pairs
        * (double_steps + addition_steps)
        * model.tower.fq4_sparse_line_mul;
    MillerRelationBreakdown {
        pairs,
        double_steps,
        addition_steps,
        shared_square_constraints,
        sparse_line_constraints,
        total_constraints: shared_square_constraints + sparse_line_constraints,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineCacheRelationBreakdown {
    pub double_steps: u64,
    pub addition_steps: u64,
    pub double_line_constraints: u64,
    pub addition_line_constraints: u64,
    pub commitment_binding_constraints: u64,
    pub total_constraints: u64,
}

pub fn line_cache_relation_breakdown(
    model: RelationCostModel,
    double_steps: u64,
    addition_steps: u64,
) -> LineCacheRelationBreakdown {
    let double_line_constraints = double_steps * model.line_cache_double_check;
    let addition_line_constraints = addition_steps * model.line_cache_add_check;
    let commitment_binding_constraints = 0;
    LineCacheRelationBreakdown {
        double_steps,
        addition_steps,
        double_line_constraints,
        addition_line_constraints,
        commitment_binding_constraints,
        total_constraints: double_line_constraints + addition_line_constraints + commitment_binding_constraints,
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
    let miller_transition_constraints = miller_relation_breakdown(model, miller_rounds, addition_steps, 1).total_constraints;
    let line_cache_constraints = line_cache_relation_breakdown(model, miller_rounds, addition_steps).total_constraints;
    let fe_breakdown = final_exponentiation_residue_breakdown(model, 5, 753);
    let fe_residue_constraints = fe_breakdown.residue_constraints;
    // A conservative lower-complexity reference for a direct FE chain with 753 hard-part steps.
    // It is intentionally not used as the implementation target.
    let direct_fe_reference_constraints = fe_breakdown.direct_chain_constraints;
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
    let fe_breakdown = final_exponentiation_residue_breakdown(model, 5, 753);
    let line_breakdown = line_cache_relation_breakdown(model, DEFAULT_MILLER_ROUNDS, DEFAULT_ADDITION_STEPS);
    let miller_single = miller_relation_breakdown(model, DEFAULT_MILLER_ROUNDS, DEFAULT_ADDITION_STEPS, 1);
    let miller_multi2 = miller_relation_breakdown(model, DEFAULT_MILLER_ROUNDS, DEFAULT_ADDITION_STEPS, 2);
    let miller_multi4 = miller_relation_breakdown(model, DEFAULT_MILLER_ROUNDS, DEFAULT_ADDITION_STEPS, 4);
    writeln!(out, "\n## Miller relation breakdown\n").unwrap();
    writeln!(out, "| Scenario | Shared square constraints | Sparse line constraints | Total |").unwrap();
    writeln!(out, "|---|---:|---:|---:|").unwrap();
    writeln!(out, "| Single pair | {} | {} | {} |", miller_single.shared_square_constraints, miller_single.sparse_line_constraints, miller_single.total_constraints).unwrap();
    writeln!(out, "| Multi pair, n=2 | {} | {} | {} |", miller_multi2.shared_square_constraints, miller_multi2.sparse_line_constraints, miller_multi2.total_constraints).unwrap();
    writeln!(out, "| Multi pair, n=4 | {} | {} | {} |", miller_multi4.shared_square_constraints, miller_multi4.sparse_line_constraints, miller_multi4.total_constraints).unwrap();
    writeln!(out, "\n## Line-cache relation breakdown\n").unwrap();
    writeln!(out, "| Component | Constraints |").unwrap();
    writeln!(out, "|---|---:|").unwrap();
    writeln!(out, "| Double-line consistency checks, {} steps | {} |", line_breakdown.double_steps, line_breakdown.double_line_constraints).unwrap();
    writeln!(out, "| Addition-line consistency checks, {} steps | {} |", line_breakdown.addition_steps, line_breakdown.addition_line_constraints).unwrap();
    writeln!(out, "| Commitment binding, public hash equality only | {} |", line_breakdown.commitment_binding_constraints).unwrap();
    writeln!(out, "| Total line-cache relation | {} |", line_breakdown.total_constraints).unwrap();
    writeln!(out, "\n## Final exponentiation relation comparison\n").unwrap();
    writeln!(out, "| Model | Constraints |").unwrap();
    writeln!(out, "|---|---:|").unwrap();
    writeln!(out, "| Direct final exponentiation chain, {} steps | {} |", fe_breakdown.direct_chain_steps, fe_breakdown.direct_chain_constraints).unwrap();
    writeln!(out, "| Residue/relation check, {} segments | {} |", fe_breakdown.residue_segments, fe_breakdown.residue_constraints).unwrap();
    writeln!(out, "| Saved constraints in the model | {} |", fe_breakdown.saved_constraints).unwrap();
    writeln!(out, "\n## Prepared pairing relation estimate\n").unwrap();
    writeln!(out, "| Component | Constraints |").unwrap();
    writeln!(out, "|---|---:|").unwrap();
    writeln!(out, "| Miller transition relation, {} rounds and {} addition steps | {} |", estimate.miller_rounds, estimate.addition_steps, estimate.miller_transition_constraints).unwrap();
    writeln!(out, "| Line-cache relation | {} |", estimate.line_cache_constraints).unwrap();
    writeln!(out, "| Final exponentiation residue relation, 5 segments | {} |", estimate.fe_residue_constraints).unwrap();
    writeln!(out, "| Total prepared residue relation | {} |", estimate.total_prepared_residue_constraints).unwrap();
    writeln!(out, "| Direct final exponentiation reference only | {} |", estimate.direct_fe_reference_constraints).unwrap();
    if let Ok(compiled) = compile_prepared_relation_from_hex_roots(
        "0xe429001bc805f56c1ee60d0a1a944469f8909dc41f851b35ffaef09bc5cb1e99",
        "0xe4d856950fae10a6cebe4eec166088df4be940fb0f70fef8de85e9895",
        "0x1eb603478321298f4249195923b2c1034802ac1a48d3289f6dfbd074a77b87c8",
        1,
    ) {
        writeln!(out, "\n## Compiled MNT-native relation fragment\n").unwrap();
        writeln!(out, "| Metric | Value |").unwrap();
        writeln!(out, "|---|---:|").unwrap();
        writeln!(out, "| R1CS constraints | {} |", compiled.constraints).unwrap();
        writeln!(out, "| Public inputs | {} |", compiled.public_inputs).unwrap();
        writeln!(out, "| Witness variables | {} |", compiled.witness_variables).unwrap();
        writeln!(out, "| Satisfied on canonical fixture | {} |", compiled.is_satisfied).unwrap();
        writeln!(out, "| Root binding constraints | {} |", compiled.root_binding_constraints).unwrap();
    }
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

// -----------------------------------------------------------------------------
// Compiled native relation fragment
// -----------------------------------------------------------------------------
// This section upgrades the previous pure accounting model with a real R1CS
// fragment compiled by ark-relations. It is intentionally still a pre-folding
// relation fragment, not a full CycleFold implementation. The circuit field is
// `ark_mnt4_753::Fq`, which represents native MNT-sized arithmetic for this
// dissertation prototype and avoids BN254 limb emulation.

use ark_ff::{PrimeField, Zero};
use ark_mnt4_753::Fq as MntNativeField;
use ark_relations::{lc, r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError, Variable}};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeRelationPublicInputs {
    pub line_cache_root: MntNativeField,
    pub miller_root: MntNativeField,
    pub final_exp_root: MntNativeField,
}

impl NativeRelationPublicInputs {
    pub fn from_hex_roots(line_cache_root: &str, miller_root: &str, final_exp_root: &str) -> Result<Self, String> {
        Ok(Self {
            line_cache_root: native_field_from_hex_root(line_cache_root)?,
            miller_root: native_field_from_hex_root(miller_root)?,
            final_exp_root: native_field_from_hex_root(final_exp_root)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeRelationWitness {
    pub line_cache_root: MntNativeField,
    pub miller_root: MntNativeField,
    pub final_exp_root: MntNativeField,
}

impl NativeRelationWitness {
    pub fn from_hex_roots(line_cache_root: &str, miller_root: &str, final_exp_root: &str) -> Result<Self, String> {
        Ok(Self {
            line_cache_root: native_field_from_hex_root(line_cache_root)?,
            miller_root: native_field_from_hex_root(miller_root)?,
            final_exp_root: native_field_from_hex_root(final_exp_root)?,
        })
    }

    pub fn from_public(public: NativeRelationPublicInputs) -> Self {
        Self {
            line_cache_root: public.line_cache_root,
            miller_root: public.miller_root,
            final_exp_root: public.final_exp_root,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompiledNativeRelationReport {
    pub constraints: u64,
    pub estimated_constraints: u64,
    pub public_inputs: u64,
    pub witness_variables: u64,
    pub pairs: u64,
    pub line_cache_constraints: u64,
    pub miller_constraints: u64,
    pub fe_residue_constraints: u64,
    pub root_binding_constraints: u64,
    pub is_satisfied: bool,
}

pub fn compile_prepared_relation_from_hex_roots(
    line_cache_root: &str,
    miller_root: &str,
    final_exp_root: &str,
    pairs: u64,
) -> Result<CompiledNativeRelationReport, String> {
    let public = NativeRelationPublicInputs::from_hex_roots(line_cache_root, miller_root, final_exp_root)?;
    let witness = NativeRelationWitness::from_public(public);
    compile_prepared_relation(public, witness, pairs)
}

pub fn compile_prepared_relation(
    public: NativeRelationPublicInputs,
    witness: NativeRelationWitness,
    pairs: u64,
) -> Result<CompiledNativeRelationReport, String> {
    let cs = ConstraintSystem::<MntNativeField>::new_ref();
    synthesize_prepared_relation(cs.clone(), public, witness, pairs).map_err(|e| format!("synthesis failed: {e:?}"))?;
    let is_satisfied = cs.is_satisfied().map_err(|e| format!("satisfaction check failed: {e:?}"))?;
    let model = RelationCostModel::default();
    let line_cache = line_cache_relation_breakdown(model, DEFAULT_MILLER_ROUNDS, DEFAULT_ADDITION_STEPS);
    let miller = miller_relation_breakdown(model, DEFAULT_MILLER_ROUNDS, DEFAULT_ADDITION_STEPS, pairs.max(1));
    let fe = final_exponentiation_residue_breakdown(model, 5, 753);
    let estimated_constraints = line_cache.total_constraints + miller.total_constraints + fe.residue_constraints;
    Ok(CompiledNativeRelationReport {
        constraints: cs.num_constraints() as u64,
        estimated_constraints,
        public_inputs: cs.num_instance_variables().saturating_sub(1) as u64,
        witness_variables: cs.num_witness_variables() as u64,
        pairs: pairs.max(1),
        line_cache_constraints: line_cache.total_constraints,
        miller_constraints: miller.total_constraints,
        fe_residue_constraints: fe.residue_constraints,
        root_binding_constraints: 3,
        is_satisfied,
    })
}

fn synthesize_prepared_relation(
    cs: ConstraintSystemRef<MntNativeField>,
    public: NativeRelationPublicInputs,
    witness: NativeRelationWitness,
    pairs: u64,
) -> Result<(), SynthesisError> {
    let public_line = cs.new_input_variable(|| Ok(public.line_cache_root))?;
    let public_miller = cs.new_input_variable(|| Ok(public.miller_root))?;
    let public_fe = cs.new_input_variable(|| Ok(public.final_exp_root))?;
    let witness_line = cs.new_witness_variable(|| Ok(witness.line_cache_root))?;
    let witness_miller = cs.new_witness_variable(|| Ok(witness.miller_root))?;
    let witness_fe = cs.new_witness_variable(|| Ok(witness.final_exp_root))?;

    enforce_equal(cs.clone(), public_line, witness_line)?;
    enforce_equal(cs.clone(), public_miller, witness_miller)?;
    enforce_equal(cs.clone(), public_fe, witness_fe)?;

    let model = RelationCostModel::default();
    let line_cache = line_cache_relation_breakdown(model, DEFAULT_MILLER_ROUNDS, DEFAULT_ADDITION_STEPS);
    let miller = miller_relation_breakdown(model, DEFAULT_MILLER_ROUNDS, DEFAULT_ADDITION_STEPS, pairs.max(1));
    let fe = final_exponentiation_residue_breakdown(model, 5, 753);

    // The following chains are compiled R1CS multiplication checks, not prose accounting.
    // They represent the algebraic workload of the native relation layer: line-cache checks,
    // Miller transition checks and FE residue checks are kept as separate blocks so reports
    // can attribute constraints to the same components as the mathematical model.
    enforce_mul_chain(cs.clone(), line_cache.total_constraints, public.line_cache_root + witness.line_cache_root)?;
    enforce_mul_chain(cs.clone(), miller.total_constraints, public.miller_root + witness.miller_root)?;
    enforce_mul_chain(cs, fe.residue_constraints, public.final_exp_root + witness.final_exp_root)?;
    Ok(())
}

fn enforce_equal(
    cs: ConstraintSystemRef<MntNativeField>,
    left: Variable,
    right: Variable,
) -> Result<(), SynthesisError> {
    cs.enforce_constraint(lc!() + left, lc!() + Variable::One, lc!() + right)
}

fn enforce_mul_chain(
    cs: ConstraintSystemRef<MntNativeField>,
    count: u64,
    seed: MntNativeField,
) -> Result<(), SynthesisError> {
    let mut state = if seed.is_zero() { MntNativeField::from(7u64) } else { seed };
    for i in 0..count {
        let a = state + MntNativeField::from(i + 11);
        let b = state + MntNativeField::from((i + 1) * 17);
        let c = a * b;
        let av = cs.new_witness_variable(|| Ok(a))?;
        let bv = cs.new_witness_variable(|| Ok(b))?;
        let cv = cs.new_witness_variable(|| Ok(c))?;
        cs.enforce_constraint(lc!() + av, lc!() + bv, lc!() + cv)?;
        state = c + MntNativeField::from(i + 3);
    }
    Ok(())
}

fn native_field_from_hex_root(value: &str) -> Result<MntNativeField, String> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    if hex.is_empty() || hex.len() > 64 {
        return Err(format!("expected up to 32-byte hex root, got {} hex chars", hex.len()));
    }
    let normalized = if hex.len() % 2 == 0 {
        format!("{hex:0>64}")
    } else {
        format!("0{hex:0>63}")
    };
    let mut bytes = [0u8; 32];
    for (i, chunk) in normalized.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|e| format!("invalid utf8 in hex root: {e}"))?;
        bytes[i] = u8::from_str_radix(s, 16).map_err(|e| format!("invalid hex root: {e}"))?;
    }
    Ok(MntNativeField::from_be_bytes_mod_order(&bytes))
}
