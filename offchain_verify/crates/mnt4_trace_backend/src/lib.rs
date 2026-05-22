use ark_ec::{models::mnt4::MNT4Config, pairing::Pairing, CurveGroup, Group};
use ark_ff::{BigInteger, CyclotomicMultSubgroup, Field, PrimeField};
use ark_mnt4_753::{
    Config, Fq, Fq2, Fq4, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, MNT4_753,
};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, time::Instant};
use tiny_keccak::{Hasher, Keccak};

pub const DEFAULT_CONTEXT_HEX: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000000";
pub const FINAL_EXP_SEGMENTS: u32 = 5;
pub const PARAMETRIC_Q_DOMAIN: &str = "MNT4_R8_PARAMETRIC_Q_V3";

const FQ2_BYTES: usize = 192;
const DBL_SPARSE_FQ2_PER_STEP: usize = 3;
const ADD_SPARSE_FQ2_PER_STEP: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendMode {
    FixedQ,
    ParametricQ,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRequest {
    #[serde(default = "default_mode")]
    pub mode: BackendMode,
    #[serde(default)]
    pub points: Vec<G1PointMont>,
    #[serde(default)]
    pub q: Option<G2PointMont>,
    #[serde(default = "default_context_string")]
    pub context: String,
    #[serde(default = "default_epoch")]
    pub epoch: u64,
    #[serde(default)]
    pub nonce: u64,
    #[serde(default)]
    pub valid_until: u64,
    #[serde(default)]
    pub fixed_q_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct G1PointMont {
    pub x: [String; 3],
    pub y: [String; 3],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct G2PointMont {
    pub x: [String; 6],
    pub y: [String; 6],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineCommitments {
    pub coeff_commitment: String,
    pub dbl_line_commitment: String,
    pub add_line_commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineCacheRelation {
    pub relation_root: String,
    pub q_hash: Option<String>,
    pub fixed_q_id: Option<String>,
    pub coeff_commitment: String,
    pub dbl_line_commitment: String,
    pub add_line_commitment: String,
    pub miller_rounds: u32,
    pub addition_steps_with_neg: u32,
    pub dbl_sparse_bytes: usize,
    pub add_sparse_bytes: usize,
    pub dbl_fq2_per_step: usize,
    pub add_fq2_per_step: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MillerRelation {
    pub relation_root: String,
    pub points_hash: String,
    pub line_cache_relation_root: String,
    pub miller_digest: String,
    pub singles_digest: String,
    pub pair_miller_digests: Vec<String>,
    pub pairs: u64,
    pub miller_rounds: u32,
    pub addition_steps_with_neg: u32,
    pub shared_accumulator: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeChunks {
    pub inv_out0: String,
    pub first_chunk_out0: String,
    pub w1_out0: String,
    pub w0_out0: String,
    pub final_out0: String,
    pub inv_digest: String,
    pub first_chunk_digest: String,
    pub first_chunk_inv_digest: String,
    pub w1_digest: String,
    pub w0_digest: String,
    pub final_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendTimings {
    pub input_normalization_ms: u64,
    pub line_cache_generation_ms: u64,
    pub miller_trace_generation_ms: u64,
    pub final_exponentiation_ms: u64,
    pub proof_input_generation_ms: u64,
    pub total_generation_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingArtifact {
    pub backend: String,
    pub mode: BackendMode,
    pub pairs: u64,
    pub context: String,
    pub epoch: u64,
    pub nonce: u64,
    pub valid_until: u64,
    pub fixed_q_id: Option<String>,
    pub q_hash: Option<String>,
    pub points_hash: String,
    pub line_commitments: LineCommitments,
    pub line_cache_relation: LineCacheRelation,
    pub miller_relation: MillerRelation,
    pub pairing_digest: String,
    pub miller_digest: String,
    pub singles_digest: String,
    pub pair_miller_digests: Vec<String>,
    pub trace_root: String,
    pub transition_root: String,
    pub miller_rounds: u32,
    pub addition_steps_with_neg: u32,
    pub final_exp_segments: u32,
    pub dbl_sparse_bytes: usize,
    pub add_sparse_bytes: usize,
    pub miller_out00: String,
    pub miller_out11: String,
    pub first_double_d0_c0: [String; 3],
    pub first_double_d0_c1: [String; 3],
    pub first_add_a0_c0: [String; 3],
    pub first_add_a0_c1: [String; 3],
    pub fe_chunks: FeChunks,
    pub generation_time_ms: u64,
    pub timings: BackendTimings,
}

fn default_mode() -> BackendMode {
    BackendMode::FixedQ
}
fn default_context_string() -> String {
    DEFAULT_CONTEXT_HEX.to_string()
}
fn default_epoch() -> u64 {
    1
}

pub fn build_default_fixed_q_artifact(
    context: &str,
    epoch: u64,
    nonce: u64,
) -> Result<PairingArtifact, String> {
    let request = TraceRequest {
        mode: BackendMode::FixedQ,
        points: vec![default_g1_mont()],
        q: None,
        context: context.to_string(),
        epoch,
        nonce,
        valid_until: 0,
        fixed_q_id: Some("arkworks-mnt4-753-g2-generator".to_string()),
    };
    build_artifact(&request)
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis().min(u64::MAX as u128) as u64
}

pub fn build_artifact(request: &TraceRequest) -> Result<PairingArtifact, String> {
    let started = Instant::now();
    let input_started = Instant::now();
    let points = if request.points.is_empty() {
        vec![default_g1_affine()]
    } else {
        request
            .points
            .iter()
            .map(g1_from_mont)
            .collect::<Result<Vec<_>, _>>()?
    };
    if points.is_empty() {
        return Err("at least one G1 point is required".to_string());
    }
    let q = match request.mode {
        BackendMode::FixedQ => default_g2_affine(),
        BackendMode::ParametricQ => request
            .q
            .as_ref()
            .map(g2_from_mont)
            .transpose()?
            .unwrap_or_else(default_g2_affine),
    };
    let input_normalization_ms = elapsed_ms(input_started);

    let line_started = Instant::now();
    let prepared = G2Prepared::from(q);
    let line_material = build_sparse_line_material(&prepared);
    let line_commitments = LineCommitments {
        dbl_line_commitment: hex32(&keccak(&line_material.dbl_blob)),
        add_line_commitment: hex32(&keccak(&line_material.add_blob)),
        coeff_commitment: hex32(&keccak(
            &[
                keccak(&line_material.dbl_blob),
                keccak(&line_material.add_blob),
            ]
            .concat(),
        )),
    };
    let q_hash = if request.mode == BackendMode::ParametricQ {
        Some(hex32(&hash_parametric_q(&q)))
    } else {
        None
    };
    let line_cache_relation = build_line_cache_relation(
        request,
        q_hash.clone(),
        &line_commitments,
        &line_material,
    )?;
    let line_cache_generation_ms = elapsed_ms(line_started);
    let points_hash = hex32(&hash_points(&points));

    let miller_started = Instant::now();
    let q_iter = std::iter::repeat(q).take(points.len());
    let miller_direct = MNT4_753::multi_miller_loop(points.iter().copied(), q_iter).0;
    let miller = miller_direct.inverse().expect("Miller value is non-zero");

    let mut singles = Fq4::ONE;
    let mut pair_miller_digests = Vec::with_capacity(points.len());
    for p in points.iter().copied() {
        let single_direct = MNT4_753::multi_miller_loop([p], [q]).0;
        let single_no_inv = single_direct
            .inverse()
            .expect("single Miller value is non-zero");
        pair_miller_digests.push(digest_fq4_mont(&single_no_inv));
        singles *= single_no_inv;
    }
    if request.mode == BackendMode::ParametricQ {
        // Solidity V3 canonical trace intentionally represents the shared-accumulator path;
        // the single-output digest is kept equal to the shared Miller digest for this mode.
        singles = miller;
    }
    let miller_trace_generation_ms = elapsed_ms(miller_started);

    let fe_started = Instant::now();
    let fe_chunks = compute_fe_chunks(&miller, true);
    let final_exponentiation_ms = elapsed_ms(fe_started);

    let proof_input_started = Instant::now();
    let pairing_digest = fe_chunks.final_digest.clone();
    let pairs = points.len() as u64;
    let miller_digest = digest_fq4_mont(&miller);
    let singles_digest = digest_fq4_mont(&singles);
    let miller_relation = build_miller_relation(
        &points_hash,
        &line_cache_relation,
        &miller_digest,
        &singles_digest,
        &pair_miller_digests,
        pairs,
    )?;
    let context = parse_bytes32(&request.context)?;
    let transition_root = keccak(&abi_encode_words(&[
        hex_to_word(&miller_digest)?,
        hex_to_word(&singles_digest)?,
        hex_to_word(&pairing_digest)?,
        context,
        uint64_word(request.epoch),
        uint64_word(pairs),
    ]));
    let trace_root = keccak(&abi_encode_words(&[
        hex_to_word(&pairing_digest)?,
        transition_root,
        context,
        uint64_word(request.epoch),
        uint64_word(pairs),
    ]));

    let miller_words = fq4_mont_words(&miller);
    let proof_input_generation_ms = elapsed_ms(proof_input_started);
    let total_generation_ms = elapsed_ms(started);
    let timings = BackendTimings {
        input_normalization_ms,
        line_cache_generation_ms,
        miller_trace_generation_ms,
        final_exponentiation_ms,
        proof_input_generation_ms,
        total_generation_ms,
    };

    Ok(PairingArtifact {
        backend: "arkworks-rust-mnt4-trace-backend-p1".to_string(),
        mode: request.mode,
        pairs,
        context: hex32(&context),
        epoch: request.epoch,
        nonce: request.nonce,
        valid_until: request.valid_until,
        fixed_q_id: request.fixed_q_id.clone(),
        q_hash,
        points_hash,
        line_commitments,
        line_cache_relation,
        miller_relation,
        pairing_digest,
        miller_digest,
        singles_digest,
        pair_miller_digests,
        trace_root: hex32(&trace_root),
        transition_root: hex32(&transition_root),
        miller_rounds: line_material.miller_rounds,
        addition_steps_with_neg: line_material.addition_steps_with_neg,
        final_exp_segments: FINAL_EXP_SEGMENTS,
        dbl_sparse_bytes: line_material.dbl_blob.len(),
        add_sparse_bytes: line_material.add_blob.len(),
        miller_out00: word_hex(&miller_words[0]),
        miller_out11: word_hex(&miller_words[9]),
        first_double_d0_c0: fq_limbs_hex(&fq2_mont(&line_material.first_double_d0).c0),
        first_double_d0_c1: fq_limbs_hex(&fq2_mont(&line_material.first_double_d0).c1),
        first_add_a0_c0: fq_limbs_hex(&fq2_mont(&line_material.first_add_a0).c0),
        first_add_a0_c1: fq_limbs_hex(&fq2_mont(&line_material.first_add_a0).c1),
        fe_chunks,
        generation_time_ms: timings.total_generation_ms,
        timings,
    })
}


pub fn validate_line_cache_relation(
    request: &TraceRequest,
    relation: &LineCacheRelation,
) -> Result<(), String> {
    let expected = build_artifact(request)?.line_cache_relation;
    compare_line_cache_field("relation_root", &relation.relation_root, &expected.relation_root)?;
    if relation.q_hash != expected.q_hash {
        return Err(format!(
            "q_hash mismatch: got {:?}, expected {:?}",
            relation.q_hash, expected.q_hash
        ));
    }
    if relation.fixed_q_id != expected.fixed_q_id {
        return Err(format!(
            "fixed_q_id mismatch: got {:?}, expected {:?}",
            relation.fixed_q_id, expected.fixed_q_id
        ));
    }
    compare_line_cache_field("coeff_commitment", &relation.coeff_commitment, &expected.coeff_commitment)?;
    compare_line_cache_field("dbl_line_commitment", &relation.dbl_line_commitment, &expected.dbl_line_commitment)?;
    compare_line_cache_field("add_line_commitment", &relation.add_line_commitment, &expected.add_line_commitment)?;
    if relation.miller_rounds != expected.miller_rounds {
        return Err(format!("miller_rounds mismatch: got {}, expected {}", relation.miller_rounds, expected.miller_rounds));
    }
    if relation.addition_steps_with_neg != expected.addition_steps_with_neg {
        return Err(format!("addition_steps_with_neg mismatch: got {}, expected {}", relation.addition_steps_with_neg, expected.addition_steps_with_neg));
    }
    if relation.dbl_sparse_bytes != expected.dbl_sparse_bytes {
        return Err(format!("dbl_sparse_bytes mismatch: got {}, expected {}", relation.dbl_sparse_bytes, expected.dbl_sparse_bytes));
    }
    if relation.add_sparse_bytes != expected.add_sparse_bytes {
        return Err(format!("add_sparse_bytes mismatch: got {}, expected {}", relation.add_sparse_bytes, expected.add_sparse_bytes));
    }
    Ok(())
}

fn compare_line_cache_field(name: &str, got: &str, expected: &str) -> Result<(), String> {
    if got == expected {
        Ok(())
    } else {
        Err(format!("{name} mismatch: got {got}, expected {expected}"))
    }
}

fn build_line_cache_relation(
    request: &TraceRequest,
    q_hash: Option<String>,
    commitments: &LineCommitments,
    material: &SparseLineMaterial,
) -> Result<LineCacheRelation, String> {
    let relation_root = line_cache_relation_root(request, q_hash.as_deref(), commitments, material)?;
    Ok(LineCacheRelation {
        relation_root: hex32(&relation_root),
        q_hash,
        fixed_q_id: request.fixed_q_id.clone(),
        coeff_commitment: commitments.coeff_commitment.clone(),
        dbl_line_commitment: commitments.dbl_line_commitment.clone(),
        add_line_commitment: commitments.add_line_commitment.clone(),
        miller_rounds: material.miller_rounds,
        addition_steps_with_neg: material.addition_steps_with_neg,
        dbl_sparse_bytes: material.dbl_blob.len(),
        add_sparse_bytes: material.add_blob.len(),
        dbl_fq2_per_step: DBL_SPARSE_FQ2_PER_STEP,
        add_fq2_per_step: ADD_SPARSE_FQ2_PER_STEP,
    })
}

fn line_cache_relation_root(
    request: &TraceRequest,
    q_hash: Option<&str>,
    commitments: &LineCommitments,
    material: &SparseLineMaterial,
) -> Result<[u8; 32], String> {
    let mut words = Vec::new();
    words.push(keccak(b"MNT4_LINE_CACHE_RELATION_V1"));
    words.push(match q_hash {
        Some(v) => parse_word(v)?,
        None => keccak(b"MNT4_FIXED_Q_IMPLICIT_GENERATOR"),
    });
    words.push(parse_word(&commitments.coeff_commitment)?);
    words.push(parse_word(&commitments.dbl_line_commitment)?);
    words.push(parse_word(&commitments.add_line_commitment)?);
    words.push(uint64_word(material.miller_rounds as u64));
    words.push(uint64_word(material.addition_steps_with_neg as u64));
    words.push(uint64_word(material.dbl_blob.len() as u64));
    words.push(uint64_word(material.add_blob.len() as u64));
    words.push(uint64_word(DBL_SPARSE_FQ2_PER_STEP as u64));
    words.push(uint64_word(ADD_SPARSE_FQ2_PER_STEP as u64));
    let fixed_q_hash = request
        .fixed_q_id
        .as_ref()
        .map(|s| keccak(s.as_bytes()))
        .unwrap_or_else(|| keccak(b"MNT4_NO_FIXED_Q_ID"));
    words.push(fixed_q_hash);
    Ok(keccak(&abi_encode_words(&words)))
}


pub fn validate_miller_relation(
    request: &TraceRequest,
    relation: &MillerRelation,
) -> Result<(), String> {
    let expected = build_artifact(request)?.miller_relation;
    compare_line_cache_field("relation_root", &relation.relation_root, &expected.relation_root)?;
    compare_line_cache_field("points_hash", &relation.points_hash, &expected.points_hash)?;
    compare_line_cache_field(
        "line_cache_relation_root",
        &relation.line_cache_relation_root,
        &expected.line_cache_relation_root,
    )?;
    compare_line_cache_field("miller_digest", &relation.miller_digest, &expected.miller_digest)?;
    compare_line_cache_field("singles_digest", &relation.singles_digest, &expected.singles_digest)?;
    if relation.pair_miller_digests != expected.pair_miller_digests {
        return Err("pair_miller_digests mismatch".to_string());
    }
    if relation.pairs != expected.pairs {
        return Err(format!("pairs mismatch: got {}, expected {}", relation.pairs, expected.pairs));
    }
    if relation.miller_rounds != expected.miller_rounds {
        return Err(format!("miller_rounds mismatch: got {}, expected {}", relation.miller_rounds, expected.miller_rounds));
    }
    if relation.addition_steps_with_neg != expected.addition_steps_with_neg {
        return Err(format!("addition_steps_with_neg mismatch: got {}, expected {}", relation.addition_steps_with_neg, expected.addition_steps_with_neg));
    }
    if relation.shared_accumulator != expected.shared_accumulator {
        return Err(format!("shared_accumulator mismatch: got {}, expected {}", relation.shared_accumulator, expected.shared_accumulator));
    }
    Ok(())
}

fn build_miller_relation(
    points_hash: &str,
    line_cache_relation: &LineCacheRelation,
    miller_digest: &str,
    singles_digest: &str,
    pair_miller_digests: &[String],
    pairs: u64,
) -> Result<MillerRelation, String> {
    let relation_root = miller_relation_root(
        points_hash,
        line_cache_relation,
        miller_digest,
        singles_digest,
        pair_miller_digests,
        pairs,
    )?;
    Ok(MillerRelation {
        relation_root: hex32(&relation_root),
        points_hash: points_hash.to_string(),
        line_cache_relation_root: line_cache_relation.relation_root.clone(),
        miller_digest: miller_digest.to_string(),
        singles_digest: singles_digest.to_string(),
        pair_miller_digests: pair_miller_digests.to_vec(),
        pairs,
        miller_rounds: line_cache_relation.miller_rounds,
        addition_steps_with_neg: line_cache_relation.addition_steps_with_neg,
        shared_accumulator: true,
    })
}

fn miller_relation_root(
    points_hash: &str,
    line_cache_relation: &LineCacheRelation,
    miller_digest: &str,
    singles_digest: &str,
    pair_miller_digests: &[String],
    pairs: u64,
) -> Result<[u8; 32], String> {
    let mut words = Vec::with_capacity(10 + pair_miller_digests.len());
    words.push(keccak(b"MNT4_MILLER_RELATION_V1"));
    words.push(parse_word(points_hash)?);
    words.push(parse_word(&line_cache_relation.relation_root)?);
    words.push(parse_word(miller_digest)?);
    words.push(parse_word(singles_digest)?);
    words.push(uint64_word(pairs));
    words.push(uint64_word(line_cache_relation.miller_rounds as u64));
    words.push(uint64_word(line_cache_relation.addition_steps_with_neg as u64));
    words.push(uint64_word(1));
    for digest in pair_miller_digests {
        words.push(parse_word(digest)?);
    }
    Ok(keccak(&abi_encode_words(&words)))
}

pub fn write_artifacts(out_dir: &Path, artifact: &PairingArtifact) -> Result<(), String> {
    fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    write_json(out_dir.join("trace.json"), artifact)?;
    write_json(
        out_dir.join("witness.json"),
        &serde_json::json!({
            "millerOut00": artifact.miller_out00,
            "millerOut11": artifact.miller_out11,
            "pairMillerDigests": artifact.pair_miller_digests,
            "feChunks": artifact.fe_chunks,
            "lineCommitments": artifact.line_commitments,
            "lineCacheRelation": artifact.line_cache_relation,
            "millerRelation": artifact.miller_relation,
            "timings": artifact.timings,
        }),
    )?;
    write_json(
        out_dir.join("public_inputs.json"),
        &serde_json::json!({
            "mode": artifact.mode,
            "pairs": artifact.pairs,
            "context": artifact.context,
            "epoch": artifact.epoch,
            "nonce": artifact.nonce,
            "validUntil": artifact.valid_until,
            "fixedQId": artifact.fixed_q_id,
            "qHash": artifact.q_hash,
            "pointsHash": artifact.points_hash,
            "coeffCommitment": artifact.line_commitments.coeff_commitment,
            "lineCacheRelationRoot": artifact.line_cache_relation.relation_root,
            "millerRelationRoot": artifact.miller_relation.relation_root,
            "pairingDigest": artifact.pairing_digest,
            "millerDigest": artifact.miller_digest,
            "singlesDigest": artifact.singles_digest,
            "pairMillerDigests": artifact.pair_miller_digests,
            "traceRoot": artifact.trace_root,
            "transitionRoot": artifact.transition_root,
            "millerRounds": artifact.miller_rounds,
            "finalExpSegments": artifact.final_exp_segments,
            "timings": artifact.timings,
        }),
    )?;
    write_json(
        out_dir.join("proof_input.json"),
        &serde_json::json!({
            "public": {
                "traceRoot": artifact.trace_root,
                "transitionRoot": artifact.transition_root,
                "pairingDigest": artifact.pairing_digest,
                "millerDigest": artifact.miller_digest,
                "singlesDigest": artifact.singles_digest,
                "pairMillerDigests": artifact.pair_miller_digests,
                "coeffCommitment": artifact.line_commitments.coeff_commitment,
                "lineCacheRelationRoot": artifact.line_cache_relation.relation_root,
                "millerRelationRoot": artifact.miller_relation.relation_root,
                "qHash": artifact.q_hash,
                "pointsHash": artifact.points_hash,
            },
            "privateWitness": {
                "millerOut00": artifact.miller_out00,
                "millerOut11": artifact.miller_out11,
                "pairMillerDigests": artifact.pair_miller_digests,
                "lineCommitments": artifact.line_commitments,
                "lineCacheRelation": artifact.line_cache_relation,
                "millerRelation": artifact.miller_relation,
                "feChunks": artifact.fe_chunks,
                "timings": artifact.timings,
            },
            "note": "Rust backend output consumed directly by the final prepared-residue proof generator."
        }),
    )?;
    Ok(())
}

fn write_json<P: AsRef<Path>, T: Serialize>(path: P, value: &T) -> Result<(), String> {
    let data = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    fs::write(path, data).map_err(|e| e.to_string())
}

struct SparseLineMaterial {
    dbl_blob: Vec<u8>,
    add_blob: Vec<u8>,
    miller_rounds: u32,
    addition_steps_with_neg: u32,
    first_double_d0: Fq2,
    first_add_a0: Fq2,
}

fn build_sparse_line_material(prepared: &G2Prepared) -> SparseLineMaterial {
    let mut dbl_blob = Vec::with_capacity(
        prepared.double_coefficients.len() * DBL_SPARSE_FQ2_PER_STEP * FQ2_BYTES,
    );
    let mut add_blob = Vec::with_capacity(
        prepared.addition_coefficients.len() * ADD_SPARSE_FQ2_PER_STEP * FQ2_BYTES,
    );
    let first_dc = &prepared.double_coefficients[0];
    let first_double_d0 = first_dc.c_l - first_dc.c_4c;
    for dc in &prepared.double_coefficients {
        pack_fq2_mont(&mut dbl_blob, &(dc.c_l - dc.c_4c));
        pack_fq2_mont(&mut dbl_blob, &dc.c_j);
        pack_fq2_mont(&mut dbl_blob, &dc.c_h);
    }
    let first_add_a0 = prepared.addition_coefficients[0].c_rz;
    for ac in &prepared.addition_coefficients {
        pack_fq2_mont(&mut add_blob, &ac.c_rz);
        pack_fq2_mont(&mut add_blob, &ac.c_l1);
    }
    SparseLineMaterial {
        dbl_blob,
        add_blob,
        miller_rounds: prepared.double_coefficients.len() as u32,
        addition_steps_with_neg: prepared.addition_coefficients.len() as u32,
        first_double_d0,
        first_add_a0,
    }
}

fn compute_fe_chunks(miller_value: &Fq4, miller_needs_inverse: bool) -> FeChunks {
    let inv = miller_value.inverse().expect("Miller value is non-zero");
    let mut first_base = *miller_value;
    first_base.cyclotomic_inverse_in_place().expect("non-zero");
    let mut first = first_base * inv;
    if miller_needs_inverse {
        first = fq4_conjugate(&first);
    }
    let first_inv = fq4_conjugate(&first);
    let mut w1 = first;
    w1.frobenius_map_in_place(1);
    let w0 = first_inv.cyclotomic_exp(Config::FINAL_EXPONENT_LAST_CHUNK_ABS_OF_W0);
    let last = w1 * w0;
    let inv_words = fq4_mont_words(&inv);
    let first_words = fq4_mont_words(&first);
    let w1_words = fq4_mont_words(&w1);
    let w0_words = fq4_mont_words(&w0);
    let last_words = fq4_mont_words(&last);
    FeChunks {
        inv_out0: word_hex(&inv_words[0]),
        first_chunk_out0: word_hex(&first_words[0]),
        w1_out0: word_hex(&w1_words[0]),
        w0_out0: word_hex(&w0_words[0]),
        final_out0: word_hex(&last_words[0]),
        inv_digest: digest_fq4_mont(&inv),
        first_chunk_digest: digest_fq4_mont(&first),
        first_chunk_inv_digest: digest_fq4_mont(&first_inv),
        w1_digest: digest_fq4_mont(&w1),
        w0_digest: digest_fq4_mont(&w0),
        final_digest: digest_fq4_mont(&last),
    }
}

fn fq4_conjugate(x: &Fq4) -> Fq4 {
    Fq4::new(x.c0, -x.c1)
}

fn default_g1_affine() -> G1Affine {
    G1Projective::generator().into_affine()
}
fn default_g2_affine() -> G2Affine {
    G2Projective::generator().into_affine()
}

fn default_g1_mont() -> G1PointMont {
    let p = default_g1_affine();
    G1PointMont {
        x: fq_limbs_hex(&montgomery_fq(&p.x)),
        y: fq_limbs_hex(&montgomery_fq(&p.y)),
    }
}

fn g1_from_mont(p: &G1PointMont) -> Result<G1Affine, String> {
    Ok(G1Affine::new_unchecked(
        from_montgomery_fq(&fq_from_u256_limbs_hex(&p.x)?),
        from_montgomery_fq(&fq_from_u256_limbs_hex(&p.y)?),
    ))
}

fn g2_from_mont(q: &G2PointMont) -> Result<G2Affine, String> {
    Ok(G2Affine::new_unchecked(
        Fq2::new(
            from_montgomery_fq(&fq_from_u256_limbs_hex_6(&q.x, 0)?),
            from_montgomery_fq(&fq_from_u256_limbs_hex_6(&q.x, 3)?),
        ),
        Fq2::new(
            from_montgomery_fq(&fq_from_u256_limbs_hex_6(&q.y, 0)?),
            from_montgomery_fq(&fq_from_u256_limbs_hex_6(&q.y, 3)?),
        ),
    ))
}

fn fq_from_u256_limbs_hex_6(words: &[String; 6], offset: usize) -> Result<Fq, String> {
    fq_from_u256_limbs_hex(&[
        words[offset].clone(),
        words[offset + 1].clone(),
        words[offset + 2].clone(),
    ])
}

fn fq_from_u256_limbs_hex(limbs: &[String; 3]) -> Result<Fq, String> {
    let mut bytes = [0u8; 96];
    for (limb_idx, limb_hex) in limbs.iter().enumerate() {
        let word = parse_word(limb_hex)?;
        for i in 0..32 {
            bytes[limb_idx * 32 + i] = word[31 - i];
        }
    }
    Ok(Fq::from_le_bytes_mod_order(&bytes))
}

fn montgomery_fq(x: &Fq) -> Fq {
    let r = Fq::from(2u64).pow([768u64]);
    *x * r
}

fn from_montgomery_fq(x: &Fq) -> Fq {
    let r_inv = Fq::from(2u64).pow([768u64]).inverse().expect("R != 0");
    *x * r_inv
}

fn fq2_mont(x: &Fq2) -> Fq2 {
    Fq2::new(montgomery_fq(&x.c0), montgomery_fq(&x.c1))
}
fn fq4_mont(x: &Fq4) -> Fq4 {
    Fq4::new(fq2_mont(&x.c0), fq2_mont(&x.c1))
}

fn pack_fq2_mont(out: &mut Vec<u8>, x: &Fq2) {
    let x = fq2_mont(x);
    for w in fq_limbs_be32(&x.c0) {
        out.extend_from_slice(&w);
    }
    for w in fq_limbs_be32(&x.c1) {
        out.extend_from_slice(&w);
    }
}

fn fq4_mont_words(x: &Fq4) -> Vec<[u8; 32]> {
    let x = fq4_mont(x);
    let mut out = Vec::with_capacity(12);
    out.extend(fq_limbs_be32(&x.c0.c0));
    out.extend(fq_limbs_be32(&x.c0.c1));
    out.extend(fq_limbs_be32(&x.c1.c0));
    out.extend(fq_limbs_be32(&x.c1.c1));
    out
}

fn digest_fq4_mont(x: &Fq4) -> String {
    let mut bytes = Vec::with_capacity(384);
    for w in fq4_mont_words(x) {
        bytes.extend_from_slice(&w);
    }
    hex32(&keccak(&bytes))
}

fn fq_limbs_hex(x: &Fq) -> [String; 3] {
    let limbs = fq_limbs_be32(x);
    [
        word_hex(&limbs[0]),
        word_hex(&limbs[1]),
        word_hex(&limbs[2]),
    ]
}

fn fq_limbs_be32(x: &Fq) -> [[u8; 32]; 3] {
    let mut le = x.into_bigint().to_bytes_le();
    le.resize(96, 0u8);
    let mut out = [[0u8; 32]; 3];
    for limb in 0..3 {
        for i in 0..32 {
            out[limb][i] = le[limb * 32 + 31 - i];
        }
    }
    out
}

fn hash_points(points: &[G1Affine]) -> [u8; 32] {
    let mut acc = keccak(b"MNT4_R8_POINTS_V3_PARAMQ");
    for p in points {
        let pm = G1PointMont {
            x: fq_limbs_hex(&montgomery_fq(&p.x)),
            y: fq_limbs_hex(&montgomery_fq(&p.y)),
        };
        let mut data = Vec::with_capacity(32 + 6 * 32);
        data.extend_from_slice(&acc);
        for w in pm.x.iter().chain(pm.y.iter()) {
            data.extend_from_slice(&parse_word(w).expect("generated word is valid"));
        }
        acc = keccak(&data);
    }
    acc
}

fn hash_parametric_q(q: &G2Affine) -> [u8; 32] {
    let mut data = Vec::with_capacity(32 + 12 * 32);
    data.extend_from_slice(&keccak(PARAMETRIC_Q_DOMAIN.as_bytes()));
    let qm = G2PointMont {
        x: {
            let x0 = fq_limbs_hex(&montgomery_fq(&q.x.c0));
            let x1 = fq_limbs_hex(&montgomery_fq(&q.x.c1));
            [
                x0[0].clone(),
                x0[1].clone(),
                x0[2].clone(),
                x1[0].clone(),
                x1[1].clone(),
                x1[2].clone(),
            ]
        },
        y: {
            let y0 = fq_limbs_hex(&montgomery_fq(&q.y.c0));
            let y1 = fq_limbs_hex(&montgomery_fq(&q.y.c1));
            [
                y0[0].clone(),
                y0[1].clone(),
                y0[2].clone(),
                y1[0].clone(),
                y1[1].clone(),
                y1[2].clone(),
            ]
        },
    };
    for w in qm.x.iter().chain(qm.y.iter()) {
        data.extend_from_slice(&parse_word(w).expect("generated word is valid"));
    }
    keccak(&data)
}

fn abi_encode_words(words: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 32);
    for word in words {
        out.extend_from_slice(word);
    }
    out
}

fn uint64_word(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&v.to_be_bytes());
    out
}

fn parse_bytes32(s: &str) -> Result<[u8; 32], String> {
    parse_word(s)
}

fn hex_to_word(s: &str) -> Result<[u8; 32], String> {
    parse_word(s)
}

fn parse_word(s: &str) -> Result<[u8; 32], String> {
    let clean = s.strip_prefix("0x").unwrap_or(s);
    if clean.len() > 64 {
        return Err(format!("hex word too long: {s}"));
    }
    let mut padded = String::with_capacity(64);
    for _ in 0..(64 - clean.len()) {
        padded.push('0');
    }
    padded.push_str(clean);
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&padded[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn word_hex(word: &[u8; 32]) -> String {
    let mut s = String::from("0x");
    for b in word {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex32(word: &[u8; 32]) -> String {
    word_hex(word)
}

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_coeff_counts_match_solidity_layout() {
        let mat = build_sparse_line_material(&G2Prepared::from(default_g2_affine()));
        assert_eq!(mat.miller_rounds, 376);
        assert_eq!(mat.addition_steps_with_neg, 124);
        assert_eq!(mat.dbl_blob.len(), 216_576);
        assert_eq!(mat.add_blob.len(), 47_616);
    }
}
