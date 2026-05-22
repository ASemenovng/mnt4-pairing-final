use mnt4_trace_backend::{
    build_artifact, build_default_fixed_q_artifact, write_artifacts, BackendMode, TraceRequest,
    DEFAULT_CONTEXT_HEX,
};

#[test]
fn default_fixed_q_matches_canonical_solidity_fixtures() {
    let artifact = build_default_fixed_q_artifact(DEFAULT_CONTEXT_HEX, 1, 1).unwrap();
    assert_eq!(artifact.miller_rounds, 376);
    assert_eq!(artifact.addition_steps_with_neg, 124);
    assert_eq!(artifact.dbl_sparse_bytes, 216_576);
    assert_eq!(artifact.add_sparse_bytes, 47_616);
    assert_eq!(
        artifact.pairing_digest,
        "0x792f0eb69a2d7c2b4fabd0fcca4e0a74b47e4c40dfe58f83ec8ef1615f1c832d"
    );
    assert_eq!(
        artifact.miller_digest,
        "0xb5bfca0deaab5483050fa32bb2a3f15f51a2ca8dcf3f4aabd2c6e35261f5a934"
    );
    assert_eq!(artifact.pair_miller_digests.len(), 1);
    assert_eq!(artifact.pair_miller_digests[0], artifact.miller_digest);
    assert_eq!(
        artifact.line_commitments.coeff_commitment,
        "0xdc70fe833c6bd71c7b8144166e9b94c3393a4d37a52b1497fc3e34180a3cd843"
    );
    assert_eq!(
        artifact.line_commitments.dbl_line_commitment,
        "0x288ded9d5a49d4a5fce95a3c0d240d128c6e1470a9bb99b8e2fa8390596e4b4c"
    );
    assert_eq!(
        artifact.line_commitments.add_line_commitment,
        "0xa06c68cea868049c9559bdaedc1b40a090f6161c1a47190b024aa199d6b6d71d"
    );
    assert_eq!(
        artifact.first_double_d0_c0[0],
        "0x963c2d749c4e4610f0dba4449dde0a8efefa3d4acf4613917c9f0c78d349c7b5"
    );
    assert_eq!(
        artifact.first_add_a0_c0[0],
        "0xdf17da89adf4c972e3d709eee18d45d85f2c26975bb6438acfee0434e7576eee"
    );
}

#[test]
fn default_parametric_q_uses_same_cache_but_binds_q_hash() {
    let request = TraceRequest {
        mode: BackendMode::ParametricQ,
        points: vec![],
        q: None,
        context: DEFAULT_CONTEXT_HEX.to_string(),
        epoch: 1,
        nonce: 7,
        valid_until: 100,
        fixed_q_id: None,
    };
    let artifact = build_artifact(&request).unwrap();
    assert_eq!(
        artifact.q_hash.as_deref(),
        Some("0x6b2368d6280cd7d2aff79fdd38c011f62151009f1c0266c453a4da2bd5b3bda7")
    );
    assert_eq!(
        artifact.line_commitments.coeff_commitment,
        "0xdc70fe833c6bd71c7b8144166e9b94c3393a4d37a52b1497fc3e34180a3cd843"
    );
    assert_eq!(
        artifact.pairing_digest,
        "0x792f0eb69a2d7c2b4fabd0fcca4e0a74b47e4c40dfe58f83ec8ef1615f1c832d"
    );
}

#[test]
fn artifact_reports_stage_timings_for_benchmark_suite() {
    let artifact = build_default_fixed_q_artifact(DEFAULT_CONTEXT_HEX, 1, 0).unwrap();
    assert_eq!(
        artifact.generation_time_ms,
        artifact.timings.total_generation_ms
    );
    assert!(
        artifact.timings.total_generation_ms >= artifact.timings.input_normalization_ms
    );
    assert!(
        artifact.timings.total_generation_ms >= artifact.timings.line_cache_generation_ms
    );
    assert!(
        artifact.timings.total_generation_ms >= artifact.timings.miller_trace_generation_ms
    );
    assert!(
        artifact.timings.total_generation_ms >= artifact.timings.final_exponentiation_ms
    );
    assert!(
        artifact.timings.total_generation_ms >= artifact.timings.proof_input_generation_ms
    );
}

#[test]
fn writer_emits_all_stage6_json_artifacts() {
    let artifact = build_default_fixed_q_artifact(DEFAULT_CONTEXT_HEX, 1, 0).unwrap();
    let mut out = std::env::temp_dir();
    out.push(format!("mnt4_trace_backend_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    write_artifacts(&out, &artifact).unwrap();
    for name in [
        "trace.json",
        "witness.json",
        "public_inputs.json",
        "proof_input.json",
    ] {
        let p = out.join(name);
        assert!(p.exists(), "missing {}", p.display());
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(body.contains("0x792f0eb69a2d7c2b4fabd0fcca4e0a74b47e4c40dfe58f83ec8ef1615f1c832d"));
    }
    let proof_input = std::fs::read_to_string(out.join("proof_input.json")).unwrap();
    assert!(proof_input.contains("lineCacheRelationRoot"));
}

#[test]
fn line_cache_relation_binds_q_to_commitments() {
    let request = TraceRequest {
        mode: BackendMode::ParametricQ,
        points: vec![],
        q: None,
        context: DEFAULT_CONTEXT_HEX.to_string(),
        epoch: 1,
        nonce: 11,
        valid_until: 0,
        fixed_q_id: None,
    };
    let artifact = build_artifact(&request).unwrap();
    let relation = artifact.line_cache_relation.clone();
    assert_eq!(relation.q_hash.as_deref(), artifact.q_hash.as_deref());
    assert_eq!(relation.coeff_commitment, artifact.line_commitments.coeff_commitment);
    assert_eq!(relation.dbl_line_commitment, artifact.line_commitments.dbl_line_commitment);
    assert_eq!(relation.add_line_commitment, artifact.line_commitments.add_line_commitment);
    assert_eq!(relation.miller_rounds, artifact.miller_rounds);
    assert_eq!(relation.addition_steps_with_neg, artifact.addition_steps_with_neg);
    mnt4_trace_backend::validate_line_cache_relation(&request, &relation).unwrap();
}

#[test]
fn line_cache_relation_rejects_tampered_commitment() {
    let request = TraceRequest {
        mode: BackendMode::ParametricQ,
        points: vec![],
        q: None,
        context: DEFAULT_CONTEXT_HEX.to_string(),
        epoch: 1,
        nonce: 12,
        valid_until: 0,
        fixed_q_id: None,
    };
    let artifact = build_artifact(&request).unwrap();
    let mut relation = artifact.line_cache_relation.clone();
    relation.dbl_line_commitment = "0x0000000000000000000000000000000000000000000000000000000000000001".to_string();
    let err = mnt4_trace_backend::validate_line_cache_relation(&request, &relation).unwrap_err();
    assert!(err.contains("dbl_line_commitment"));
}

#[test]
fn miller_relation_binds_points_line_cache_and_accumulator() {
    let request = TraceRequest {
        mode: BackendMode::ParametricQ,
        points: vec![],
        q: None,
        context: DEFAULT_CONTEXT_HEX.to_string(),
        epoch: 2,
        nonce: 21,
        valid_until: 0,
        fixed_q_id: None,
    };
    let artifact = build_artifact(&request).unwrap();
    let relation = artifact.miller_relation.clone();
    assert_eq!(relation.points_hash, artifact.points_hash);
    assert_eq!(relation.line_cache_relation_root, artifact.line_cache_relation.relation_root);
    assert_eq!(relation.miller_digest, artifact.miller_digest);
    assert_eq!(relation.singles_digest, artifact.singles_digest);
    assert_eq!(relation.pair_miller_digests, artifact.pair_miller_digests);
    assert_eq!(relation.pairs, artifact.pairs);
    assert_eq!(relation.miller_rounds, artifact.miller_rounds);
    assert_eq!(relation.addition_steps_with_neg, artifact.addition_steps_with_neg);
    mnt4_trace_backend::validate_miller_relation(&request, &relation).unwrap();
}

#[test]
fn miller_relation_rejects_tampered_miller_digest() {
    let request = TraceRequest {
        mode: BackendMode::ParametricQ,
        points: vec![],
        q: None,
        context: DEFAULT_CONTEXT_HEX.to_string(),
        epoch: 2,
        nonce: 22,
        valid_until: 0,
        fixed_q_id: None,
    };
    let artifact = build_artifact(&request).unwrap();
    let mut relation = artifact.miller_relation.clone();
    relation.miller_digest = "0x0000000000000000000000000000000000000000000000000000000000000002".to_string();
    let err = mnt4_trace_backend::validate_miller_relation(&request, &relation).unwrap_err();
    assert!(err.contains("miller_digest"));
}

#[test]
fn miller_relation_rejects_tampered_line_cache_root() {
    let request = TraceRequest {
        mode: BackendMode::ParametricQ,
        points: vec![],
        q: None,
        context: DEFAULT_CONTEXT_HEX.to_string(),
        epoch: 2,
        nonce: 23,
        valid_until: 0,
        fixed_q_id: None,
    };
    let artifact = build_artifact(&request).unwrap();
    let mut relation = artifact.miller_relation.clone();
    relation.line_cache_relation_root = "0x0000000000000000000000000000000000000000000000000000000000000003".to_string();
    let err = mnt4_trace_backend::validate_miller_relation(&request, &relation).unwrap_err();
    assert!(err.contains("line_cache_relation_root"));
}
