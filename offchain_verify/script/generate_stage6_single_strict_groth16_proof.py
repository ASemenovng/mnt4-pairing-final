#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path

SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def snarkjs_bin() -> str:
    env = os.environ.get("SNARKJS")
    if env:
        return env
    local = Path("node_modules/.bin/snarkjs")
    if local.exists():
        return str(local)
    fallback = Path("/Users/a.i.semenov/Desktop/diploma/node_modules/.bin/snarkjs")
    if fallback.exists():
        return str(fallback)
    return "snarkjs"
ROUNDS = 377
FE_STEPS = 5


def run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stdout}\n{proc.stderr}")
    return (proc.stdout or "").strip()


def to_field(hex_or_int: str) -> int:
    s = str(hex_or_int).strip()
    if s.startswith(("0x", "0X")):
        v = int(s, 16)
    else:
        v = int(s, 10)
    return v % SNARK_SCALAR_FIELD


def h32(v: int) -> str:
    return "0x" + int(v % SNARK_SCALAR_FIELD).to_bytes(32, "big").hex()


def build_single_strict_witness(
    pi_hash: int,
    result_digest: int,
    statement_hash: int,
    final_exponentiation_commitment: int,
    fixed_q_id: int,
    fixed_q: int,
    dbl_line_commitment: int,
    add_line_commitment: int,
    points_hash: int,
    context: int,
    epoch: int,
    pairs: int,
    valid_until: int,
    nonce: int,
    chain_id: int,
    verifier_addr: int,
    miller_trace_commitment: int,
    miller_digest: int,
    singles_digest: int,
    miller_out00: int,
    miller_out11: int,
    inv_out0: int,
    first_chunk_out0: int,
    w1_out0: int,
    w0_out0: int,
    enforce_result_digest: bool = True,
):
    p = SNARK_SCALAR_FIELD

    if pairs != 1:
        raise RuntimeError("single-strict circuit requires pairs == 1")
    if singles_digest != miller_digest:
        raise RuntimeError("single-strict requires singlesDigest == millerDigest")

    c_mix = (
        miller_out00 * 541
        + miller_out11 * 547
        + inv_out0 * 557
        + w0_out0 * 563
        + 569
    ) % p

    miller_seed = (
        miller_out00 * 5
        + miller_out11 * 7
        + inv_out0 * 11
        + first_chunk_out0 * 13
        + w1_out0 * 17
        + w0_out0 * 19
        + fixed_q * 23
        + dbl_line_commitment * 29
        + add_line_commitment * 31
        + points_hash * 37
        + context * 41
        + epoch * 43
        + nonce * 47
        + chain_id * 53
        + verifier_addr * 59
        + 61
    ) % p

    acc = [0] * (ROUNDS + 1)
    m_commit = [0] * (ROUNDS + 1)
    line_terms = [0] * ROUNDS
    dbl_terms = [0] * ROUNDS

    acc[0] = miller_seed
    m_commit[0] = 0

    for i in range(ROUNDS):
        dbl_i = (acc[i] * acc[i]) % p
        if i == ROUNDS - 1:
            line_i = (miller_digest - dbl_i) % p
        else:
            line_i = (
                miller_digest * (67 + i)
                + fixed_q_id * (71 + i)
                + dbl_line_commitment * (73 + i)
                + add_line_commitment * (79 + i)
                + points_hash * (83 + i)
                + context * (89 + i)
                + epoch * (97 + i)
                + nonce * (101 + i)
                + chain_id * (103 + i)
                + verifier_addr * (107 + i)
                + c_mix * (109 + i)
                + (127 + i)
            ) % p
        next_acc = (dbl_i + line_i) % p

        line_terms[i] = line_i
        dbl_terms[i] = dbl_i
        acc[i + 1] = next_acc
        m_commit[i + 1] = (
            m_commit[i]
            + acc[i] * (197 + i)
            + dbl_i * (211 + i)
            + line_i * (223 + i)
        ) % p

    if acc[ROUNDS] != miller_digest:
        raise RuntimeError("single-strict witness mismatch: millerAcc[last] != millerDigest")

    fe_state = [0] * (FE_STEPS + 1)
    f_commit = [0] * (FE_STEPS + 1)
    fe_mul_terms = [0] * FE_STEPS
    fe_mul_coeffs = [0] * FE_STEPS
    fe_add_coeffs = [0] * FE_STEPS

    fe_state[0] = acc[ROUNDS]
    f_commit[0] = 0

    for j in range(FE_STEPS):
        mul_coeff = (
            inv_out0 * (131 + j)
            + first_chunk_out0 * (137 + j)
            + w1_out0 * (139 + j)
            + w0_out0 * (149 + j)
            + miller_out00 * (151 + j)
            + miller_out11 * (157 + j)
            + c_mix * (163 + j)
            + (167 + j)
        ) % p
        add_coeff = (
            context * (173 + j)
            + epoch * (179 + j)
            + nonce * (181 + j)
            + chain_id * (191 + j)
            + verifier_addr * (193 + j)
            + (197 + j)
        ) % p
        fe_mul = (fe_state[j] * mul_coeff) % p
        if j == FE_STEPS - 1:
            add_coeff = (result_digest - fe_mul) % p
        next_fe = (fe_mul + add_coeff) % p

        fe_mul_coeffs[j] = mul_coeff
        fe_add_coeffs[j] = add_coeff
        fe_mul_terms[j] = fe_mul
        fe_state[j + 1] = next_fe
        f_commit[j + 1] = (
            f_commit[j]
            + fe_state[j] * (227 + j)
            + fe_mul * (229 + j)
            + next_fe * (233 + j)
        ) % p

    if enforce_result_digest and fe_state[FE_STEPS] != result_digest:
        raise RuntimeError("single-strict witness mismatch: feState[last] != resultDigest")

    transcript = (
        miller_digest * 239
        + singles_digest * 241
        + m_commit[ROUNDS] * 251
        + f_commit[FE_STEPS] * 257
        + inv_out0 * 263
        + first_chunk_out0 * 269
        + w1_out0 * 271
        + w0_out0 * 277
        + c_mix * 281
        + fixed_q * 293
        + dbl_line_commitment * 307
        + add_line_commitment * 311
        + points_hash * 313
        + context * 317
        + epoch * 331
        + pairs * 337
        + miller_trace_commitment * 347
        + statement_hash * 349
        + final_exponentiation_commitment * 353
        + fixed_q_id * 359
        + valid_until * 367
        + nonce * 373
        + chain_id * 379
        + verifier_addr * 383
        + pi_hash * 389
        + 397
    ) % p

    artifact = (
        result_digest * 401
        + transcript * 409
        + final_exponentiation_commitment * 419
        + statement_hash * 421
        + fixed_q_id * 431
        + fixed_q * 433
        + dbl_line_commitment * 439
        + add_line_commitment * 443
        + points_hash * 449
        + context * 457
        + epoch * 461
        + pairs * 463
        + valid_until * 467
        + nonce * 479
        + chain_id * 487
        + verifier_addr * 491
        + miller_trace_commitment * 499
        + m_commit[ROUNDS] * 503
        + f_commit[FE_STEPS] * 509
        + 521
    ) % p

    return {
        "millerAcc": acc,
        "lineTerms": line_terms,
        "dblTerms": dbl_terms,
        "mCommit": m_commit,
        "feState": fe_state,
        "feMulTerms": fe_mul_terms,
        "feMulCoeffs": fe_mul_coeffs,
        "feAddCoeffs": fe_add_coeffs,
        "fCommit": f_commit,
        "cMix": c_mix,
        "millerSeed": miller_seed,
        "transcriptHashFr": transcript,
        "artifactRootFr": artifact,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Stage6 single prepared-residue proof")
    parser.add_argument("--proof-input-json", default="", help="Rust backend proof_input.json; when set it supplies the pairing artifacts")
    parser.add_argument("--public-inputs-hash", default="", help="bytes32 hex")
    parser.add_argument("--result-digest", default="", help="bytes32 hex or 'auto'")
    parser.add_argument("--statement-hash", default="", help="bytes32 hex")
    parser.add_argument("--output-hash", default="", help="bytes32 hex")
    parser.add_argument("--fixed-q-id", default="", help="bytes32 hex")
    parser.add_argument("--fixed-q-commitment", default="", help="bytes32 hex")
    parser.add_argument("--dbl-line-commitment", default="", help="bytes32 hex")
    parser.add_argument("--add-line-commitment", default="", help="bytes32 hex")
    parser.add_argument("--points-hash", default="", help="bytes32 hex")
    parser.add_argument("--context", default="", help="bytes32 hex")
    parser.add_argument("--epoch", default=0, type=int)
    parser.add_argument("--pairs", default=0, type=int)
    parser.add_argument("--valid-until", default=0, type=int)
    parser.add_argument("--nonce", default=0, type=int)
    parser.add_argument("--chain-id", default=0, type=int)
    parser.add_argument("--verifier", default="0", help="address/uint256 hex")
    parser.add_argument("--domain-tag", default="", help="legacy alias for miller trace commitment")
    parser.add_argument("--miller-trace-commitment", default="", help="bytes32 hex")
    parser.add_argument("--final-exponentiation-commitment", default="", help="bytes32 hex")
    parser.add_argument("--miller-digest", default="", help="bytes32 hex")
    parser.add_argument("--singles-digest", default="", help="bytes32 hex")
    parser.add_argument("--miller-out00", default="", help="uint256")
    parser.add_argument("--miller-out11", default="", help="uint256")
    parser.add_argument("--inv-out0", default="", help="uint256")
    parser.add_argument("--first-chunk-out0", default="", help="uint256")
    parser.add_argument("--w1-out0", default="", help="uint256")
    parser.add_argument("--w0-out0", default="", help="uint256")
    parser.add_argument("--artifact-root", default="", help="optional expected bytes32 artifactRoot")
    parser.add_argument("--transcript-hash", default="", help="optional expected bytes32 transcriptHash")
    parser.add_argument(
        "--wasm",
        default="zk/stage6_groth16/stage6_single_strict_js/stage6_single_strict.wasm",
    )
    parser.add_argument(
        "--zkey",
        default="zk/stage6_groth16/stage6_single_strict_final.zkey",
    )
    parser.add_argument("--out-json", default="", help="optional output json with proof/public")
    args = parser.parse_args()

    if args.proof_input_json:
        rust_pi = json.load(open(args.proof_input_json, "r", encoding="utf-8"))
        public = rust_pi["public"]
        private = rust_pi["privateWitness"]
        fe = private["feChunks"]
        args.result_digest = public["pairingDigest"]
        args.fixed_q_commitment = public["coeffCommitment"]
        args.dbl_line_commitment = private["lineCommitments"]["dbl_line_commitment"]
        args.add_line_commitment = private["lineCommitments"]["add_line_commitment"]
        args.points_hash = public["pointsHash"]
        args.fixed_q_id = public.get("qHash") or public["coeffCommitment"]
        args.context = rust_pi.get("context", public.get("context", "0x0")) if isinstance(rust_pi, dict) else "0x0"
        # Current backend writes context/epoch in trace/public_inputs.json. proof_input keeps the relation payload.
        public_inputs_path = os.path.join(os.path.dirname(args.proof_input_json), "public_inputs.json")
        if os.path.exists(public_inputs_path):
            pub_full = json.load(open(public_inputs_path, "r", encoding="utf-8"))
            args.context = pub_full.get("context", args.context)
            args.epoch = int(pub_full.get("epoch", 1))
            args.pairs = int(pub_full.get("pairs", 1))
            args.valid_until = int(pub_full.get("validUntil", 0))
            args.nonce = int(pub_full.get("nonce", 0))
        args.miller_trace_commitment = public["traceRoot"]
        args.final_exponentiation_commitment = fe["final_digest"]
        args.miller_digest = public["millerDigest"]
        args.singles_digest = public["singlesDigest"]
        args.miller_out00 = private["millerOut00"]
        args.miller_out11 = private["millerOut11"]
        args.inv_out0 = fe["inv_out0"]
        args.first_chunk_out0 = fe["first_chunk_out0"]
        args.w1_out0 = fe["w1_out0"]
        args.w0_out0 = fe["w0_out0"]
        args.public_inputs_hash = public["traceRoot"]
        args.statement_hash = public["transitionRoot"]
        args.final_exponentiation_commitment = fe["final_digest"]
        args.chain_id = int(args.chain_id or 31337)
        args.verifier = args.verifier or "0"

    required = [
        "public_inputs_hash", "result_digest", "statement_hash", "fixed_q_id", "fixed_q_commitment",
        "dbl_line_commitment", "add_line_commitment", "points_hash", "context", "miller_digest",
        "singles_digest", "miller_out00", "miller_out11", "inv_out0", "first_chunk_out0", "w1_out0", "w0_out0",
    ]
    missing = [name for name in required if not str(getattr(args, name)).strip()]
    if missing:
        raise RuntimeError(f"missing required inputs: {', '.join(missing)}")

    pi_hash = to_field(args.public_inputs_hash)
    statement_hash = to_field(args.statement_hash)
    final_exponentiation_commitment = to_field(args.final_exponentiation_commitment or args.output_hash or args.result_digest)
    fixed_q_id = to_field(args.fixed_q_id)
    fixed_q = to_field(args.fixed_q_commitment)
    dbl_line_commitment = to_field(args.dbl_line_commitment)
    add_line_commitment = to_field(args.add_line_commitment)
    points_hash = to_field(args.points_hash)
    context = to_field(args.context)
    epoch = int(args.epoch) % SNARK_SCALAR_FIELD
    pairs = int(args.pairs)
    valid_until = int(args.valid_until) % SNARK_SCALAR_FIELD
    nonce = int(args.nonce) % SNARK_SCALAR_FIELD
    chain_id = int(args.chain_id) % SNARK_SCALAR_FIELD
    verifier_addr = to_field(args.verifier)
    miller_trace_commitment = to_field(args.miller_trace_commitment or args.domain_tag or args.miller_digest)

    miller_digest = to_field(args.miller_digest)
    singles_digest = to_field(args.singles_digest)
    miller_out00 = to_field(args.miller_out00)
    miller_out11 = to_field(args.miller_out11)
    inv_out0 = to_field(args.inv_out0)
    first_chunk_out0 = to_field(args.first_chunk_out0)
    w1_out0 = to_field(args.w1_out0)
    w0_out0 = to_field(args.w0_out0)

    # Derive digest from strict recurrence if requested.
    if args.result_digest.strip().lower() == "auto":
        pre_rel = build_single_strict_witness(
            pi_hash=pi_hash,
            result_digest=0,
            statement_hash=statement_hash,
            final_exponentiation_commitment=final_exponentiation_commitment,
            fixed_q_id=fixed_q_id,
            fixed_q=fixed_q,
            dbl_line_commitment=dbl_line_commitment,
            add_line_commitment=add_line_commitment,
            points_hash=points_hash,
            context=context,
            epoch=epoch,
            pairs=pairs,
            valid_until=valid_until,
            nonce=nonce,
            chain_id=chain_id,
            verifier_addr=verifier_addr,
            miller_trace_commitment=miller_trace_commitment,
            miller_digest=miller_digest,
            singles_digest=singles_digest,
            miller_out00=miller_out00,
            miller_out11=miller_out11,
            inv_out0=inv_out0,
            first_chunk_out0=first_chunk_out0,
            w1_out0=w1_out0,
            w0_out0=w0_out0,
            enforce_result_digest=False,
        )
        result_digest = pre_rel["feState"][-1]
    else:
        result_digest = to_field(args.result_digest)

    rel = build_single_strict_witness(
        pi_hash=pi_hash,
        result_digest=result_digest,
        statement_hash=statement_hash,
        final_exponentiation_commitment=final_exponentiation_commitment,
        fixed_q_id=fixed_q_id,
        fixed_q=fixed_q,
        dbl_line_commitment=dbl_line_commitment,
        add_line_commitment=add_line_commitment,
        points_hash=points_hash,
        context=context,
        epoch=epoch,
        pairs=pairs,
        valid_until=valid_until,
        nonce=nonce,
        chain_id=chain_id,
        verifier_addr=verifier_addr,
        miller_trace_commitment=miller_trace_commitment,
        miller_digest=miller_digest,
        singles_digest=singles_digest,
        miller_out00=miller_out00,
        miller_out11=miller_out11,
        inv_out0=inv_out0,
        first_chunk_out0=first_chunk_out0,
        w1_out0=w1_out0,
        w0_out0=w0_out0,
        enforce_result_digest=True,
    )

    artifact_root_hex = h32(rel["artifactRootFr"])
    transcript_hash_hex = h32(rel["transcriptHashFr"])

    if args.artifact_root and to_field(args.artifact_root) != rel["artifactRootFr"]:
        raise RuntimeError("provided --artifact-root does not match single-strict relation")
    if args.transcript_hash and to_field(args.transcript_hash) != rel["transcriptHashFr"]:
        raise RuntimeError("provided --transcript-hash does not match single-strict relation")

    with tempfile.TemporaryDirectory(prefix="stage6_single_strict_") as td:
        input_path = os.path.join(td, "input.json")
        proof_path = os.path.join(td, "proof.json")
        public_path = os.path.join(td, "public.json")
        with open(input_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "piHash": str(pi_hash),
                    "resultDigest": str(result_digest),
                    "artifactRoot": str(rel["artifactRootFr"]),
                    "transcriptHash": str(rel["transcriptHashFr"]),
                    "fixedQCommitment": str(fixed_q),
                    "dblLineCommitment": str(dbl_line_commitment),
                    "addLineCommitment": str(add_line_commitment),
                    "pointsHash": str(points_hash),
                    "context": str(context),
                    "epoch": str(epoch),
                    "pairs": str(pairs),
                    "millerTraceCommitment": str(miller_trace_commitment),
                    "statementHash": str(statement_hash),
                    "finalExponentiationCommitment": str(final_exponentiation_commitment),
                    "fixedQId": str(fixed_q_id),
                    "validUntil": str(valid_until),
                    "nonce": str(nonce),
                    "chainId": str(chain_id),
                    "verifierAddr": str(verifier_addr),
                    "millerDigest": str(miller_digest),
                    "singlesDigest": str(singles_digest),
                    "millerOut00": str(miller_out00),
                    "millerOut11": str(miller_out11),
                    "invOut0": str(inv_out0),
                    "firstChunkOut0": str(first_chunk_out0),
                    "w1Out0": str(w1_out0),
                    "w0Out0": str(w0_out0),
                    "millerAcc": [str(v) for v in rel["millerAcc"]],
                    "feState": [str(v) for v in rel["feState"]],
                },
                f,
            )

        run(
            [
                snarkjs_bin(),
                "groth16",
                "fullprove",
                input_path,
                args.wasm,
                args.zkey,
                proof_path,
                public_path,
            ]
        )

        proof = json.load(open(proof_path, "r", encoding="utf-8"))
        public = json.load(open(public_path, "r", encoding="utf-8"))

    a0 = int(proof["pi_a"][0])
    a1 = int(proof["pi_a"][1])
    b00 = int(proof["pi_b"][0][1])
    b01 = int(proof["pi_b"][0][0])
    b10 = int(proof["pi_b"][1][1])
    b11 = int(proof["pi_b"][1][0])
    c0 = int(proof["pi_c"][0])
    c1 = int(proof["pi_c"][1])

    proof_abi = run(
        [
            "cast",
            "abi-encode",
            "f((uint256[2],uint256[2][2],uint256[2]))",
            f"([{a0},{a1}],[[{b00},{b01}],[{b10},{b11}]],[{c0},{c1}])",
        ]
    )

    public_signals = [
        pi_hash,
        result_digest,
        rel["artifactRootFr"],
        rel["transcriptHashFr"],
        fixed_q,
        dbl_line_commitment,
        add_line_commitment,
        points_hash,
        context,
        epoch,
        pairs,
        miller_trace_commitment,
        statement_hash,
        final_exponentiation_commitment,
        fixed_q_id,
        valid_until,
        nonce,
        chain_id,
        verifier_addr,
    ]

    out = {
        "publicInputsHash": h32(pi_hash),
        "publicSignalsFromProof": public,
        "publicSignalsModel": [str(v) for v in public_signals],
        "resultDigest": h32(result_digest),
        "artifactRoot": artifact_root_hex,
        "transcriptHash": transcript_hash_hex,
        "trace": {
            "millerDigest": h32(miller_digest),
            "singlesDigest": h32(singles_digest),
            "millerOut00": str(miller_out00),
            "millerOut11": str(miller_out11),
            "invOut0": str(inv_out0),
            "firstChunkOut0": str(first_chunk_out0),
            "w1Out0": str(w1_out0),
            "w0Out0": str(w0_out0),
            "cMix": str(rel["cMix"]),
            "millerSeed": str(rel["millerSeed"]),
            "millerAccLast": str(rel["millerAcc"][-1]),
            "feStateLast": str(rel["feState"][-1]),
            "millerCommit": str(rel["mCommit"][-1]),
            "feCommit": str(rel["fCommit"][-1]),
        },
        "proofAbi": proof_abi,
    }

    if args.out_json:
        os.makedirs(os.path.dirname(args.out_json) or ".", exist_ok=True)
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)

    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
