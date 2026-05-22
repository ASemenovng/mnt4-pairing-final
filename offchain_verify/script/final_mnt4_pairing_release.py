#!/usr/bin/env python3
"""Reproducible final MNT4 pairing release pipeline.

The script intentionally targets the supervisor-facing final folder only:
  src/final_mnt4_pairing
  test/final_mnt4_pairing

It does not use PairingTraceWorker or anvil as an arithmetic oracle. The Rust
backend is run as the off-chain arithmetic source; the Solidity tests check the
public verifier, the neutral proof checker, arkworks vectors, and BN254
precompile-style boolean behavior.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "cache" / "final_mnt4_pairing"
RUST_OUT = CACHE / "rust_backend_smoke"
SUMMARY_JSON = CACHE / "release_summary.json"
REPORT_MD = ROOT / "FINAL_MNT4_PAIRING_RELEASE_REPORT.md"
RUST_REQUEST = CACHE / "parametric_q_request.json"
MNT_CYCLE_REPORT = ROOT / "cache" / "mnt_cycle_constraints" / "MNT_CYCLE_CONSTRAINTS_REPORT.md"


def snarkjs_bin() -> str:
    env = os.environ.get("SNARKJS")
    if env:
        return env
    local = ROOT / "node_modules" / ".bin" / "snarkjs"
    if local.exists():
        return str(local)
    fallback = Path("/Users/a.i.semenov/Desktop/diploma/node_modules/.bin/snarkjs")
    if fallback.exists():
        return str(fallback)
    return "snarkjs"


def run(cmd: list[str], *, timeout: int | None = None) -> tuple[str, int]:
    started = time.time()
    proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, timeout=timeout)
    elapsed_ms = int((time.time() - started) * 1000)
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{out}")
    return out, elapsed_ms


def parse_r1cs_info(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    patterns = {
        "wires": r"# of Wires:\s*(\d+)",
        "constraints": r"# of Constraints:\s*(\d+)",
        "private_inputs": r"# of Private Inputs:\s*(\d+)",
        "public_inputs": r"# of Public Inputs:\s*(\d+)",
        "labels": r"# of Labels:\s*(\d+)",
    }
    for key, pattern in patterns.items():
        m = re.search(pattern, text)
        if m:
            out[key] = int(m.group(1))
    return out


def parse_mnt_cycle_report(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    patterns = {
        "native_prepared_residue_constraints": r"MNT-native prepared/residue relation model \| (\d+) \|",
        "native_direct_fe_reference_constraints": r"MNT-native model with direct FE reference \| (\d+) \|",
        "bn254_emulated_pairing_reference_constraints": r"BN254 emulated pairing reference \| (\d+) \|",
        "sonobe_decider_reference_constraints": r"Sonobe-like Ethereum decider reference \| (\d+) \|",
        "miller_transition_constraints": r"Miller transition relation, .* \| (\d+) \|",
        "miller_single_constraints": r"Single pair \| \d+ \| \d+ \| (\d+) \|",
        "miller_multi2_constraints": r"Multi pair, n=2 \| \d+ \| \d+ \| (\d+) \|",
        "miller_multi4_constraints": r"Multi pair, n=4 \| \d+ \| \d+ \| (\d+) \|",
        "line_cache_relation_constraints": r"Line-cache relation \| (\d+) \|",
        "final_exponentiation_residue_constraints": r"Final exponentiation residue relation, .* \| (\d+) \|",
    }
    for key, pattern in patterns.items():
        m = re.search(pattern, text)
        if m:
            out[key] = int(m.group(1))
    return out


def parse_test_gas(text: str) -> dict[str, int]:
    gas: dict[str, int] = {}
    for name, value in re.findall(r"\[PASS\]\s+(test\w+)\(\) \(gas: (\d+)\)", text):
        gas[name] = int(value)
    m = re.search(r"testFuzzWrapperMatchesRawPrecompileBoolean\(bytes\).*?μ:\s*(\d+),\s*~:\s*(\d+)", text)
    if m:
        gas["testFuzzWrapperMatchesRawPrecompileBoolean_mean"] = int(m.group(1))
        gas["testFuzzWrapperMatchesRawPrecompileBoolean_median"] = int(m.group(2))
    return gas


def regenerate_final_proof(proof_input_json: Path) -> tuple[dict, int]:
    cmd = [
        "python3", "script/generate_stage6_single_strict_groth16_proof.py",
        "--proof-input-json", str(proof_input_json),
        "--chain-id", "31337",
        "--verifier", "0x68b1d87f95878fe05b998f19b66f4baba5de1aed",
        "--out-json", str(CACHE / "final_single_real_proof.json"),
    ]
    _, elapsed_ms = run(cmd, timeout=120)
    return json.loads((CACHE / "final_single_real_proof.json").read_text()), elapsed_ms


def main() -> int:
    CACHE.mkdir(parents=True, exist_ok=True)

    RUST_REQUEST.write_text(json.dumps({
        "mode": "parametric_q",
        "points": [],
        "q": None,
        "context": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "epoch": 1,
        "nonce": 0,
        "valid_until": 0,
        "fixed_q_id": None,
    }, indent=2))
    rust_stdout, rust_total_ms = run([
        "cargo", "run", "--offline", "--manifest-path", "crates/mnt4_trace_backend/Cargo.toml", "--",
        "--request", str(RUST_REQUEST),
        "--out-dir", str(RUST_OUT),
    ], timeout=120)
    rust_public = json.loads((RUST_OUT / "public_inputs.json").read_text())

    proof_json, proof_generation_ms = regenerate_final_proof(RUST_OUT / "proof_input.json")

    r1cs_stdout, _ = run([snarkjs_bin(), "r1cs", "info", "zk/stage6_groth16/stage6_single_strict.r1cs"], timeout=30)
    constraints = parse_r1cs_info(r1cs_stdout)

    _, mnt_cycle_report_ms = run([
        "cargo", "run", "--offline", "--manifest-path", "crates/mnt_cycle_constraints/Cargo.toml", "--",
        "--out", str(MNT_CYCLE_REPORT),
    ], timeout=60)
    mnt_cycle_constraints = parse_mnt_cycle_report(MNT_CYCLE_REPORT.read_text())

    gas_stdout, gas_ms = run(["forge", "test", "--offline", "--match-path", "test/final_mnt4_pairing/*", "--gas-report"], timeout=240)
    (CACHE / "forge_final_gas_report.log").write_text(gas_stdout)

    summary = {
        "rust_backend": {
            "command_ms": rust_total_ms,
            "reported_timings": rust_public.get("timings", {}),
            "pairingDigest": rust_public.get("pairingDigest"),
            "millerDigest": rust_public.get("millerDigest"),
            "traceRoot": rust_public.get("traceRoot"),
        },
        "proof": {
            "generation_command_ms": proof_generation_ms,
            "proof_bytes": (len(proof_json["proofAbi"]) - 2) // 2,
            "public_inputs": len(proof_json["publicSignalsFromProof"]),
            "claimedPairingDigest": rust_public.get("pairingDigest"),
            "resultDigestFr": proof_json["resultDigest"],
            "artifactRoot": proof_json["artifactRoot"],
            "transcriptHash": proof_json["transcriptHash"],
        },
        "circuit": constraints,
        "mnt_cycle_constraints": {
            "report_generation_ms": mnt_cycle_report_ms,
            **mnt_cycle_constraints,
        },
        "gas": parse_test_gas(gas_stdout),
        "artifacts": {
            "rust_output_dir": str(RUST_OUT.relative_to(ROOT)),
            "proof_fixture": "cache/final_mnt4_pairing/final_single_real_proof.json",
            "gas_log": "cache/final_mnt4_pairing/forge_final_gas_report.log",
        },
    }
    SUMMARY_JSON.write_text(json.dumps(summary, indent=2, ensure_ascii=False))

    gas = summary["gas"]
    timings = summary["rust_backend"]["reported_timings"]
    REPORT_MD.write_text(f"""# Финальный отчет по реализации MNT4 pairing verifier

Документ формируется командой `script/final_mnt4_pairing_release.py` для итоговой реализации, вынесенной в `src/final_mnt4_pairing`.

## Область отчета

Финальный путь содержит один публичный deployable-entrypoint `MNT4PairingFinal`, арифметические/reference-контракты и нейтральный proof-checker adapter. В этом контуре намеренно отсутствуют ownership, replay-state, expiry-policy, consume-режим, изменяемые registry и diagnostic on-chain recomputation.

## Основные on-chain метрики

| Измерение | Gas |
|---|---:|
| Полный финальный путь: `MNT4PairingFinal.verifyPairingClaim`, валидный proof | {gas.get('testFinalMainContractVerifiesRealProofEnvelope', 'n/a')} |
| Отклонение подмененной точки до proof verification | {gas.get('testFinalMainContractRejectsTamperedPoint', 'n/a')} |
| Backend-only проверка proof через нейтральный checker | {gas.get('testRealProofFixtureVerifiesThroughNeutralChecker', 'n/a')} |
| Полное on-chain reference-вычисление MNT4 pairing digest | {gas.get('testFinalFolderParametricQPairingDigestMatchesArkworksConventionSet', 'n/a')} |

## Метрики circuit

| Метрика | Значение |
|---|---:|
| Constraints | {constraints.get('constraints', 'n/a')} |
| Wires | {constraints.get('wires', 'n/a')} |
| Public inputs | {constraints.get('public_inputs', 'n/a')} |
| Private inputs | {constraints.get('private_inputs', 'n/a')} |
| Размер proof, bytes | {summary['proof']['proof_bytes']} |

Важно: эти circuit-метрики относятся к compact BN254 verifier-envelope, а не к полному доказательству MNT4-сопряжения. Для оценки будущего MNT-native/folding слоя используется отдельный отчет `cache/mnt_cycle_constraints/MNT_CYCLE_CONSTRAINTS_REPORT.md`.

## Метрики MNT-cycle native relation model

| Измерение | Constraints |
|---|---:|
| Miller relation, single pair | {summary['mnt_cycle_constraints'].get('miller_single_constraints', 'n/a')} |
| Miller relation, multi n=2 | {summary['mnt_cycle_constraints'].get('miller_multi2_constraints', 'n/a')} |
| Miller relation, multi n=4 | {summary['mnt_cycle_constraints'].get('miller_multi4_constraints', 'n/a')} |
| Line-cache relation | {summary['mnt_cycle_constraints'].get('line_cache_relation_constraints', 'n/a')} |
| Final exponentiation residue relation | {summary['mnt_cycle_constraints'].get('final_exponentiation_residue_constraints', 'n/a')} |
| MNT-native prepared/residue model total | {summary['mnt_cycle_constraints'].get('native_prepared_residue_constraints', 'n/a')} |
| BN254 emulated pairing reference | {summary['mnt_cycle_constraints'].get('bn254_emulated_pairing_reference_constraints', 'n/a')} |
| Sonobe-like decider reference | {summary['mnt_cycle_constraints'].get('sonobe_decider_reference_constraints', 'n/a')} |

## Метрики Rust off-chain backend

| Этап | Время, ms |
|---|---:|
| Генерация line cache | {timings.get('line_cache_generation_ms', 'n/a')} |
| Генерация Miller trace | {timings.get('miller_trace_generation_ms', 'n/a')} |
| Final exponentiation | {timings.get('final_exponentiation_ms', 'n/a')} |
| Генерация proof input | {timings.get('proof_input_generation_ms', 'n/a')} |
| Total reported generation | {timings.get('total_generation_ms', 'n/a')} |
| Wall time Rust-команды | {rust_total_ms} |

## Проверки корректности

- Арифметика базового поля и полей расширения MNT4 сверяется с arkworks-векторами.
- Digest результата MNT4 pairing сверяется с arkworks-generated convention set.
- Финальный публичный verifier проверяется end-to-end на proof fixture, построенном из `Rust proof_input.json`.
- Подмена точки, Q, result digest, line commitment, Miller trace commitment и final exponentiation commitment отклоняется через public-input binding.
- BN254 precompile-style boolean behavior проверяется fuzz-тестом: wrapper и raw precompile должны возвращать одинаковый `true/false`.

## Воспроизводимость

Команда запуска из корня проекта:

```bash
python3 script/final_mnt4_pairing_release.py
```

Формируемые артефакты:

- `{summary['artifacts']['rust_output_dir']}`;
- `{summary['artifacts']['proof_fixture']}`;
- `{summary['artifacts']['gas_log']}`;
- `cache/final_mnt4_pairing/release_summary.json`;
- `cache/mnt_cycle_constraints/MNT_CYCLE_CONSTRAINTS_REPORT.md`.
""")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
