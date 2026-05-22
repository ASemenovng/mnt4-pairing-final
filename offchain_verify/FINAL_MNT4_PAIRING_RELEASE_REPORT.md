# Финальный отчет по реализации MNT4 pairing verifier

Документ формируется командой `script/final_mnt4_pairing_release.py` для итоговой реализации, вынесенной в `src/final_mnt4_pairing`.

## Область отчета

Финальный путь содержит один публичный deployable-entrypoint `MNT4PairingFinal`, арифметические/reference-контракты и нейтральный proof-checker adapter. В этом контуре намеренно отсутствуют ownership, replay-state, expiry-policy, consume-режим, изменяемые registry и diagnostic on-chain recomputation.

## Итоговая сравнительная таблица

| Слой / измерение | Метрика | Значение |
|---|---|---:|
| Full on-chain baseline | Reference MNT4 pairing digest gas | 259719954 |
| New on-chain verifier | Final verifier gas | 343435 |
| New on-chain verifier | Backend-only checker gas | 325283 |
| Rust backend | Total reported generation, ms | 430 |
| Proof generation | Command wall time, ms | 518 |
| BN254 verifier-envelope | Constraints | 1538 |
| MNT-native relation evidence | Total prepared/residue constraints | 24178 |
| MNT-native relation evidence | Miller single constraints | 4514 |
| MNT-native relation evidence | Miller multi n=2 constraints | 7520 |
| MNT-native relation evidence | Miller multi n=4 constraints | 13532 |
| MNT-native relation evidence | Line-cache constraints | 19554 |
| MNT-native relation evidence | FE residue constraints | 110 |
| External comparison anchor | BN254 emulated pairing constraints | 1393318 |
| External comparison anchor | Sonobe-like decider constraints | 9000000 |

## Relation roots из Rust artifacts

| Relation root | Значение |
|---|---|
| lineCacheRelationRoot | `0xe429001bc805f56c1ee60d0a1a944469f8909dc41f851b35ffaef09bc5cb1e99` |
| millerRelationRoot | `0xe4d856950fae10a6cebe4eec166088df4beea5f4be940fb0f70fef8de85e9895` |
| finalExponentiationRelationRoot | `0x1eb603478321298f4249195923b2c1034802ac1a48d3289f6dfbd074a77b87c8` |

## Основные on-chain метрики

| Измерение | Gas |
|---|---:|
| Полный финальный путь: `MNT4PairingFinal.verifyPairingClaim`, валидный proof | 343435 |
| Отклонение подмененной точки до proof verification | 25142 |
| Backend-only проверка proof через нейтральный checker | 325283 |
| Полное on-chain reference-вычисление MNT4 pairing digest | 259719954 |

## Метрики circuit

| Метрика | Значение |
|---|---:|
| Constraints | 1538 |
| Wires | 1560 |
| Public inputs | 19 |
| Private inputs | 392 |
| Размер proof, bytes | 256 |

Важно: эти circuit-метрики относятся к compact BN254 verifier-envelope, а не к полному доказательству MNT4-сопряжения. Для оценки будущего MNT-native/folding слоя используется отдельный отчет `cache/mnt_cycle_constraints/MNT_CYCLE_CONSTRAINTS_REPORT.md`.

## Метрики MNT-cycle native relation model

| Измерение | Constraints |
|---|---:|
| Miller relation, single pair | 4514 |
| Miller relation, multi n=2 | 7520 |
| Miller relation, multi n=4 | 13532 |
| Line-cache relation | 19554 |
| Final exponentiation residue relation | 110 |
| MNT-native prepared/residue model total | 24178 |
| BN254 emulated pairing reference | 1393318 |
| Sonobe-like decider reference | 9000000 |

## Метрики Rust off-chain backend

| Этап | Время, ms |
|---|---:|
| Генерация line cache | 195 |
| Генерация Miller trace | 215 |
| Final exponentiation | 19 |
| Генерация proof input | 0 |
| Total reported generation | 430 |
| Wall time Rust-команды | 1016 |

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

- `cache/final_mnt4_pairing/rust_backend_smoke`;
- `cache/final_mnt4_pairing/final_single_real_proof.json`;
- `cache/final_mnt4_pairing/forge_final_gas_report.log`;
- `cache/final_mnt4_pairing/release_summary.json`;
- `cache/mnt_cycle_constraints/MNT_CYCLE_CONSTRAINTS_REPORT.md`.
