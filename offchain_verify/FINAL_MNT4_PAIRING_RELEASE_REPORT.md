# Финальный отчет по реализации MNT4 pairing verifier

Документ формируется командой `script/final_mnt4_pairing_release.py` для итоговой реализации, вынесенной в `src/final_mnt4_pairing`.

## Область отчета

Финальный путь содержит один публичный deployable-entrypoint `MNT4PairingFinal`, арифметические/reference-контракты и нейтральный proof-checker adapter. В этом контуре намеренно отсутствуют ownership, replay-state, expiry-policy, consume-режим, изменяемые registry и diagnostic on-chain recomputation.

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

## Метрики Rust off-chain backend

| Этап | Время, ms |
|---|---:|
| Генерация line cache | 184 |
| Генерация Miller trace | 213 |
| Final exponentiation | 18 |
| Генерация proof input | 0 |
| Total reported generation | 417 |
| Wall time Rust-команды | 10724 |

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
- `cache/final_mnt4_pairing/release_summary.json`.
