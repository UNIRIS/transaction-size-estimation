# Transaction estimation

Context: Given 5 masters, 4 cross validation nodes and 36 storage nodes.

## Summary

| Contains | Size (bytes) |
| -----|--------------|
| Transaction + validations + with headers | 2656 |
| Transaction + validations - headers | 908 |
| Transaction only | 309 |

## Transaction only (value size in bytes) = 309

| New address | Type | Data | Timestamp | Public key | Signature | Origin signature |
|---------|------|------|-----------|------------|-----------|------------------|
| 32 | 1 | 106 (SC: UCO transfer + shared key proposal) | 10 | 32 | 64 | 64

## Master validation only (value size in bytes) = 139
| Tx hash | POW | Status | Timestamp | Public key | Signature |
|------------------|-----|--------|-----------|------------|-----------|
| 33 | 32 | 1 | 10 | 32 | 64 |


## Cross validation only (value size in bytes) = 107
| Status | Timestamp | Public key | Signature|
|--------|-----------|------------|----------|
| 1 | 10 | 32 | 64 |

## Header (value size in bytes) = 38
| Public key | Is unreachable | Is master | Is OK | Patch ID |
|------------|----------------|-----------|-------|----------|
| 32 | 1 | 1 | 1 | 3 |