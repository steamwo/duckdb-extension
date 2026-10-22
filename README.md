# DuckDB encrypted_parquet extension

[中文 README](README.zh-CN.md)

This repository contains one implementation: `parquet-native-encryptedwithconfig`.

It builds a DuckDB `encrypted_parquet` loadable extension based on DuckDB's Parquet extension, adding Parquet Modular Encryption writer support, parquet-java/Spark compatibility, and COPY-local Direct-KMS metadata.

## Features

- Parquet Modular Encryption writer support with per-file/module AAD.
- parquet-java/Spark-compatible uniform encryption using `PropertiesDrivenCryptoFactory` and `InMemoryKMS` semantics.
- COPY-local Direct-KMS metadata so separate COPY statements can carry independent KMS identifiers and classes.
- Explicit binary AES-key input for Direct-KMS using `footer_key_value` with `from_base64()` / `from_hex()`.
- Linux x86_64 and Windows x64/MSVC build/package scripts.
- Linux and Windows CI smoke tests for extension loading, binary-key round trips, and COPY-local metadata isolation.

## Repository layout

```text
parquet-native-encryptedwithconfig/
├── prepare_extension.py
├── prepare_extension_java_compat_final.py
├── prepare_extension_direct_kms_final.py
├── build-linux-native-final.sh
├── build-windows-native-final.ps1
├── java_compat_usage.sql
└── direct_kms_usage.sql
```

`prepare_extension.py` is the public entry point. The two `*_final.py` files are retained as internal implementation layers because the Direct-KMS generator intentionally builds on the already validated Java-compatible generator.

## Prepare an existing DuckDB source tree

Default mode: Java compatibility + Direct-KMS overlay.

```bash
python3 parquet-native-encryptedwithconfig/prepare_extension.py /path/to/duckdb
```

Java-compatible layer only:

```bash
python3 parquet-native-encryptedwithconfig/prepare_extension.py /path/to/duckdb --mode java-compat
```

The generator creates:

```text
/path/to/duckdb/extension/encrypted_parquet/
/path/to/duckdb/extension/extension_config_encrypted_parquet.cmake
```

## Build

The current build scripts clone DuckDB `v1.5.5`.

### Linux

Requirements: Python 3, Git, CMake, Ninja, and a C++ compiler.

```bash
bash parquet-native-encryptedwithconfig/build-linux-native-final.sh
```

Artifacts are written to:

```text
parquet-native-encryptedwithconfig/dist/linux_amd64/
parquet-native-encryptedwithconfig/dist/linux_amd64.tar.gz
```

### Windows

Requirements: Python 3, Git, Visual Studio Build Tools with the C++ workload, and Visual Studio CMake.

```powershell
.\parquet-native-encryptedwithconfig\build-windows-native-final.ps1
```

Artifacts are written to:

```text
parquet-native-encryptedwithconfig\dist\windows_amd64\
parquet-native-encryptedwithconfig\dist\windows_amd64.zip
```

## Load the extension

Use the packaged DuckDB shell with unsigned extension loading enabled:

```bash
./duckdb -unsigned
```

Then:

```sql
LOAD 'encrypted_parquet.duckdb_extension';
```

## Java-compatible uniform encryption

See `parquet-native-encryptedwithconfig/java_compat_usage.sql`.

Configuration API:

```sql
PRAGMA set_encrypted_parquet_config('name', 'value');
PRAGMA unset_encrypted_parquet_config('name');
PRAGMA clear_encrypted_parquet_config;
```

The current compatibility layer implements Hadoop-style uniform encryption. Per-column Hadoop-style encryption is intentionally not implemented.

## Direct-KMS metadata

See `parquet-native-encryptedwithconfig/direct_kms_usage.sql`.

For new Direct-KMS code, pass the actual AES key as binary data through `footer_key_value`. Decode textual Base64 or Hex explicitly so the decoded byte length selects AES-128/192/256 without ambiguity:

```sql
COPY (SELECT 1 AS id, 'secret' AS payload)
TO 'direct_kms.parquet' (
  FORMAT encrypted_parquet,
  ENCRYPTION_CONFIG {
    footer_key_value: from_base64('MDEyMzQ1Njc4OWFiY2RlZg=='),
    master_key_id: 'kms-master-key-123',
    kms_instance_id: 'production-kms',
    kms_instance_url: 'https://kms.example.invalid',
    crypto_factory_class: 'com.company.DirectKmsCryptoFactory',
    kms_client_class: 'com.company.DirectKmsClient'
  }
);
```

A decoded key length of 16, 24, or 32 bytes selects AES-128, AES-192, or AES-256. This avoids the inherited raw-string/Base64 ambiguity where a 16-byte AES-128 key becomes 24 Base64 characters, which is also a valid raw AES-192 key length.

`master_key_id` and the other Direct-KMS fields are metadata only. Existing `add_encrypted_parquet_key` plus `footer_key: 'alias'` remains supported for backward compatibility.

The Direct-KMS metadata fields are attached to the current COPY operation. A legacy PRAGMA-based Direct-KMS fallback is also kept for backward compatibility, but it is database-scoped and should not be used when concurrent COPY isolation is required.

## Validation status

The binary Direct-KMS path from PR #3 has been used and validated outside CI. CI also covers Linux and Windows round trips for AES-128 Base64, AES-128 Hex, AES-256 Base64, the legacy key-alias path, and COPY-local metadata isolation.

## Upgrade notes

The generators patch DuckDB source files by matching expected source text. This is deliberate: if DuckDB changes an anchor, generation fails instead of silently producing a partially patched extension. When changing the DuckDB version, run CI and review every failed patch anchor.

Example keys, KMS IDs, classes, and URLs in this repository are placeholders and must not be used as production secrets or endpoints.
