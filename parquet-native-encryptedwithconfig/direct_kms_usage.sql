-- Direct-KMS metadata mode with COPY-local isolation.
--
-- RECOMMENDED: pass the actual AES key as a BLOB through footer_key_value.
-- Decode textual Base64/Hex explicitly with from_base64()/from_hex() so the
-- byte length unambiguously selects AES-128/192/256.
--
-- master_key_id and the other Direct-KMS fields below are metadata only and are
-- stored in FileCryptoMetaData.key_metadata as PKMT1 JSON for Spark/parquet-java.

LOAD encrypted_parquet;

-- AES-128 example: this Base64 value decodes to exactly 16 bytes
-- (ASCII "0123456789abcdef").
COPY (
  SELECT 1 AS id, 'secret' AS payload
) TO 'direct_kms.parquet' (
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

-- The same AES-128 key can be supplied as Hex instead:
--   footer_key_value: from_hex('30313233343536373839616263646566')
--
-- AES-256 Base64 example (decodes to exactly 32 bytes):
--   footer_key_value: from_base64('MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=')
--
-- Avoid passing a Base64/Hex *text string* to footer_key_value without decoding
-- it first. Also prefer footer_key_value for Direct-KMS over the inherited
-- add_encrypted_parquet_key auto-detection path: a 16-byte AES key has a
-- 24-character Base64 representation, which is also a valid raw AES-192 string
-- length and is therefore ambiguous to an auto-detecting key registry API.

-- FileCryptoMetaData.key_metadata is a PKMT1 JSON payload containing at least:
--   masterKeyID / parquet.encryption.footer.key = kms-master-key-123
--   kmsInstanceID = production-kms
--   kmsInstanceURL = https://kms.example.invalid
--   parquet.crypto.factory.class = com.company.DirectKmsCryptoFactory
--   parquet.encryption.kms.client.class = com.company.DirectKmsClient
--   duckdbDirectKey = true
--
-- The AES key bytes and these metadata values belong to this COPY's
-- ParquetEncryptionConfig. Another COPY can use different key bytes and metadata
-- in the same DatabaseInstance without reading or overwriting the database-scoped
-- EncryptedParquetConfiguration or the local key-alias registry.
--
-- The Spark-side custom DecryptionKeyRetriever should parse masterKeyID from
-- this key_metadata and return the final AES key directly. It must not use
-- parquet-java FileKeyUnwrapper/wrappedDEK semantics for duckdbDirectKey=true.
--
-- Backward compatibility: footer_key:'alias' + add_encrypted_parquet_key remains
-- supported. Hadoop/parquet-java PropertiesDrivenCryptoFactory + InMemoryKMS
-- compatibility still uses PRAGMA set_encrypted_parquet_config(...) as before.
-- The PR #1 explicit-COPY + Direct-KMS-PRAGMA form is also retained as a legacy
-- fallback when none of the COPY-local Direct-KMS fields are present; that
-- legacy fallback is database-scoped and is not concurrency-safe.
