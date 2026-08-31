-- Direct-KMS metadata mode with COPY-local isolation.
-- footer_key remains DuckDB's local key alias / actual AES key source.
-- master_key_id and the other Direct-KMS fields below are metadata only and are
-- stored in FileCryptoMetaData.key_metadata as PKMT1 JSON for Spark/parquet-java.

LOAD encrypted_parquet;

-- Example only. Replace with the actual 16/24/32-byte AES key used by your
-- application. The first argument is only DuckDB's local key-registry name.
PRAGMA add_encrypted_parquet_key('local_footer_key', '0123456789abcdef');

COPY (
  SELECT 1 AS id, 'secret' AS payload
) TO 'direct_kms.parquet' (
  FORMAT encrypted_parquet,
  ENCRYPTION_CONFIG {
    footer_key: 'local_footer_key',
    master_key_id: 'kms-master-key-123',
    kms_instance_id: 'production-kms',
    kms_instance_url: 'https://kms.example.invalid',
    crypto_factory_class: 'com.company.DirectKmsCryptoFactory',
    kms_client_class: 'com.company.DirectKmsClient'
  }
);

-- FileCryptoMetaData.key_metadata is a PKMT1 JSON payload containing at least:
--   masterKeyID / parquet.encryption.footer.key = kms-master-key-123
--   kmsInstanceID = production-kms
--   kmsInstanceURL = https://kms.example.invalid
--   parquet.crypto.factory.class = com.company.DirectKmsCryptoFactory
--   parquet.encryption.kms.client.class = com.company.DirectKmsClient
--   duckdbDirectKey = true
--
-- These metadata values belong to this COPY's ParquetEncryptionConfig. Another
-- COPY can use different values in the same DatabaseInstance without reading
-- or overwriting the database-scoped EncryptedParquetConfiguration.
--
-- The Spark-side custom DecryptionKeyRetriever should parse masterKeyID from
-- this key_metadata and return the final AES key directly. It must not use
-- parquet-java FileKeyUnwrapper/wrappedDEK semantics for duckdbDirectKey=true.
--
-- Hadoop/parquet-java PropertiesDrivenCryptoFactory + InMemoryKMS compatibility
-- still uses PRAGMA set_encrypted_parquet_config(...) as before. For backward
-- compatibility, the PR #1 explicit-COPY + Direct-KMS-PRAGMA form is retained
-- as a legacy fallback when none of the COPY-local Direct-KMS fields above are
-- present; that legacy fallback is database-scoped and is not concurrency-safe.
