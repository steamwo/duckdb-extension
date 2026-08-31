-- Direct-KMS metadata mode.
-- The AES key registered below is the actual Parquet footer/data encryption key.
-- parquet.encryption.footer.key is a business/KMS key identifier only; it does
-- not replace ENCRYPTION_CONFIG.footer_key and is written into PKMT1 key_metadata.

LOAD encrypted_parquet;

CALL clear_encrypted_parquet_config();

-- Example only. Replace with the actual 16/24/32-byte AES key used by your
-- application. The first argument is only DuckDB's local key-registry name.
PRAGMA add_encrypted_parquet_key('local_footer_key', '0123456789abcdef');

CALL set_encrypted_parquet_config(
  'parquet.crypto.factory.class',
  'com.company.DirectKmsCryptoFactory'
);
CALL set_encrypted_parquet_config(
  'parquet.encryption.kms.client.class',
  'com.company.DirectKmsClient'
);
CALL set_encrypted_parquet_config(
  'parquet.encryption.footer.key',
  'kms-master-key-123'
);
CALL set_encrypted_parquet_config(
  'parquet.encryption.kms.instance.id',
  'production-kms'
);
CALL set_encrypted_parquet_config(
  'parquet.encryption.kms.instance.url',
  'https://kms.example.invalid'
);

COPY (
  SELECT 1 AS id, 'secret' AS payload
) TO 'direct_kms.parquet' (
  FORMAT encrypted_parquet,
  ENCRYPTION_CONFIG {
    footer_key: 'local_footer_key'
  }
);

CALL clear_encrypted_parquet_config();

-- FileCryptoMetaData.key_metadata is a PKMT1 JSON payload containing at least:
--   masterKeyID / parquet.encryption.footer.key = kms-master-key-123
--   parquet.crypto.factory.class = com.company.DirectKmsCryptoFactory
--   parquet.encryption.kms.client.class = com.company.DirectKmsClient
--   duckdbDirectKey = true
--
-- The Spark-side custom DecryptionKeyRetriever should parse masterKeyID from
-- this key_metadata and return the final AES key directly. It must not use
-- parquet-java FileKeyUnwrapper/wrappedDEK semantics for duckdbDirectKey=true.
