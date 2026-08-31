-- DuckDB: parquet-java PropertiesDrivenCryptoFactory / InMemoryKMS compatible uniform encryption
LOAD encrypted_parquet;

CALL set_encrypted_parquet_config(
  'parquet.crypto.factory.class',
  'org.apache.parquet.crypto.keytools.PropertiesDrivenCryptoFactory'
);

CALL set_encrypted_parquet_config(
  'parquet.encryption.kms.client.class',
  'org.apache.parquet.crypto.keytools.mocks.InMemoryKMS'
);

-- Java InMemoryKMS format: keyId:Base64(AES master key)
CALL set_encrypted_parquet_config(
  'parquet.encryption.key.list',
  'keyA:AAECAwQFBgcICQoLDA0ODw=='
);

-- Java uniform encryption: one generated DEK protects footer + all columns.
CALL set_encrypted_parquet_config(
  'parquet.encryption.uniform.key',
  'keyA'
);

-- Optional; these values match the Java defaults.
CALL set_encrypted_parquet_config('parquet.encryption.algorithm', 'AES_GCM_V1');
CALL set_encrypted_parquet_config('parquet.encryption.double.wrapping', 'true');
CALL set_encrypted_parquet_config('parquet.encryption.key.material.store.internally', 'true');
CALL set_encrypted_parquet_config('parquet.encryption.data.key.length.bits', '128');
CALL set_encrypted_parquet_config('parquet.encryption.kek.length.bits', '128');

COPY (
  SELECT 1::INTEGER AS id, 'spark-readable'::VARCHAR AS payload
)
TO 'java_compatible.parquet'
(FORMAT encrypted_parquet);

CALL clear_encrypted_parquet_config();


-- Spark / Scala read side:
-- val hconf = spark.sparkContext.hadoopConfiguration
-- hconf.set("parquet.crypto.factory.class",
--   "org.apache.parquet.crypto.keytools.PropertiesDrivenCryptoFactory")
-- hconf.set("parquet.encryption.kms.client.class",
--   "org.apache.parquet.crypto.keytools.mocks.InMemoryKMS")
-- hconf.set("parquet.encryption.key.list",
--   "keyA:AAECAwQFBgcICQoLDA0ODw==")
-- val df = spark.read.parquet("java_compatible.parquet")
-- df.show(false)
