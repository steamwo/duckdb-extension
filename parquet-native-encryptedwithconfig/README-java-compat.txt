DuckDB 1.5.5 encrypted_parquet - parquet-java/Spark compatibility add-on

Generators
----------
prepare_extension_java_compat_final.py
  Existing parquet-java PropertiesDrivenCryptoFactory/InMemoryKMS-compatible
  generator.

prepare_extension_direct_kms_final.py
  Runs the generator above, then adds direct-KMS metadata overlay support for
  the explicit COPY ENCRYPTION_CONFIG path.

Build scripts
-------------
build-windows-native-final.ps1
  Builds DuckDB v1.5.5 + encrypted_parquet for Windows x64/MSVC.

build-linux-native-final.sh
  Builds DuckDB v1.5.5 + encrypted_parquet for Linux x86_64.

Usage examples
--------------
java_compat_usage.sql
  Existing parquet-java/InMemoryKMS uniform-encryption example.

direct_kms_usage.sql
  Explicit AES encryption plus direct-KMS key metadata for a custom Spark
  DecryptionPropertiesFactory/DecryptionKeyRetriever.

Configuration SQL API
---------------------
- Set a property:
    PRAGMA set_encrypted_parquet_config('name', 'value');
- Unset a property:
    PRAGMA unset_encrypted_parquet_config('name');
- Clear all properties:
    CALL clear_encrypted_parquet_config();

The clear operation is a zero-argument table function because DuckDB v1.5.5
loadable-extension runtime did not reliably resolve the zero-argument custom
pragma form. CI executes this API after loading the produced extension.

Compatibility policy
--------------------
- Existing add_encrypted_parquet_key + COPY ENCRYPTION_CONFIG remains the
  authoritative source of the actual AES key.
- When explicit ENCRYPTION_CONFIG is present and
  parquet.encryption.footer.key is configured, that value is treated only as
  the external/business/KMS key ID and does not alter the AES key.
- Direct-KMS metadata is stored in FileCryptoMetaData.key_metadata as PKMT1
  JSON. masterKeyID and the exact parquet.encryption.footer.key property carry
  the configured external key ID.
- parquet.crypto.factory.class and parquet.encryption.kms.client.class are also
  persisted as additional JSON fields when configured.
- Direct-KMS metadata includes duckdbDirectKey=true. A custom Spark
  DecryptionKeyRetriever should parse masterKeyID and return the final AES key
  directly; it should not invoke FileKeyUnwrapper/wrappedDEK processing.
- If explicit ENCRYPTION_CONFIG is absent, the existing Hadoop-style uniform
  mode and InMemoryKMS wrapping behavior are unchanged.
- Per-column encryption is intentionally not implemented in this add-on.
