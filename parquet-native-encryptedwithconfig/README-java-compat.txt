DuckDB 1.5.5 encrypted_parquet - parquet-java/Spark compatibility add-on

prepare_extension_java_compat_final.py
  Self-contained generator. The previously validated generator is kept first,
  then the Java-compatible Hadoop Configuration / PKMT1 layer is appended.

build-windows-java-compat-final.ps1
  Builds DuckDB v1.5.5 encrypted_parquet on Windows.

java_compat_usage.sql
  DuckDB write configuration and Spark read configuration.

Compatibility policy:
- Existing add_encrypted_parquet_key + COPY ENCRYPTION_CONFIG path has priority.
- With no explicit ENCRYPTION_CONFIG, Hadoop-style properties can activate the
  Java-compatible uniform-encryption path.
- Per-column encryption is intentionally not implemented in this add-on.
- The Java-compatible mode currently implements InMemoryKMS wrapping semantics.
- Internal key metadata is PKMT1, with Java-compatible AES-GCM wrapped-key bytes.
