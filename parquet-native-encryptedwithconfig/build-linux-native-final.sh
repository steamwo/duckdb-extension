#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${1:-$SCRIPT_DIR/work-linux-amd64}"

rm -rf "$WORK"
mkdir -p "$WORK"

DUCK="$WORK/duckdb"
git clone --depth 1 --branch v1.5.5 https://github.com/duckdb/duckdb.git "$DUCK"

python3 "$SCRIPT_DIR/prepare_extension_direct_kms_final.py" "$DUCK"

CONFIG="$DUCK/extension/extension_config_encrypted_parquet.cmake"
BUILD="$DUCK/build/linux_amd64"

cmake -S "$DUCK" -B "$BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DDUCKDB_EXTENSION_CONFIGS="$CONFIG" \
  -DPython3_EXECUTABLE="$(command -v python3)" \
  -DBUILD_SHELL=ON \
  -DBUILD_UNITTESTS=OFF \
  -DBUILD_BENCHMARKS=OFF \
  -DNATIVE_ARCH=OFF

cmake --build "$BUILD" --parallel "${BUILD_JOBS:-4}"

DUCK_BIN="$(find "$BUILD" -type f -name duckdb -perm -111 | head -n 1)"
EXTENSION="$(find "$BUILD" -type f -name encrypted_parquet.duckdb_extension | head -n 1)"

if [[ -z "$DUCK_BIN" ]]; then
  echo "duckdb executable was not produced" >&2
  exit 1
fi
if [[ -z "$EXTENSION" ]]; then
  echo "encrypted_parquet.duckdb_extension was not produced" >&2
  exit 1
fi

DIST_ROOT="$SCRIPT_DIR/dist"
DIST="$DIST_ROOT/linux_amd64"
rm -rf "$DIST"
mkdir -p "$DIST"

cp "$DUCK_BIN" "$DIST/duckdb"
cp "$EXTENSION" "$DIST/encrypted_parquet.duckdb_extension"
cp "$SCRIPT_DIR/java_compat_usage.sql" "$DIST/java_compat_usage.sql"
if [[ -f "$SCRIPT_DIR/direct_kms_usage.sql" ]]; then
  cp "$SCRIPT_DIR/direct_kms_usage.sql" "$DIST/direct_kms_usage.sql"
fi

cat > "$DIST/RUN-LINUX.txt" <<'EOF'
DuckDB v1.5.5 + encrypted_parquet (linux_amd64)

Start:
    ./duckdb -unsigned

Then:
    LOAD 'encrypted_parquet.duckdb_extension';

Use java_compat_usage.sql for parquet-java/InMemoryKMS wrapping.
Use direct_kms_usage.sql for explicit AES encryption plus direct-KMS metadata.
EOF

tar -C "$DIST_ROOT" -czf "$DIST_ROOT/linux_amd64.tar.gz" linux_amd64

echo "DONE"
echo "  DuckDB:    $DIST/duckdb"
echo "  Extension: $DIST/encrypted_parquet.duckdb_extension"
echo "  Package:   $DIST_ROOT/linux_amd64.tar.gz"
