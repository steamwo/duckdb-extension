#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
HERE = Path(__file__).resolve().parent
BASE = HERE / 'prepare_extension_direct_kms_final.py'

subprocess.check_call([sys.executable, str(BASE), str(ROOT)])

# Preserve the original config pragma registration exactly. The existing
# extension used a zero-argument PragmaCall and existing callers use:
#   PRAGMA clear_encrypted_parquet_config;
# Do not change this interface as part of the Direct-KMS metadata work.
p = ROOT / 'extension' / 'encrypted_parquet' / 'parquet_extension.cpp'
s = p.read_text(encoding='utf-8')
old = 'PragmaFunction::PragmaStatement("clear_encrypted_parquet_config", ParquetCrypto::ClearConfig)'
new = 'PragmaFunction::PragmaCall("clear_encrypted_parquet_config", ParquetCrypto::ClearConfig, {})'
if s.count(old) != 1:
    raise RuntimeError(f'expected exactly one Direct-KMS clear pragma override, found {s.count(old)}')
p.write_text(s.replace(old, new, 1), encoding='utf-8')

print('Original clear_encrypted_parquet_config registration restored:', p)
