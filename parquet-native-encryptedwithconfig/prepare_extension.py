#!/usr/bin/env python3
"""Unified entry point for preparing the encrypted_parquet extension."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
GENERATORS = {
    "direct-kms": HERE / "prepare_extension_direct_kms_final.py",
    "java-compat": HERE / "prepare_extension_java_compat_final.py",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate encrypted_parquet inside a DuckDB source tree."
    )
    parser.add_argument(
        "duckdb_root",
        nargs="?",
        default=".",
        help="DuckDB source root (default: current directory)",
    )
    parser.add_argument(
        "--mode",
        choices=GENERATORS,
        default="direct-kms",
        help="Generator mode (default: direct-kms)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    generator = GENERATORS[args.mode]
    if not generator.exists():
        raise SystemExit(f"generator not found: {generator}")
    subprocess.check_call(
        [sys.executable, str(generator), str(Path(args.duckdb_root).resolve())]
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
