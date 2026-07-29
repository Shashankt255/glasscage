# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Enable `python -m glasscage ...` (delegates to the CLI)."""
import sys
from pathlib import Path


def _run():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from cli import main
    from glasscage.errors import GlasscageError
    try:
        raise SystemExit(main())
    except GlasscageError as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    _run()
