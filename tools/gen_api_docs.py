#!/usr/bin/env python3
"""Generate API reference docs from docstrings (stdlib pydoc, no dependencies).

Usage: python tools/gen_api_docs.py
Writes docs/api/<module>.txt for each public module.
"""
import importlib
import pkgutil
import pydoc
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = ROOT / "docs" / "api"
OUT.mkdir(parents=True, exist_ok=True)

import glasscage


def modules():
    yield "glasscage"
    for m in pkgutil.walk_packages(glasscage.__path__, "glasscage."):
        if m.name.endswith("__main__"): continue
        yield m.name

count = 0
index = ["# GLASSCAGE API Reference\n", "Auto-generated from docstrings via pydoc.\n"]
for name in sorted(set(modules())):
    try:
        mod = importlib.import_module(name)
        text = pydoc.render_doc(mod, renderer=pydoc.plaintext)
    except Exception as e:
        text = f"(could not document {name}: {e})"
    (OUT / f"{name}.txt").write_text(text)
    index.append(f"- [{name}](api/{name}.txt)")
    count += 1
(ROOT / "docs" / "API_INDEX.md").write_text("\n".join(index))
print(f"wrote {count} API doc files to {OUT}")
