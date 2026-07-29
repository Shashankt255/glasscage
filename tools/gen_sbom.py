#!/usr/bin/env python3
"""Generate a CycloneDX-style SBOM for GLASSCAGE (stdlib only, honest).

Usage: python tools/gen_sbom.py > sbom.json
Reports the package, its (zero) runtime dependencies, declared optional extras, and
the enumerated first-party modules. Does not invent transitive deps.
"""
import json, sys, hashlib, pkgutil
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import glasscage  # noqa: E402

def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

modules = []
for m in pkgutil.walk_packages(glasscage.__path__, "glasscage."):
    f = ROOT / (m.name.replace(".", "/") + ".py")
    if f.exists():
        modules.append({"name": m.name, "sha256": _sha(f)})

sbom = {
    "bomFormat": "CycloneDX", "specVersion": "1.5",
    "metadata": {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "component": {"type": "application", "name": "glasscage",
                      "version": glasscage.__version__,
                      "licenses": [{"license": {"id": "Apache-2.0"}}]},
        "tools": [{"name": "glasscage gen_sbom.py"}],
    },
    "components": [],  # zero runtime dependencies (stdlib-only core)
    "properties": [
        {"name": "runtime_dependencies", "value": "0 (standard library only)"},
        {"name": "optional_extras",
         "value": "llm(anthropic), yaml(pyyaml), rich, crypto(cryptography), dev"},
        {"name": "first_party_module_count", "value": str(len(modules))},
    ],
    "firstPartyModules": modules,
}
json.dump(sbom, sys.stdout, indent=2)
print()
