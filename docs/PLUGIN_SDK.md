# GLASSCAGE Plugin SDK

Stable, versioned interface (`PLUGIN_API_VERSION = "1.0"`) for shipping custom probes
without modifying the core.

## Contract
- A plugin is a `.py` file in a plugins directory (load with `--plugins DIR`).
- Register probes by subclassing `glasscage.probes.Probe` + `@register`, or expose a
  module-level `register(registry)` hook.
- Declare `GLASSCAGE_PLUGIN_API = "1.0"`; a major-version mismatch is refused.
- Every probe MUST define `name`, `owasp_id`, and `min_tier`.
- A probe MAY define `surface_kinds` — the surface kinds it can drive. Defaults to
  `(SurfaceKind.CHAT,)`, so a probe written before this attribute existed keeps working
  unchanged. The engine never invokes a probe against a kind it does not declare; it
  reports `NOT ASSESSABLE` instead, exactly as it does for an unmet `min_tier`. Declare a
  non-chat kind only when your `run()` can actually drive one. See
  [ADR 0006](adr/0006-probe-surface-applicability.md).

## Minimal example
```python
from glasscage.probes import Probe, register, canary_verdict, CANARY_INJECT
from glasscage.models import Severity, Status
from glasscage.tal import Tier

GLASSCAGE_PLUGIN_API = "1.0"

@register
class MyProbe(Probe):
    name = "my-probe"
    owasp_id = "LLM01"
    min_tier = Tier.L0
    # surface_kinds omitted -> (SurfaceKind.CHAT,), correct for a prompt-shaped probe
    def run(self, target, recon):
        r = target.send("...")
        status, conf, _ = canary_verdict(CANARY_INJECT, r.text)
        return [self._finding(status, "result", Severity.LOW, "...", r.text, conf)]
```
See `plugins_example/example_probe.py`. Load only trusted plugins — plugin code runs
with the host's privileges.

## Stability
Public interfaces are semver'd. Within a major version: `Probe` base attributes,
`register`, `canary_verdict`, `detect_secret`, `Finding` fields, adapter base class,
and `PropertyGraph` public methods will not break. See `VERSIONING.md`.
