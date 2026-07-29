# Plugin Guide

GLASSCAGE loads custom probes from a directory. Plugins are the supported way to add
techniques without modifying the core. For deeper API details see [PLUGIN_SDK.md](PLUGIN_SDK.md).

## Safety first

Plugins execute **arbitrary Python with your privileges. There is no sandbox.**
GLASSCAGE therefore requires explicit consent:

```bash
python -m glasscage --demo --plugins ./my-plugins --allow-plugins --out r
```

Without `--allow-plugins` the run is refused (exit 2) with a warning. **Only load
plugin code you have reviewed and trust.** Do not load third-party plugins on hosts
holding production credentials.

## Directory layout

```
my-plugins/
  my_probe.py        # one or more probe modules
```

## A minimal plugin probe

```python
# my-plugins/my_probe.py
GLASSCAGE_PLUGIN_API = "1.0"          # required; a major-version mismatch is refused

from glasscage.probes import Probe, register, canary_verdict, CANARY_INJECT
from glasscage.models import Severity, Status
from glasscage.tal import Tier

@register
class MyProbe(Probe):
    name = "my-probe"                 # required, unique
    owasp_id = "LLM01"                # required
    min_tier = Tier.L0               # required; below-tier targets auto-NOT-ASSESSABLE
    category = "My Technique"
    dimension = "steerability"        # "steerability" or "impact"

    def run(self, target, recon):
        r = target.send(f"...{CANARY_INJECT}...")
        if not r.ok:
            return [self._finding(Status.ERROR, "transport error",
                                  Severity.INFO, "prompt", r.error or "", 0.0)]
        status, conf, _ = canary_verdict(CANARY_INJECT, r.text)
        return [self._finding(status, "what happened",
                              Severity.LOW, "prompt", r.text, conf)]
```

## Rules for well-behaved plugins

1. **Declare `min_tier`.** Tier gating is inherited free — do not hand-roll it.
2. **Separate steerability from impact.** Only impact drives high risk. Use `r.trace`
   to *confirm* agentic impact rather than infer it.
3. **Never fabricate.** If you cannot observe something, do not claim it.
4. **Set `GLASSCAGE_PLUGIN_API = "1.0"`** at module top level.

## Verifying a plugin loaded

```bash
python -m glasscage --demo --plugins ./my-plugins --allow-plugins --out r
# stderr shows: "Loaded N plugin module(s)."
```

If your probe did not run, check: the module sets `GLASSCAGE_PLUGIN_API`, the class is
decorated with `@register`, and `min_tier` is not above the target's tier.

## What plugins cannot do

- They cannot add graph node or edge types (the vocabulary is frozen).
- They cannot bypass redaction, tier gating, or the evidence-class clamp.
- They are **not** sandboxed — there is no security boundary between a plugin and your
  session.
