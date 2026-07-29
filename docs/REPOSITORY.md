# Repository Structure

The complete layout of the GLASSCAGE repository, with the purpose of every major
directory. This reflects the actual tree as of 1.0.0rc3.

```
glasscage/
├── glasscage/                # the Python package (importable module)
│   ├── __init__.py           #   public API surface + __version__
│   ├── aakg/                 #   AI Attack Knowledge Graph — the substrate + engines
│   │   ├── types.py          #     24 node types, 12 edge types, edge states
│   │   ├── engine.py         #     PropertyGraph (deterministic, cached)
│   │   ├── build.py          #     assemble the graph from a run
│   │   ├── paths.py          #     attack-path traversal (weakest-link state)
│   │   ├── trust_graph.py    #     trust-boundary analysis
│   │   ├── blast.py          #     blast-radius analysis
│   │   ├── posture.py        #     Indicative Risk Index (heuristic)
│   │   ├── coverage.py       #     per-taxonomy coverage
│   │   ├── remediation.py    #     graph-cited prioritized mitigations
│   │   ├── report.py         #     graph-native markdown
│   │   ├── narrative.py      #     8 attack-narrative strategies (renderer)
│   │   ├── story.py          #     13-section Assessment Story (renderer)
│   │   └── views.py          #     5 audience views (renderer)
│   ├── adapters/             #   external-tool parsers (garak/pyrit/promptfoo/…)
│   ├── probes.py             #   21 built-in probes
│   ├── agent_probes.py       #   tier-aware agentic probes (L0–L2)
│   ├── tal.py                #   Target Abstraction Layer / capability tiers
│   ├── target.py             #   HTTP target + config validation
│   ├── refagent.py           #   deterministic L2 reference harness (a test fixture)
│   ├── recon.py              #   reconnaissance / tier assessment
│   ├── mcp.py                #   MCP manifest analysis (static; no network)
│   ├── evidence_confidence.py#   the 8-class evidence vocabulary + clamp
│   ├── redaction.py          #   secret redaction + optional encryption
│   ├── stats.py              #   Wilson intervals, trial runner
│   ├── taxonomy.py           #   OWASP↔ATLAS↔CWE↔CAPEC↔NIST crosswalk
│   ├── benchmark.py          #   detector corpus runner (Experimental)
│   ├── validation.py         #   paper/validation report (Experimental)
│   ├── genetic.py / mutation.py  # payload search / transforms
│   ├── report.py / sarif.py  #   top-level HTML/JSON report + SARIF export
│   ├── errors.py             #   exception hierarchy
│   ├── logging_setup.py      #   structured logging
│   ├── config.py             #   config validation
│   └── plugins.py            #   plugin loader (consent-gated)
├── cli.py                    # command-line entry point
├── tests/                    # 189 tests (unit, fuzz, property, anti-hallucination)
│   └── fixtures/             #   adapter fixtures, sample inputs
├── tools/                    # maintenance scripts (SBOM, API docs, profiling)
├── samples/                  # example configs (target, schema, MCP manifest, arch)
├── plugins_example/          # a working example plugin
├── benchmark/                # detector corpus (Experimental)
├── integrations/             # CI / platform integration helpers
├── docs/                     # this documentation
│   ├── guide/                #   the original guide set (User/Operator/Admin/…)
│   ├── examples/             #   before/after reports, example views
│   ├── reports/              #   engineering reports (perf, tech debt, release checklist)
│   └── api/                  #   generated API docs (pydoc)
├── pyproject.toml            # package metadata, extras, entry points
├── README.md                 # project overview
├── LICENSE                   # Apache-2.0
├── SECURITY.md               # vulnerability disclosure policy
├── CHANGELOG.md              # release history
├── CONTRIBUTING.md           # contribution guide
└── VERSIONING.md             # semantic-versioning policy
```

## How the project is organized

- **`glasscage/` is the whole product.** Everything else supports, tests, documents, or
  packages it.
- **`glasscage/aakg/` is the heart.** The graph is built once and every analysis and
  report queries it. Nothing outside `aakg/` recomputes findings.
- **Acquisition vs analysis vs reporting are separated.** Probes/targets acquire
  evidence; `aakg/` analysis modules derive conclusions; renderers
  (`narrative`/`story`/`views`/`report`) only read.
- **Cross-cutting concerns are single-authority modules** (`evidence_confidence`,
  `redaction`, `stats`, `taxonomy`) so behaviour cannot drift between subsystems.
- **Tests mirror the package** and include fuzz, property-based, and anti-hallucination
  suites, not just unit tests.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the data flow and design invariants.
