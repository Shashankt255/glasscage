# First Run — A Beginner's Walkthrough

This assumes you have never used GLASSCAGE. By the end you will have run an assessment
and understood every file it produced. No prior security tooling knowledge needed.

## Step 1 — Install and verify

Follow [INSTALL.md](INSTALL.md), then confirm:

```bash
python -m glasscage --demo --out first-run
```

**Expected:** the command completes without error and prints where it wrote files.

**How to know it worked — you should have these files:**

```
first-run.md          # the report, human-readable
first-run.html        # the report, interactive
first-run.json        # everything, machine-readable
first-run_aakg.json   # the knowledge graph
first-run_evidence/   # per-finding evidence cards (redacted)
```

If those exist, GLASSCAGE works. *(Screenshot to capture: your terminal showing the
completion message and the file list from `ls first-run*`.)*

## Step 2 — Create a target

The `--demo` target is built in. To assess something real, describe it in a JSON file.
Create `target.json`:

```json
{
  "name": "my-first-target",
  "url": "https://your-endpoint.example.com/chat",
  "method": "POST",
  "headers": { "Authorization": "Bearer YOUR_TOKEN" },
  "body_template": { "messages": [ { "role": "user", "content": "{{PROMPT}}" } ] },
  "response_path": "choices.0.message.content"
}
```

- `{{PROMPT}}` is where each probe's payload is inserted.
- `response_path` is the dotted path to the assistant's text in the JSON response.
- **Tip:** curl the endpoint once by hand first, so you know the real `response_path`.

## Step 3 — Your first assessment

For learning, keep using the built-in targets (no authorization needed). Run the L2
reference agent so you see the full range of analysis:

```bash
python -m glasscage --harness --schema samples/function_schema.json \
  --views all --out first-run
```

For a **real** target you would add `--config target.json --authorized`.

**Expected:** completion, plus five `first-run_view_*.md` files (one per audience).
*(Screenshot: the terminal showing "Wrote first-run.md, …".)*

## Step 4 — Understand the generated reports

Open `first-run.md`. From top to bottom:

1. **Evidence legend** — the eight confidence classes.
2. **Executive Summary** — the Indicative Risk Index (labelled `[Estimated]`) and
   finding counts (demonstrated / hypothesized / not assessable).
3. **Assessment Story** — 13 sections reading like a pentest report.
4. **Attack Narratives** — 8 strategic readings of the graph's attack paths.
5. **Findings**, **Coverage**, **Remediation**.

**How to read it:** look at the **evidence class** on each section *before* the numbers.
See [REPORT_GUIDE.md](REPORT_GUIDE.md). *(Screenshot: the Executive Summary and the
first narrative.)*

## Step 5 — The replay bundle

Add `--replay` to make the run reproducible:

```bash
python -m glasscage --harness --replay --out first-run
```

This writes a bundle a colleague can re-execute (auth headers are stripped for safety).
It is your reproducibility evidence — archive it with the report.

## Step 6 — Narratives

In `first-run.md`, find **## Attack Narratives**. Each transition cites node ids, an
edge id, an evidence id, a confidence, and an evidence class, e.g.:

```
3. planner invokes get_secret
   - nodes `Planner:planner` -> `Tool:get_secret` · edge `...` · evidence 7f3a… · [Demonstrated]
```

If a strategy has no matching path it prints **"Not demonstrated."** — GLASSCAGE will
not invent one. See [NARRATIVES.md](NARRATIVES.md).

## Step 7 — The HTML report

Open `first-run.html` in a browser. It is self-contained (no internet needed). You get
the same content as the markdown plus an interactive graph. *(Screenshot: the HTML
report with the graph visible.)*

## Step 8 — The JSON report

```bash
python -c "import json; d=json.load(open('first-run.json')); print(sorted(d.keys()))"
# -> ['findings', 'narratives', 'recon', 'story', 'summary', 'target']
```

Use this for automation. It contains findings, the full narrative models, and the story.

## Step 9 — SARIF

```bash
python -m glasscage --harness --sarif --out first-run
python -c "import json; d=json.load(open('first-run.sarif')); print(sorted(d))"
# -> ['$schema', 'runs', 'version']
```

SARIF 2.1.0 plugs into code-scanning platforms (e.g. GitHub code scanning).

## Directory structure after a full run

```
first-run.md              first-run.html          first-run.json
first-run_aakg.json       first-run.sarif         first-run_evidence/
first-run_view_executive.md   first-run_view_security.md   first-run_view_developer.md
first-run_view_incident_response.md   first-run_view_compliance.md
```

## How to know everything worked

- [ ] The command exited without an error (exit code 0).
- [ ] `.md`, `.html`, `.json`, `_aakg.json` all exist.
- [ ] `first-run.md` contains "Assessment Story" and "Attack Narratives".
- [ ] With `--views all`, five `_view_*.md` files exist.
- [ ] With `--sarif`, `first-run.sarif` parses as JSON with a `runs` key.

## Where to go next

- Concepts you skipped: [USER_GUIDE.md](USER_GUIDE.md)
- Every flag: [COMMAND_REFERENCE.md](COMMAND_REFERENCE.md)
- A real engagement: [ASSESSMENT_WORKFLOW.md](ASSESSMENT_WORKFLOW.md)
- More tutorials: [TUTORIALS.md](TUTORIALS.md)
