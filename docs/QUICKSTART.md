# Quickstart

Five minutes from install to your first report. No network or authorization needed for
steps 1–2 (they use built-in targets).

## 1. Smoke-test the tool (mock target, L0)

```bash
python -m glasscage --demo --out quickstart
```

This runs against a built-in **mock** target. Output files:

```
quickstart.md          # human-readable report (start here)
quickstart.html        # interactive report
quickstart.json        # machine-readable results (findings, narratives, story)
quickstart_aakg.json   # the AI Attack Knowledge Graph
quickstart_evidence/   # per-finding evidence cards (redacted)
```

Open `quickstart.md`. You will see an evidence legend, an executive summary with the
**Indicative Risk Index** (labelled `[Estimated]`), findings split into
demonstrated / hypothesized / not assessable, an Assessment Story, and Attack Narratives.

## 2. See agentic analysis work (reference harness, L2)

```bash
python -m glasscage --harness --schema samples/function_schema.json --out harness-demo
```

The built-in **reference agent** exposes planner/memory/tool traces, so agentic probes
can confirm impact and produce `demonstrated` graph edges and a demonstrated attack path.

> **Important:** the harness is a **deterministic test fixture**. It proves the
> machinery works; it says nothing about efficacy against a real model. Never present
> harness results as evidence about a real system.

## 3. Assess a real target (requires authorization)

Create `target.json`:

```json
{
  "name": "my-bot-staging",
  "url": "https://your-bot.example.com/v1/chat",
  "method": "POST",
  "headers": { "Authorization": "Bearer YOUR_TOKEN" },
  "body_template": { "messages": [ { "role": "user", "content": "{{PROMPT}}" } ] },
  "response_path": "choices.0.message.content"
}
```

Run (note `--authorized` — your assertion that you may test this system):

```bash
python -m glasscage --config target.json --authorized --views all --out engagement
```

## 4. What to do next

- Confirm every finding manually — GLASSCAGE produces hypotheses, not verdicts.
- Read the [USER_GUIDE.md](USER_GUIDE.md) core concepts (steerability vs impact, tiers,
  evidence classes).
- Read [REPORT_GUIDE.md](REPORT_GUIDE.md) before quoting any number externally.

## Next steps

| You want to… | Read |
|---|---|
| Understand the concepts | [USER_GUIDE.md](USER_GUIDE.md) |
| Learn every flag | [COMMAND_REFERENCE.md](COMMAND_REFERENCE.md) |
| Run a real engagement | [ASSESSMENT_WORKFLOW.md](ASSESSMENT_WORKFLOW.md) |
| Work through examples | [TUTORIALS.md](TUTORIALS.md) |
