# Publishing the Documentation to GitHub

Step-by-step instructions for taking the generated documentation and committing it to
the GLASSCAGE repository.

## 1. Which files were generated

The documentation set under `docs/` (all Markdown, no placeholders, cross-referenced):

| File | Part it satisfies |
|---|---|
| `docs/README.md` | documentation index |
| `docs/INSTALL.md` | Part 3 — installation (Windows/Linux/macOS, extras, verification) |
| `docs/QUICKSTART.md` | quickstart |
| `docs/FIRST_RUN.md` | Part 4 — beginner first-run walkthrough |
| `docs/USER_GUIDE.md` | concepts, maturity matrix, known limitations |
| `docs/COMMAND_REFERENCE.md` | Part 5 — every CLI option |
| `docs/REPORT_GUIDE.md` | Part 6 — report interpretation |
| `docs/ASSESSMENT_WORKFLOW.md` | Part 7 — end-to-end workflow |
| `docs/ADMIN_GUIDE.md` | Part 8 — administration |
| `docs/DEVELOPER_GUIDE.md` | Part 9 — developer guide |
| `docs/PLUGIN_GUIDE.md` | plugin authoring |
| `docs/ARCHITECTURE.md` | architecture (descriptive) |
| `docs/REPOSITORY.md` | Part 2 — repository structure |
| `docs/NARRATIVES.md` | attack narratives & story |
| `docs/THREAT_MODEL.md` | threat model of the tool |
| `docs/VALIDATION.md` | Part 12 — validation & comparison |
| `docs/TUTORIALS.md` | Part 11 — tutorials |
| `docs/TROUBLESHOOTING.md` | Part 10 — troubleshooting |
| `docs/FAQ.md` | FAQ |
| `docs/ROADMAP.md` | what is not implemented |
| `docs/CHANGELOG.md` | release history |
| `docs/CONTRIBUTING.md` | contribution guide |
| `docs/EVIDENCE_CONFIDENCE.md`, `docs/GRAPH_MODEL.md`, `docs/PLUGIN_SDK.md` | supporting references |
| `docs/examples/`, `docs/reports/` | example reports and engineering reports |

## 2. How to download them from Claude

The documentation was written into the project's `docs/` directory and packaged. To
retrieve it:

- **If you received `glasscage.zip`** (the packaged project): download it from the chat's
  file panel, then unzip — the docs are under `glasscage/docs/`.
- **If individual files were presented:** download each from the file panel in the chat.
- **To download the whole updated project:** grab the presented `glasscage.zip` and
  extract it locally:

```bash
unzip glasscage.zip -d glasscage-download
ls glasscage-download/glasscage/docs
```

## 3. Where each file goes in the repository

Everything belongs under `docs/` at the repository root, preserving the structure shown
in §1. If you are merging into an existing checkout:

```bash
# from your local GLASSCAGE repo root
cp -r glasscage-download/glasscage/docs/* docs/
```

Do **not** place documentation elsewhere; the cross-references assume all files live in
`docs/` (with `docs/examples/` and `docs/reports/` subdirectories).

## 4. Commit and push

```bash
cd /path/to/your/glasscage           # repository root
git checkout -b docs/finalize-rc3    # a feature branch

git add docs/
git status                           # review what will be committed

git commit -m "docs: production documentation for 1.0.0rc3

- install/quickstart/first-run, command reference, report guide
- assessment workflow, admin, developer, plugin, architecture guides
- validation, troubleshooting, FAQ, roadmap, repository structure
- reflects implemented functionality only; limitations documented"

git push -u origin docs/finalize-rc3
```

Then open a pull request on GitHub from `docs/finalize-rc3` into your default branch.

> **Do not commit assessment artifacts.** Ensure `.gitignore` excludes generated output
> (`*_evidence/`, `*.har`, engagement `*.json`/`*.md`/`*.html`, `*.sarif`). Only the
> documentation under `docs/` should be in this commit.

## 5. Verify the documentation locally

### Render the Markdown
- **VS Code:** open any `.md` and press `Ctrl/Cmd+Shift+V` for a preview.
- **GitHub CLI:** `gh markdown-preview docs/README.md` (if installed).
- **grip (GitHub-style):** `pip install grip && grip docs/README.md` → open the local URL.

### Check internal links resolve
```bash
python - << 'PY'
import os, re, glob
broken = []
for f in glob.glob("docs/**/*.md", recursive=True):
    d = os.path.dirname(f)
    for m in re.finditer(r'\[[^\]]+\]\(([^)]+\.md)(#[^)]*)?\)', open(f, encoding='utf-8').read()):
        link = m.group(1)
        if link.startswith(('http://', 'https://')):
            continue
        if not os.path.exists(os.path.normpath(os.path.join(d, link))):
            broken.append((f, link))
print("all internal links resolve" if not broken else f"BROKEN: {broken}")
PY
```

### Confirm the examples actually run
Every command in `QUICKSTART.md`, `FIRST_RUN.md`, and `TUTORIALS.md` was executed
against rc3. Re-verify the core ones:

```bash
python -m glasscage --demo --out /tmp/verify
python -m glasscage --harness --schema samples/function_schema.json --views all --out /tmp/verify2
python -m glasscage --validate-adapters --out /tmp/verify3   # expect "Genuine-validated: 0"
python -m unittest discover -s tests -q                      # expect "Ran 189 tests ... OK"
```

### Optional: a link/lint pass in CI
Add a docs job that runs the link-check snippet above and fails on broken links, so
documentation stays consistent as the project evolves.

## 6. After merge

- Tag the docs with the release if you cut one: `git tag -a v1.0.0rc3-docs -m "..."`.
- Point the project `README.md` at `docs/README.md`.
- If you publish a docs site (e.g. MkDocs/GitHub Pages), `docs/README.md` is the natural
  index; the file names map directly to nav entries.
