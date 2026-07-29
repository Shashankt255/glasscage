# Security Policy

## Scope
GLASSCAGE is an offensive security assessment tool. Only run it against systems you
own or are explicitly authorized to test. `--authorized` is required for live targets.

## Handling of sensitive data (important)
- By default GLASSCAGE **redacts secret-shaped content** from all written artifacts
  (reports, JSON, HAR, evidence). See `docs/THREAT_MODEL.md`.
- Unredacted evidence is only written with the explicit `--store-raw` consent flag.
- `--encrypt-evidence` encrypts the evidence directory at rest (requires the
  `cryptography` package; there is no `crypto` extra in rc3 — run `pip install
  cryptography`). No homemade cipher is provided.
- Chain of custody: original evidence hashes are computed before redaction.

## Reporting a vulnerability
> **RELEASE BLOCKER:** the address below is a PLACEHOLDER and MUST be replaced with a
> monitored security contact before any public release. Shipping a disclosure policy
> with a non-working address is worse than shipping none.

**Report privately via GitHub Security Advisory** — the "Report a vulnerability"
button under the repository's Security tab. This is the primary, always-available
channel and needs no email setup.

If the maintainers publish a dedicated security email, it will be listed here; until
then use the Security Advisory flow. Please do not file public issues for
vulnerabilities.
- Target response: acknowledge within 5 business days.
- Coordinated disclosure: up to 90 days; we credit reporters unless anonymity is
  requested.

## Supported versions
Pre-1.0 (release candidates): only the latest RC receives fixes. Post-1.0: latest
minor of the current major.

## Plugin trust model
Plugins execute as arbitrary Python with the host's privileges. They load ONLY with
`--allow-plugins`. Load only plugins you trust. There is no sandbox.
