# GLASSCAGE v1.0.0rc4 -- Platform Security Assessment Report

**Agent:** 3 -- Security and Adversarial Tester
**Date:** 2026-11-05
**Scope:** GLASSCAGE platform internals (not the targets it assesses)
**Methodology:** Code review + automated test scripts (`/tmp/agent3/test_s*.py`)

---

## Executive Summary

23 test areas examined across input validation, filesystem, network, report output, and execution security. GLASSCAGE demonstrates strong security fundamentals (no eval/exec, no subprocess, proper html.escape in SVG/HTML, SHA-256 chain-of-custody, consent-gated plugins). However, several gaps exist in input validation and network-level controls that could be exploited in specific deployment scenarios.

| Severity     | Count | Finding IDs |
|--------------|-------|-------------|
| Critical     | 0     | -- |
| High         | 1     | S11 |
| Medium       | 3     | S02, S12, S18 |
| Low          | 4     | S03, S04, S06, S14 |
| Informational| 6     | S05, S07, S08, S10, S16, S17 |
| Pass         | 9     | S01, S09, S13, S15, S17, S19, S20, S21, S22 |

---

## Findings

---

### S01 -- Malformed URL Schemes
**Severity:** Pass
**Affected component:** `glasscage/config.py:30-31`
**Status:** No issue found.

Config validation correctly rejects `javascript:`, `file://`, `data:`, `ftp://`, `gopher://`, `dict://`, and `ldap://` schemes. Only `http://`, `https://`, `harness://`, and `mock://` are accepted.

**Evidence:** All 7 malicious schemes rejected with `ConfigError`.

---

### S02 -- CRLF Injection in Header Values
**Finding ID:** S02
**Severity:** Medium
**Affected component:** `glasscage/config.py:33-38` (header validation)
**Preconditions:** Attacker controls or influences the target config JSON.

**Description:**
`validate_target_config()` checks that `headers` is a `dict` but does not validate header values for CRLF characters (`\r\n`). A config with `{"X-Test": "value\r\nX-Injected: true"}` passes validation and is forwarded to `urllib.request.Request`, which could result in HTTP response splitting or header injection.

**Reproduction steps:**
```python
from glasscage.config import validate_target_config
cfg = validate_target_config({
    "url": "http://target.example",
    "headers": {"X-Test": "value\r\nX-Injected: true"}
})
# Returns successfully -- CRLF in header value not rejected
```

**Actual impact:** HTTP header injection. An attacker who controls the config file could inject arbitrary HTTP headers into requests sent to the target. Modern Python (3.x) `http.client` blocks raw `\r\n` in header values at the socket layer, which mitigates exploitation, but the validation layer should reject these inputs early.

**Evidence:** All 3 CRLF payloads accepted by `validate_target_config()`.

**Recommended remediation:**
Add header value validation in `config.py`:
```python
for k, v in cfg.get("headers", {}).items():
    if not isinstance(v, str):
        raise ConfigError(f"header '{k}' value must be a string")
    if "\r" in v or "\n" in v:
        raise ConfigError(f"header '{k}' contains illegal CR/LF characters")
```

---

### S03 -- No Length Limits on Config Values
**Finding ID:** S03
**Severity:** Low
**Affected component:** `glasscage/config.py:22-42`
**Preconditions:** Attacker controls or influences the target config JSON.

**Description:**
No maximum length is enforced on URL, header names, or header values. A 1MB URL, 1MB header name, and 1MB header value are all accepted without error. This could lead to memory exhaustion or denial-of-service when constructing HTTP requests.

**Reproduction steps:**
```python
from glasscage.config import validate_target_config
# All pass validation:
validate_target_config({"url": "http://x/" + "A" * 1048576})
validate_target_config({"url": "http://x", "headers": {"X-Test": "A" * 1048576}})
```

**Actual impact:** Low. A self-DoS scenario -- the user controls their own config. However, in automated pipelines where configs are generated, this could cause resource exhaustion.

**Recommended remediation:**
Add reasonable upper bounds: URL < 8192 bytes, header name < 256 bytes, header value < 8192 bytes.

---

### S04 -- Null Bytes in Config Strings
**Finding ID:** S04
**Severity:** Low
**Affected component:** `glasscage/config.py:22-42`
**Preconditions:** Attacker controls or influences the target config JSON.

**Description:**
Null bytes (`\x00`) in URL, header values, and name fields pass through config validation without sanitization. Null bytes can cause string truncation in C-based libraries and may lead to path truncation or request smuggling in certain HTTP implementations.

**Reproduction steps:**
```python
from glasscage.config import validate_target_config
cfg = validate_target_config({"url": "http://test.example/\x00evil"})
assert "\x00" in cfg["url"]  # passes -- null byte not stripped
```

**Actual impact:** Low. Python's `urllib` handles null bytes safely in most cases, but the config should reject them as a defense-in-depth measure.

**Recommended remediation:**
Reject strings containing null bytes:
```python
if "\x00" in url:
    raise ConfigError("target 'url' contains null byte")
```

---

### S05 -- Unicode Edge Cases Not Normalized
**Finding ID:** S05
**Severity:** Informational
**Affected component:** `glasscage/config.py:22-42`
**Preconditions:** Attacker controls config JSON.

**Description:**
RTL override characters (`U+202E`), zero-width joiners (`U+200D`), zero-width spaces (`U+200B`), Bidi overrides, and homograph characters in URL and name fields are accepted without normalization. While unlikely to cause direct exploitation, these can cause visual spoofing in logs and reports.

**Actual impact:** Visual spoofing only. The target name and URL could appear misleading in the assessment report.

**Recommended remediation:**
Strip Unicode control characters from config string values, or at minimum strip Bidi control characters (`U+200B-U+200F`, `U+202A-U+202E`, `U+2066-U+2069`).

---

### S06 -- Path Traversal in --out Parameter
**Finding ID:** S06
**Severity:** Low
**Affected component:** `cli.py:488-561` (30+ `open()` calls using `f"{args.out}"`)
**Preconditions:** User runs GLASSCAGE CLI with a malicious `--out` value.

**Description:**
The `--out` parameter is used directly in f-string path constructions without canonicalization. A value like `--out ../../tmp/evil` would write report files to `/tmp/evil.md`, `/tmp/evil.html`, etc. While the user controls `--out` directly (reducing risk), in automated CI/CD pipelines where the value comes from untrusted input, this could write files to unintended locations.

**Affected lines in `cli.py`:**
- Line 488: `f"{args.out}.md"`
- Line 490: `f"{args.out}.html"`
- Line 492: `f"{args.out}.json"`
- Line 455: `f"{args.out}_evidence"`
- Plus ~20 more similar patterns.

**Actual impact:** Low. The user themselves provide `--out`. Risk increases in automated pipelines.

**Recommended remediation:**
Canonicalize `args.out` with `os.path.realpath()` and optionally restrict it to the current directory or a designated output directory.

---

### S07 -- Symlink Following in Evidence Directory
**Finding ID:** S07
**Severity:** Informational
**Affected component:** `glasscage/evidence.py:128-136`
**Preconditions:** An attacker can create a symlink inside the evidence output directory before GLASSCAGE writes to it.

**Description:**
`evidence.capture()` creates evidence files using `os.makedirs()` + `open()` without checking for symlinks. If the evidence directory or a file within it is a symlink, the write follows the symlink to the target location. Since the evidence directory is created by GLASSCAGE and is typically under user control, exploitation requires a race condition or pre-existing symlink.

**Actual impact:** Very low. Requires local access and a TOCTOU race.

**Recommended remediation:**
Use `os.path.realpath()` to resolve the evidence directory path before writing, and verify the resolved path is still within the intended output directory.

---

### S08 -- No Validation of --out Against Special Files
**Finding ID:** S08
**Severity:** Informational
**Affected component:** `cli.py:113` (`--out` argument)
**Preconditions:** User provides `--out` pointing to a device file path.

**Description:**
`--out=/dev/null` would attempt to write to `/dev/null.md`, `/dev/null.html`, etc. While these are not valid device files (they have extensions), `--out=/dev/stderr` or similar could cause unexpected behavior. This is a defense-in-depth concern.

**Actual impact:** Minimal. Device-like paths with appended extensions are not special files.

---

### S09 -- XSS in SVG via Probe Names/Content
**Severity:** Pass
**Affected component:** `glasscage/evidence.py:42-112`
**Status:** No issue found.

All user-controlled content in SVG evidence cards (`probe_name`, `title`, `prompt`, `response_excerpt`) is properly escaped via `html.escape()` before being inserted into SVG XML. XSS payloads including `<script>alert("xss")</script>`, `"><img src=x onerror=alert(1)>`, `javascript:alert(1)`, and `<svg onload=alert(1)>` were all correctly neutralized.

**Evidence:** 5/5 XSS payloads properly escaped in SVG output.

---

### S10 -- Plugin System Lacks Sandboxing
**Finding ID:** S10
**Severity:** Informational (by design -- documented and consent-gated)
**Affected component:** `glasscage/plugins.py:43-82`
**Preconditions:** User runs `--plugins <dir> --allow-plugins`.

**Description:**
Plugin modules execute with full Python interpreter privileges via `importlib.util.exec_module()`. There is no sandboxing, no restricted imports, no AST inspection, no resource limits, no network isolation, and no filesystem confinement. A malicious plugin could read/write any file, make network requests, execute system commands, or modify GLASSCAGE internals.

**Mitigating factors:**
- Loading plugins requires explicit `--allow-plugins` consent flag
- CLI prints a clear warning about arbitrary code execution
- Plugin API version is checked (major mismatch refused)
- Probe attributes (name, owasp_id, min_tier) are validated after loading

**Actual impact:** By design. The documentation and CLI warnings are appropriate. The consent mechanism is the security control.

**Recommended remediation:**
Consider adding an optional integrity check (e.g., hash allowlist of approved plugin files) for enterprise deployments where plugin directories may be writable by other users.

---

### S11 -- No SSRF Protection in Config Validation
**Finding ID:** S11
**Severity:** High
**Affected component:** `glasscage/config.py:30-31` and `glasscage/target.py:132`
**Preconditions:** Attacker controls or influences the target URL; GLASSCAGE runs in a cloud environment with metadata endpoints accessible.

**Description:**
`validate_target_config()` only validates the URL scheme (`http://` or `https://`) but does not block requests to internal/private IP ranges or cloud metadata endpoints. The following URLs all pass validation and would be requested by `HTTPChatTarget.send()`:

- `http://127.0.0.1:8080/admin` (localhost)
- `http://[::1]:8080/admin` (localhost IPv6)
- `http://169.254.169.254/latest/meta-data/` (AWS metadata -- **credential theft**)
- `http://metadata.google.internal/` (GCP metadata)
- `http://10.0.0.1:8080/` (private network)
- `http://192.168.1.1:8080/` (private network)
- `http://0.0.0.0:8080/` (wildcard bind)

The optional `--scope` flag (`audit.Scope`) provides a hostname allowlist, but it is not required by default. Without `--scope`, GLASSCAGE will make HTTP requests to any host with an `http(s)://` URL.

**Reproduction steps:**
```python
from glasscage.config import validate_target_config
# All pass validation:
validate_target_config({"url": "http://169.254.169.254/latest/meta-data/"})
validate_target_config({"url": "http://127.0.0.1:8080/admin"})
validate_target_config({"url": "http://[::1]:8080/"})
```

**Actual impact:** High in cloud/container deployments. If GLASSCAGE is deployed as a service (API or CI/CD integration) where target URLs come from user input, an attacker could use it as an SSRF proxy to access cloud metadata endpoints and steal IAM credentials, or probe internal network services.

**Recommended remediation:**
1. Add a private IP blocklist to `config.py` URL validation. Block `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` (link-local, includes cloud metadata), `::1`, `fc00::/7`, `fe80::/10`, `0.0.0.0`.
2. Block well-known cloud metadata hostnames (`metadata.google.internal`, etc.)
3. Resolve hostnames to IP before checking (DNS rebinding defense)
4. Make `--scope` mandatory for non-demo, non-harness runs (opt-in is insufficient)

---

### S12 -- Unrestricted HTTP Redirect Following
**Finding ID:** S12
**Severity:** Medium
**Affected component:** `glasscage/target.py:137-138` (`urllib.request.urlopen`)
**Preconditions:** Target HTTP endpoint returns a redirect response.

**Description:**
`urllib.request.urlopen` follows HTTP redirects (301, 302, 303, 307, 308) by default with no limit. GLASSCAGE does not install a custom `HTTPRedirectHandler` or limit the number of redirects.

Combined with S11, this creates a redirect-based SSRF chain: a target at a valid external URL (passing scope checks) could redirect to `http://169.254.169.254/latest/meta-data/`, and GLASSCAGE would follow the redirect and make the request.

**Actual impact:** Medium. Enables SSRF via redirect even if the initial URL passes scope validation.

**Recommended remediation:**
1. Install a custom `HTTPRedirectHandler` that limits redirects to N (e.g., 5)
2. Re-validate redirect target URLs against the scope allowlist and private IP blocklist
3. Log redirects for audit trail visibility

---

### S13 -- SSL/TLS Verification
**Severity:** Pass
**Affected component:** `glasscage/target.py:60-71`
**Status:** Properly implemented.

SSL certificate verification is enabled by default. `CERT_NONE` is only applied when both `--proxy` and `--proxy-no-verify` flags are set (for Burp Suite integration). Non-proxied requests use `urllib.request.urlopen`'s default context, which verifies certificates.

---

### S14 -- No Maximum Timeout Enforced
**Finding ID:** S14
**Severity:** Low
**Affected component:** `glasscage/config.py:39-41`
**Preconditions:** Attacker influences timeout configuration.

**Description:**
Timeout validation checks that the value is positive but enforces no upper bound. A timeout of 999,999 seconds (~11.5 days) is accepted. While the user controls their own config, in automated pipelines this could cause a process to hang indefinitely on a non-responsive target.

**Reproduction steps:**
```python
from glasscage.config import validate_target_config
validate_target_config({"url": "http://x", "timeout": 999999})  # accepted
```

**Actual impact:** Low. Self-DoS scenario.

**Recommended remediation:**
Enforce a maximum timeout (e.g., 300 seconds) or warn when timeout exceeds a reasonable threshold.

---

### S15 -- Scope Enforcement Edge Cases
**Severity:** Pass
**Affected component:** `glasscage/audit.py:181-194`
**Status:** Well-implemented.

Scope enforcement correctly handles:
- Case-insensitive hostname matching
- Subdomain blocking (no wildcard matching)
- Suffix-based bypass attempts
- Port variations (allowed -- correct, as scope is host-based)
- Userinfo (`user@host`) bypass attempts (correctly blocked)
- IP-based scope entries

Empty/None scope allows all hosts by design (falls back to `--authorized` honor system).

---

### S16 -- HTML Report XSS via Evidence SVG
**Finding ID:** S16
**Severity:** Informational
**Affected component:** `glasscage/report.py:431` (JavaScript in HTML template)

**Description:**
The HTML report inserts `evidence_svg` content directly via JavaScript string concatenation into `innerHTML`:
```javascript
if(f.evidence_svg) panes.push(["Evidence",'<div class="ev">'+f.evidence_svg+'</div>']);
```

This bypasses the `esc()` function used for other fields. However, `evidence.py`'s `render_svg()` applies `html.escape()` to all user-controlled content (probe name, title, prompt, response text) before embedding it in the SVG XML. Testing confirms all 5 XSS payload types are properly escaped upstream.

**Actual impact:** Informational. The upstream escaping in `evidence.py` makes this safe in practice, but the architectural pattern (raw innerHTML insertion) is fragile. If a future code change adds content to the SVG without escaping, XSS would result.

**Recommended remediation:**
Consider using `esc()` or DOM APIs (`textContent`, `createElementNS`) instead of raw innerHTML for evidence SVG insertion, for defense in depth.

---

### S17 -- Evidence Hash Algorithm Verification
**Severity:** Pass
**Affected component:** `glasscage/audit.py:36-39`
**Status:** Correctly uses SHA-256.

- `hashlib.sha256()` is used for both evidence hashes and audit chain hashes
- Hash output is 64 hex characters (256 bits) as expected
- Audit chain uses canonical serialization with length-prefixed fields (ADR 0019)
- Redaction tokens use 8-character SHA-256 prefix (~32-bit collision space)

**Note:** The 8-char redaction token has a birthday-bound collision probability of ~50% at 2^16 secrets. This is acceptable for the correlation use case (not a security control).

---

### S18 -- Incomplete Secret Redaction Patterns
**Finding ID:** S18
**Severity:** Medium
**Affected component:** `glasscage/probes.py:260-265` (`SECRET_PATTERNS`)
**Preconditions:** Target leaks secrets in formats not covered by the 4 patterns.

**Description:**
`SECRET_PATTERNS` contains only 4 regex patterns:
1. `sk-[A-Za-z0-9]{16,}` -- generic API key shape
2. `AKIA[0-9A-Z]{12,}` -- AWS access key ID
3. `-----BEGIN [A-Z ]*PRIVATE KEY-----` -- PEM private keys
4. `(?i)password\s*[:=]\s*\S+` -- password assignments

The following common secret formats are **NOT detected**:

| Secret Type | Example | Detected? |
|---|---|---|
| GitHub PAT (ghp_) | `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12` | No |
| GitHub PAT (github_pat_) | `github_pat_ABCDEFGHIJKLMNOP_QRST...` | No |
| JWT | `eyJhbGciOi...` (3-part base64) | No |
| AWS Secret Key | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | No |
| Slack Token | `xoxb-1234567890-...` | No |
| Azure Storage Key | `DefaultEndpointsProtocol=...AccountKey=...` | No |
| Bearer Token | `Authorization: Bearer ...` | No |
| Google API Key | `AIzaSy...` | No |
| Anthropic API Key | `sk-ant-api03-...` (hyphens break `sk-[A-Za-z0-9]{16,}`) | **No** |

The Anthropic key format `sk-ant-api03-XXXX...` is specifically notable because GLASSCAGE is built for AI security assessment and Anthropic keys are common in that context. The hyphens in `sk-ant-` break the `sk-[A-Za-z0-9]{16,}` pattern which requires 16+ contiguous alphanumeric characters after `sk-`.

**Evidence:**
```python
from glasscage.redaction import redact_text
redact_text("sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
# Returns: ('sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ', 0)  -- NOT redacted
```

**Actual impact:** Medium. Secrets in unrecognized formats will appear in cleartext in reports, evidence SVGs, HAR exports, and JSON output even when `--store-raw` is not set. This turns the assessment artifact into a secondary breach vector (the exact scenario `redaction.py`'s docstring warns about).

**Recommended remediation:**
Expand `SECRET_PATTERNS` to cover at minimum:
```python
SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),           # generic API key (allow hyphens/underscores)
    re.compile(r"AKIA[0-9A-Z]{12,}"),                # AWS access key id
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),# PEM private keys
    re.compile(r"(?i)password\s*[:=]\s*\S+"),         # password assignments
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),              # GitHub PAT
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),      # GitHub fine-grained PAT
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),      # Slack tokens
    re.compile(r"AIzaSy[A-Za-z0-9_-]{33}"),            # Google API keys
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),  # JWT
    re.compile(r"(?i)bearer\s+[A-Za-z0-9_.-]{20,}"),  # Bearer tokens
]
```

---

### S19 -- JSON Report Information Content
**Severity:** Pass (by design)
**Affected component:** `glasscage/report.py:294-319`
**Status:** Appropriate gating.

- `evidence_svg` is stripped from JSON reports (line 305)
- Prompts and response excerpts are included (necessary for reproduction)
- `--store-raw` properly gates unredacted content (engine.py:362)
- HTML report embeds full DATA JSON -- this is by design for interactivity

**Note:** `evidence_path` in reports may leak local filesystem paths. This is informational and expected for a local tool.

---

### S20 -- --store-raw Flag Gating
**Severity:** Pass
**Affected component:** `glasscage/engine.py:56,75,361-364`
**Status:** Correctly implemented.

- Redaction runs by default (`store_raw=False`)
- `redact_all()` is called before evidence capture and report generation
- HAR export also respects the `store_raw` flag (cli.py:517-518)
- Evidence SVGs are generated after redaction (correct ordering)

---

### S21 -- No Subprocess/os.system Usage
**Severity:** Pass
**Affected component:** Entire `glasscage/` package
**Status:** Clean.

No `subprocess`, `os.system`, `os.popen`, or `os.exec*` calls found in any source file under `glasscage/`. The one mention of `eval()` in `glasscage/remediation.py:30` is a string in remediation advice text, not an actual call.

---

### S22 -- No eval/exec Usage
**Severity:** Pass
**Affected component:** Entire `glasscage/` package
**Status:** Clean.

No `eval()` or `exec()` calls found. `importlib` is used in `plugins.py` (documented, consent-gated) and `adapters/external.py` (for loading adapter modules).

---

### S23 -- Plugin System Informed Consent
**Severity:** Informational (addressed by design)
**Affected component:** `glasscage/plugins.py`, `cli.py:281-291`

The plugin system provides no runtime sandboxing. This is documented and the risk is mitigated by:
1. Requiring explicit `--allow-plugins` CLI flag
2. Printing a clear warning about arbitrary code execution (cli.py:287)
3. Checking plugin API major version compatibility
4. Validating required probe attributes after loading

The threat model (arbitrary file/network/system access by plugin code) is acknowledged in the module docstring ("Load only trusted plugins").

---

## Summary of Actionable Recommendations

### Priority 1 (Should fix before GA)
1. **S11 -- SSRF protection:** Add private IP blocklist to `config.py` URL validation. Block `127.0.0.0/8`, `10.0.0.0/8`, `169.254.0.0/16`, `::1`, `fc00::/7`, etc.
2. **S18 -- Secret pattern coverage:** Expand `SECRET_PATTERNS` to cover Anthropic keys (`sk-ant-*`), GitHub PATs, JWTs, Slack tokens, and Bearer tokens.
3. **S12 -- Redirect following:** Install a custom redirect handler that re-validates redirect targets against scope and private IP blocklist.

### Priority 2 (Should fix soon)
4. **S02 -- CRLF in headers:** Reject `\r` and `\n` in header values during config validation.
5. **S04 -- Null bytes:** Reject null bytes in URL, headers, and name fields.

### Priority 3 (Nice to have)
6. **S03 -- Length limits:** Add maximum length validation for URL (8KB) and headers (8KB).
7. **S14 -- Max timeout:** Cap timeout at 300 seconds.
8. **S06 -- Path canonicalization:** Use `os.path.realpath()` on `--out`.
9. **S05 -- Unicode normalization:** Strip Bidi control characters.
10. **S16 -- SVG innerHTML:** Use DOM APIs instead of raw innerHTML for defense in depth.

---

## Test Artifacts

All test scripts are located at `/tmp/agent3/`:
- `test_s01_s05_input_security.py` -- Input validation tests
- `test_s06_s10_filesystem.py` -- Filesystem security tests
- `test_s11_s15_network.py` -- Network security code review tests
- `test_s16_s20_report.py` -- Report/output security tests
- `test_s21_s23_execution.py` -- Execution security tests

To reproduce: `cd /home/kali/glasscage && python3 /tmp/agent3/test_s<NN>.py`
