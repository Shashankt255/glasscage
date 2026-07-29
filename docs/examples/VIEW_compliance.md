### Compliance View

_Control failures and framework mappings, taken from graph mappings only._

**Control failures observed**  [Demonstrated]
- **VIOLATION:** Untrusted-influenced get_secret reaches TRUSTED Secrets via get_secret (demonstrated) with no mitigating control
- **VIOLATION:** Untrusted-influenced run_sql reaches TRUSTED Filesystem via run_sql (demonstrated) with no mitigating control
- **VIOLATION:** Untrusted-influenced search_docs reaches TRUSTED Database via search_docs (hypothesized) with no mitigating control
- **VIOLATION:** Untrusted-influenced send_email reaches TRUSTED Database via send_email (demonstrated) with no mitigating control
- **Excessive privilege:** model reaches Database via search_docs, Database via send_email, Filesystem via run_sql, Secrets via get_secret
- **Excessive privilege:** planner reaches Database via search_docs, Database via send_email, Filesystem via run_sql, Secrets via get_secret

**Framework mappings**  [Demonstrated]
- OWASP LLM: LLM01, LLM02, LLM03, LLM05, LLM06, LLM08, LLM09, LLM10
- MITRE ATLAS: AML.T0020, AML.T0029, AML.T0051, AML.T0051.000, AML.T0053, AML.T0054, AML.T0057, AML.T0070, AML.T0080
- CWE: CWE-1357, CWE-1426, CWE-1427, CWE-200, CWE-250, CWE-284, CWE-400, CWE-79
- CAPEC: CAPEC-118, CAPEC-121, CAPEC-122, CAPEC-125, CAPEC-248, CAPEC-437, CAPEC-63
- NIST AI RMF: GOVERN-1.1, MAP-4.1, MEASURE-2.3, MEASURE-2.6, MEASURE-2.7, MEASURE-2.9

**Residual compliance gaps**  [Estimated]
- Attack paths in the graph: **4**; paths NOT addressed by the mitigations above: **0**.
- Indicative Risk Index before remediation: 88.2/100 (uncalibrated heuristic).
- Residual risk after remediation is **not computed as a number**: GLASSCAGE has no calibration data to support such a claim. Re-run the assessment after fixes to observe the change.