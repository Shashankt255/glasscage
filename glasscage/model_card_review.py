# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Model card and deployment configuration review.

Assesses data poisoning, supply chain, and safety alignment risks from model
provenance metadata supplied by the engineer. This is assessed input, clearly
labelled as such — not something GLASSCAGE can probe black-box.
"""

from __future__ import annotations

from .models import Finding, Severity, Status

TRUSTED_PROVIDERS = frozenset({
    "openai", "anthropic", "google", "meta", "mistral", "cohere", "microsoft",
})

_PROBE = "model-card-review"
_CATEGORY = "Model Provenance / Data Poisoning"


def _val(card: dict, key: str) -> str:
    raw = card.get(key)
    if raw is None:
        return "unknown"
    if isinstance(raw, bool):
        return "yes" if raw else "no"
    return str(raw).strip().lower()


def template() -> dict:
    """A blank model card the engineer fills in."""
    return {
        "model_name": "",
        "model_provider": "",
        "model_source": "api",
        "fine_tuned": False,
        "fine_tune_dataset": None,
        "fine_tune_source": None,
        "rlhf_applied": "unknown",
        "training_data_reviewed": "unknown",
        "deployment": "cloud",
        "access_level": "internal",
        "pii_in_training": "unknown",
        "model_pinned_version": "unknown",
    }


def analyze(card: dict) -> list[Finding]:
    """Run all provenance checks against the model card."""
    findings: list[Finding] = []

    provider = _val(card, "model_provider")
    source = _val(card, "model_source")
    fine_tuned = _val(card, "fine_tuned")
    ft_source = _val(card, "fine_tune_source")
    rlhf = _val(card, "rlhf_applied")
    data_reviewed = _val(card, "training_data_reviewed")
    pii = _val(card, "pii_in_training")
    pinned = _val(card, "model_pinned_version")
    access = _val(card, "access_level")
    model_name = card.get("model_name") or "unknown"

    def _add(check_id, owasp, status, severity, title, fix):
        f = Finding(
            probe_name=_PROBE, owasp_id=owasp, title=title,
            category=_CATEGORY, status=status, severity=severity,
            confidence=0.9, dimension="informational",
            prompt=f"(model-card) {check_id}",
            response_excerpt=f"model: {model_name}, provider: {provider}",
            source_rule_id=check_id,
        )
        if status is not Status.PASSED:
            f.remediation = [fix]
        findings.append(f)

    # 1. Untrusted model source
    if provider in TRUSTED_PROVIDERS or source in ("api",):
        _add("untrusted_model_source", "LLM03", Status.PASSED, Severity.INFO,
             f"Model provider ({provider}) is a known trusted source", "")
    elif provider in ("unknown", "") and source in ("unknown", ""):
        _add("untrusted_model_source", "LLM03", Status.INCONCLUSIVE, Severity.LOW,
             "Model provider and source not specified in model card",
             "Document the model provider and source; verify provenance before deployment.")
    else:
        _add("untrusted_model_source", "LLM03", Status.VULNERABLE, Severity.MEDIUM,
             f"Model sourced from unverified provider ({provider})",
             "Verify model provenance and integrity; prefer models from established providers "
             "with published safety evaluations; maintain an AI-BOM.")

    # 2. Unverified fine-tuning
    if fine_tuned == "yes":
        if ft_source not in ("unknown", ""):
            _add("unverified_fine_tuning", "LLM04", Status.PASSED, Severity.INFO,
                 f"Fine-tuning source documented ({ft_source})", "")
        else:
            _add("unverified_fine_tuning", "LLM04", Status.VULNERABLE, Severity.HIGH,
                 "Model is fine-tuned but the training data source is undocumented",
                 "Document and audit fine-tuning data sources; verify they are free of "
                 "poisoned or adversarial samples; maintain data lineage records.")
    else:
        _add("unverified_fine_tuning", "LLM04", Status.PASSED, Severity.INFO,
             "Model is not fine-tuned (base model from provider)", "")

    # 3. No RLHF / safety alignment
    if rlhf == "yes":
        _add("no_safety_alignment", "LLM04", Status.PASSED, Severity.INFO,
             "RLHF or equivalent safety alignment has been applied", "")
    elif rlhf == "no":
        _add("no_safety_alignment", "LLM04", Status.VULNERABLE, Severity.MEDIUM,
             "No RLHF or safety alignment applied to this model",
             "Apply RLHF, DPO, or equivalent alignment training; deploy guardrails "
             "and output filters as compensating controls.")
    else:
        _add("no_safety_alignment", "LLM04", Status.INCONCLUSIVE, Severity.LOW,
             "Safety alignment status unknown — verify with model provider",
             "Confirm whether RLHF or equivalent alignment was applied; document the result.")

    # 4. Training data not reviewed
    if data_reviewed == "yes":
        _add("training_data_unreviewed", "LLM04", Status.PASSED, Severity.INFO,
             "Training data has been reviewed for quality and safety", "")
    elif data_reviewed == "no":
        _add("training_data_unreviewed", "LLM04", Status.VULNERABLE, Severity.MEDIUM,
             "Training data has not been reviewed for poisoning or quality issues",
             "Audit training data for adversarial samples, bias, and poisoning vectors; "
             "implement data validation pipelines before fine-tuning.")
    else:
        _add("training_data_unreviewed", "LLM04", Status.INCONCLUSIVE, Severity.LOW,
             "Training data review status unknown",
             "Confirm whether training data has been audited; document the review process.")

    # 5. PII in training data
    if pii == "no":
        _add("pii_in_training", "LLM02", Status.PASSED, Severity.INFO,
             "No PII reported in training data", "")
    elif pii == "yes":
        _add("pii_in_training", "LLM02", Status.VULNERABLE, Severity.MEDIUM,
             "Training data contains or may contain PII",
             "Scrub PII from training data; implement differential privacy during training; "
             "add output filters to detect and redact PII in responses.")
    else:
        _add("pii_in_training", "LLM02", Status.INCONCLUSIVE, Severity.LOW,
             "PII status of training data is unknown",
             "Audit training data for PII; document the result and apply scrubbing if found.")

    # 6. Model version not pinned
    if pinned == "yes":
        _add("model_version_unpinned", "LLM03", Status.PASSED, Severity.INFO,
             "Model version is pinned to a specific release", "")
    elif pinned == "no":
        _add("model_version_unpinned", "LLM03", Status.VULNERABLE, Severity.MEDIUM,
             "Model version is not pinned — provider updates may change behavior silently",
             "Pin the model to a specific version or snapshot; test before upgrading; "
             "monitor for behavioral drift after provider-side updates.")
    else:
        _add("model_version_unpinned", "LLM03", Status.INCONCLUSIVE, Severity.LOW,
             "Model version pinning status unknown",
             "Verify whether the deployment uses a pinned model version.")

    # 7. Public deployment without safety alignment
    if access == "public" and rlhf == "no":
        _add("public_unaligned_deployment", "LLM04", Status.VULNERABLE, Severity.HIGH,
             "Model is deployed publicly without safety alignment",
             "Do not deploy unaligned models to public-facing endpoints; apply RLHF/DPO "
             "or restrict access to internal users with monitoring.")
    elif access == "public":
        _add("public_unaligned_deployment", "LLM04", Status.PASSED, Severity.INFO,
             "Public deployment has safety alignment in place", "")
    else:
        _add("public_unaligned_deployment", "LLM04", Status.PASSED, Severity.INFO,
             f"Deployment access is restricted ({access})", "")

    return findings


def summary(findings: list[Finding]) -> dict:
    """Summary stats for the report."""
    mc = [f for f in findings if f.probe_name == _PROBE]
    flagged = sum(1 for f in mc if f.status is Status.VULNERABLE)
    unknown = sum(1 for f in mc if f.status is Status.INCONCLUSIVE)
    clear = sum(1 for f in mc if f.status is Status.PASSED)
    return {"checks_total": len(mc), "clear": clear,
            "flagged": flagged, "unverified": unknown}
