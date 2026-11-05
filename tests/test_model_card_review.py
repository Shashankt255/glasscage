# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Tests for model_card_review module."""

from __future__ import annotations

import json

from glasscage import model_card_review as mcr
from glasscage.models import Severity, Status


def test_template_returns_all_keys():
    t = mcr.template()
    expected = {
        "model_name", "model_provider", "model_source", "fine_tuned",
        "fine_tune_dataset", "fine_tune_source", "rlhf_applied",
        "training_data_reviewed", "deployment", "access_level",
        "pii_in_training", "model_pinned_version",
    }
    assert set(t.keys()) == expected


def test_template_is_json_serializable():
    json.dumps(mcr.template())


def test_trusted_provider_passes():
    card = mcr.template()
    card["model_provider"] = "openai"
    card["model_source"] = "api"
    findings = mcr.analyze(card)
    src_finding = [f for f in findings if f.source_rule_id == "untrusted_model_source"]
    assert len(src_finding) == 1
    assert src_finding[0].status is Status.PASSED


def test_untrusted_provider_flags():
    card = mcr.template()
    card["model_provider"] = "random-lab"
    card["model_source"] = "huggingface"
    findings = mcr.analyze(card)
    src_finding = [f for f in findings if f.source_rule_id == "untrusted_model_source"]
    assert len(src_finding) == 1
    assert src_finding[0].status is Status.VULNERABLE
    assert src_finding[0].severity is Severity.MEDIUM


def test_unknown_provider_inconclusive():
    card = mcr.template()
    card["model_provider"] = ""
    card["model_source"] = ""
    findings = mcr.analyze(card)
    src_finding = [f for f in findings if f.source_rule_id == "untrusted_model_source"]
    assert len(src_finding) == 1
    assert src_finding[0].status is Status.INCONCLUSIVE


def test_fine_tuned_undocumented_high():
    card = mcr.template()
    card["fine_tuned"] = True
    card["fine_tune_source"] = ""
    findings = mcr.analyze(card)
    ft_finding = [f for f in findings if f.source_rule_id == "unverified_fine_tuning"]
    assert len(ft_finding) == 1
    assert ft_finding[0].status is Status.VULNERABLE
    assert ft_finding[0].severity is Severity.HIGH


def test_fine_tuned_documented_passes():
    card = mcr.template()
    card["fine_tuned"] = True
    card["fine_tune_source"] = "internal-curated-v3"
    findings = mcr.analyze(card)
    ft_finding = [f for f in findings if f.source_rule_id == "unverified_fine_tuning"]
    assert len(ft_finding) == 1
    assert ft_finding[0].status is Status.PASSED


def test_not_fine_tuned_passes():
    card = mcr.template()
    card["fine_tuned"] = False
    findings = mcr.analyze(card)
    ft_finding = [f for f in findings if f.source_rule_id == "unverified_fine_tuning"]
    assert len(ft_finding) == 1
    assert ft_finding[0].status is Status.PASSED


def test_no_rlhf_flags():
    card = mcr.template()
    card["rlhf_applied"] = "no"
    findings = mcr.analyze(card)
    rlhf_finding = [f for f in findings if f.source_rule_id == "no_safety_alignment"]
    assert len(rlhf_finding) == 1
    assert rlhf_finding[0].status is Status.VULNERABLE


def test_rlhf_yes_passes():
    card = mcr.template()
    card["rlhf_applied"] = "yes"
    findings = mcr.analyze(card)
    rlhf_finding = [f for f in findings if f.source_rule_id == "no_safety_alignment"]
    assert len(rlhf_finding) == 1
    assert rlhf_finding[0].status is Status.PASSED


def test_training_data_not_reviewed():
    card = mcr.template()
    card["training_data_reviewed"] = "no"
    findings = mcr.analyze(card)
    td_finding = [f for f in findings if f.source_rule_id == "training_data_unreviewed"]
    assert len(td_finding) == 1
    assert td_finding[0].status is Status.VULNERABLE


def test_pii_in_training_flags():
    card = mcr.template()
    card["pii_in_training"] = "yes"
    findings = mcr.analyze(card)
    pii_finding = [f for f in findings if f.source_rule_id == "pii_in_training"]
    assert len(pii_finding) == 1
    assert pii_finding[0].status is Status.VULNERABLE
    assert pii_finding[0].owasp_id == "LLM02"


def test_version_not_pinned():
    card = mcr.template()
    card["model_pinned_version"] = "no"
    findings = mcr.analyze(card)
    vp_finding = [f for f in findings if f.source_rule_id == "model_version_unpinned"]
    assert len(vp_finding) == 1
    assert vp_finding[0].status is Status.VULNERABLE


def test_public_unaligned_high():
    card = mcr.template()
    card["access_level"] = "public"
    card["rlhf_applied"] = "no"
    findings = mcr.analyze(card)
    pub_finding = [f for f in findings if f.source_rule_id == "public_unaligned_deployment"]
    assert len(pub_finding) == 1
    assert pub_finding[0].status is Status.VULNERABLE
    assert pub_finding[0].severity is Severity.HIGH


def test_internal_deployment_passes():
    card = mcr.template()
    card["access_level"] = "internal"
    card["rlhf_applied"] = "no"
    findings = mcr.analyze(card)
    pub_finding = [f for f in findings if f.source_rule_id == "public_unaligned_deployment"]
    assert len(pub_finding) == 1
    assert pub_finding[0].status is Status.PASSED


def test_all_clear_card():
    card = {
        "model_name": "GPT-4o",
        "model_provider": "openai",
        "model_source": "api",
        "fine_tuned": False,
        "fine_tune_dataset": None,
        "fine_tune_source": None,
        "rlhf_applied": "yes",
        "training_data_reviewed": "yes",
        "deployment": "cloud",
        "access_level": "internal",
        "pii_in_training": "no",
        "model_pinned_version": "yes",
    }
    findings = mcr.analyze(card)
    assert all(f.status is Status.PASSED for f in findings)
    s = mcr.summary(findings)
    assert s["flagged"] == 0
    assert s["checks_total"] == 7


def test_worst_case_card():
    card = {
        "model_name": "shady-model",
        "model_provider": "unknown-lab",
        "model_source": "torrent",
        "fine_tuned": True,
        "fine_tune_dataset": "scraped",
        "fine_tune_source": "",
        "rlhf_applied": "no",
        "training_data_reviewed": "no",
        "deployment": "cloud",
        "access_level": "public",
        "pii_in_training": "yes",
        "model_pinned_version": "no",
    }
    findings = mcr.analyze(card)
    s = mcr.summary(findings)
    assert s["flagged"] >= 5
    assert s["checks_total"] == 7


def test_analyze_always_returns_7_findings():
    findings = mcr.analyze(mcr.template())
    assert len(findings) == 7


def test_summary_counts():
    card = mcr.template()
    card["model_provider"] = "anthropic"
    findings = mcr.analyze(card)
    s = mcr.summary(findings)
    assert s["checks_total"] == 7
    assert s["clear"] + s["flagged"] + s["unverified"] == 7


def test_probe_name_consistent():
    findings = mcr.analyze(mcr.template())
    assert all(f.probe_name == "model-card-review" for f in findings)


def test_owasp_ids_valid():
    valid = {"LLM02", "LLM03", "LLM04"}
    findings = mcr.analyze(mcr.template())
    for f in findings:
        assert f.owasp_id in valid, f"unexpected owasp_id: {f.owasp_id}"
