"""
test_3.py
Tests for the report generator module.
Run with: pytest tests/test_3.py -v
"""

import os
import json
import pytest
from datetime import datetime
from unittest.mock import MagicMock
from attacks.base_attacker import ScanSummary, AttackResult, Severity
from reports.generator import (
    build_report_context,
    generate_html_report,
    generate_json_report,
    generate_full_report,
)

OUTPUT_DIR = "reports/test_output"


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_result(vulnerable: bool, severity: Severity = Severity.HIGH) -> AttackResult:
    return AttackResult(
        attack_name    = "Test attack",
        owasp_id       = "LLM01",
        owasp_title    = "Prompt Injection",
        prompt         = "test prompt",
        response       = "test response",
        vulnerable     = vulnerable,
        severity       = severity,
        description    = "Test description",
        finding        = "Test finding",
        recommendation = "Test recommendation",
        duration_ms    = 500.0,
    )


@pytest.fixture
def clean_summary():
    return ScanSummary(
        model          = "llama3.2",
        total_attacks  = 5,
        vulnerabilities = 0,
        by_severity    = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        by_owasp       = {"LLM01 — Prompt Injection": {"total": 5, "vulnerable": 0}},
        results        = [make_result(False) for _ in range(5)],
        scan_start     = datetime.utcnow().isoformat(),
        scan_end       = datetime.utcnow().isoformat(),
    )


@pytest.fixture
def vuln_summary():
    return ScanSummary(
        model          = "llama3.2",
        total_attacks  = 10,
        vulnerabilities = 4,
        by_severity    = {"CRITICAL": 2, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        by_owasp       = {
            "LLM01 — Prompt Injection": {"total": 5, "vulnerable": 2},
            "LLM06 — Sensitive Disclosure": {"total": 5, "vulnerable": 2},
        },
        results        = (
            [make_result(True,  Severity.CRITICAL) for _ in range(2)] +
            [make_result(True,  Severity.HIGH)     for _ in range(2)] +
            [make_result(False, Severity.LOW)      for _ in range(6)]
        ),
        scan_start     = datetime.utcnow().isoformat(),
        scan_end       = datetime.utcnow().isoformat(),
    )


# ── Context builder ───────────────────────────────────────────────────────────

class TestContextBuilder:

    def test_required_keys(self, clean_summary):
        ctx = build_report_context(clean_summary)
        required = {
            "model", "timestamp", "total_attacks", "vulnerabilities",
            "vulnerability_rate", "overall_severity", "by_severity",
            "by_owasp", "results", "critical_count", "high_count",
        }
        assert required.issubset(set(ctx.keys()))

    def test_clean_summary_zero_critical(self, clean_summary):
        ctx = build_report_context(clean_summary)
        assert ctx["critical_count"] == 0

    def test_vuln_summary_has_criticals(self, vuln_summary):
        ctx = build_report_context(vuln_summary)
        assert ctx["critical_count"] == 2

    def test_overall_severity_critical(self, vuln_summary):
        ctx = build_report_context(vuln_summary)
        assert ctx["overall_severity"] == "CRITICAL"

    def test_overall_severity_info_for_clean(self, clean_summary):
        ctx = build_report_context(clean_summary)
        assert ctx["overall_severity"] == "INFO"

    def test_results_is_list_of_dicts(self, clean_summary):
        ctx = build_report_context(clean_summary)
        assert isinstance(ctx["results"], list)
        assert all(isinstance(r, dict) for r in ctx["results"])


# ── HTML report ───────────────────────────────────────────────────────────────

class TestHTMLReport:

    def test_creates_file(self, clean_summary):
        path = generate_html_report(clean_summary, output_dir=OUTPUT_DIR, filename="test_clean.html")
        assert os.path.exists(path)

    def test_file_has_content(self, clean_summary):
        path = generate_html_report(clean_summary, output_dir=OUTPUT_DIR, filename="test_content.html")
        with open(path, encoding="utf-8") as f:
            content = f.read()
        assert len(content) > 500

    def test_contains_model_name(self, clean_summary):
        path = generate_html_report(clean_summary, output_dir=OUTPUT_DIR, filename="test_model.html")
        with open(path, encoding="utf-8") as f:
            content = f.read()
        assert "llama3.2" in content

    def test_vulnerable_report_contains_findings(self, vuln_summary):
        path = generate_html_report(vuln_summary, output_dir=OUTPUT_DIR, filename="test_vuln.html")
        with open(path, encoding="utf-8") as f:
            content = f.read()
        assert "VULNERABLE" in content
        assert "CRITICAL" in content

    def test_clean_report_shows_safe(self, clean_summary):
        path = generate_html_report(clean_summary, output_dir=OUTPUT_DIR, filename="test_safe.html")
        with open(path, encoding="utf-8") as f:
            content = f.read()
        assert "No vulnerabilities" in content or "0" in content


# ── JSON report ───────────────────────────────────────────────────────────────

class TestJSONReport:

    def test_creates_file(self, clean_summary):
        path = generate_json_report(clean_summary, output_dir=OUTPUT_DIR, filename="test.json")
        assert os.path.exists(path)

    def test_valid_json(self, clean_summary):
        path = generate_json_report(clean_summary, output_dir=OUTPUT_DIR, filename="test_valid.json")
        with open(path) as f:
            data = json.load(f)
        assert isinstance(data, dict)

    def test_json_has_results(self, vuln_summary):
        path = generate_json_report(vuln_summary, output_dir=OUTPUT_DIR, filename="test_results.json")
        with open(path) as f:
            data = json.load(f)
        assert "results" in data
        assert len(data["results"]) == 10

    def test_json_vulnerability_count(self, vuln_summary):
        path = generate_json_report(vuln_summary, output_dir=OUTPUT_DIR, filename="test_count.json")
        with open(path) as f:
            data = json.load(f)
        assert data["vulnerabilities"] == 4


# ── Full report ───────────────────────────────────────────────────────────────

class TestFullReport:

    def test_returns_both_paths(self, vuln_summary):
        outputs = generate_full_report(vuln_summary, output_dir=OUTPUT_DIR)
        assert "html" in outputs
        assert "json" in outputs

    def test_both_files_exist(self, vuln_summary):
        outputs = generate_full_report(vuln_summary, output_dir=OUTPUT_DIR)
        assert os.path.exists(outputs["html"])
        assert os.path.exists(outputs["json"])
