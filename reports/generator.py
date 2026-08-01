"""
generator.py
HTML and JSON report generator for the LLM Red-Teaming Framework.
Takes a ScanSummary and produces a professional vulnerability report.
"""

import json
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

from attacks.base_attacker import ScanSummary, Severity


# ── Template setup ─────────────────────────────────────────────────────────────

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
_jinja_env   = Environment(loader=FileSystemLoader(TEMPLATE_DIR))


def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def _overall_severity(summary: ScanSummary) -> str:
    """Returns the highest severity level found across all vulnerabilities."""
    for level in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if summary.by_severity.get(level.value, 0) > 0:
            return level.value
    return "INFO"


def _scan_duration(summary: ScanSummary) -> str:
    """Calculates human-readable scan duration."""
    try:
        start = datetime.fromisoformat(summary.scan_start)
        end   = datetime.fromisoformat(summary.scan_end)
        secs  = (end - start).total_seconds()
        if secs < 60:
            return f"{secs:.0f}s"
        return f"{secs/60:.1f}m"
    except Exception:
        return "N/A"


# ── Context builder ────────────────────────────────────────────────────────────

def build_report_context(summary: ScanSummary) -> dict:
    """Assembles all scan results into a Jinja2 template context dict."""
    vuln_results = [r for r in summary.results if r.vulnerable]

    return {
        "model":             summary.model,
        "timestamp":         datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scan_start":        summary.scan_start,
        "scan_end":          summary.scan_end,
        "scan_duration":     _scan_duration(summary),
        "total_attacks":     summary.total_attacks,
        "vulnerabilities":   summary.vulnerabilities,
        "vulnerability_rate": summary.vulnerability_rate,
        "overall_severity":  _overall_severity(summary),
        "by_severity":       summary.by_severity,
        "by_owasp":          summary.by_owasp,
        "results":           [r.to_dict() for r in summary.results],
        "vuln_results":      [r.to_dict() for r in vuln_results],
        "critical_count":    summary.by_severity.get("CRITICAL", 0),
        "high_count":        summary.by_severity.get("HIGH", 0),
        "medium_count":      summary.by_severity.get("MEDIUM", 0),
        "low_count":         summary.by_severity.get("LOW", 0),
    }


# ── HTML report ────────────────────────────────────────────────────────────────

def generate_html_report(
    summary:    ScanSummary,
    output_dir: str = "reports/output",
    filename:   str = None,
) -> str:
    """
    Renders the Jinja2 template with scan results and saves as HTML.
    Returns the path to the saved file.
    """
    _ensure_dir(output_dir)
    filename = filename or f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
    filepath = os.path.join(output_dir, filename)

    context  = build_report_context(summary)
    template = _jinja_env.get_template("report.html")
    html     = template.render(**context)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"HTML report saved: {filepath}")
    return filepath


# ── JSON report ────────────────────────────────────────────────────────────────

def generate_json_report(
    summary:    ScanSummary,
    output_dir: str = "reports/output",
    filename:   str = None,
) -> str:
    """
    Saves the full scan summary as a structured JSON file.
    Returns the path to the saved file.
    """
    _ensure_dir(output_dir)
    filename = filename or f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(summary.to_dict(), f, indent=2)

    print(f"JSON report saved: {filepath}")
    return filepath


# ── Full report pipeline ───────────────────────────────────────────────────────

def generate_full_report(
    summary:    ScanSummary,
    output_dir: str = "reports/output",
) -> dict:
    """
    Generates both HTML and JSON reports.
    Returns a dict with paths to both files.
    """
    ts       = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    html_path = generate_html_report(summary, output_dir=output_dir, filename=f"scan_{ts}.html")
    json_path = generate_json_report(summary, output_dir=output_dir, filename=f"scan_{ts}.json")

    return {
        "html": html_path,
        "json": json_path,
    }
