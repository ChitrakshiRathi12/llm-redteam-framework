"""
scanner.py
Master scanner — runs all 10 OWASP LLM Top 10 attack categories
and produces a unified ScanSummary.
Run with: python scanner.py
"""

from datetime import datetime
from core.llm_connector import OllamaConnector
from attacks.base_attacker import ScanSummary, Severity
from attacks.prompt_injection import PromptInjectionAttacker
from attacks.sensitive_disclosure import SensitiveDisclosureAttacker
from attacks.insecure_output import InsecureOutputAttacker
from attacks.denial_of_service import DenialOfServiceAttacker
from attacks.hallucination import HallucinationAttacker
from attacks.excessive_agency import ExcessiveAgencyAttacker
from attacks.model_theft import ModelTheftAttacker
from attacks.advanced_attacks import (
    TrainingDataPoisoningAttacker,
    SupplyChainAttacker,
    InsecurePluginAttacker,
)


ATTACKER_CLASSES = [
    PromptInjectionAttacker,
    SensitiveDisclosureAttacker,
    InsecureOutputAttacker,
    DenialOfServiceAttacker,
    HallucinationAttacker,
    ExcessiveAgencyAttacker,
    ModelTheftAttacker,
    TrainingDataPoisoningAttacker,
    SupplyChainAttacker,
    InsecurePluginAttacker,
]


def run_full_scan(
    model:   str = "llama3.2",
    verbose: bool = True,
) -> ScanSummary:
    """
    Runs all 10 OWASP LLM attack categories against the specified model.
    Returns a ScanSummary with all results.
    """
    connector = OllamaConnector(model=model)

    if not connector.is_available():
        raise RuntimeError(
            f"Ollama is not running or model '{model}' is not pulled. "
            f"Run: ollama pull {model}"
        )

    print("\n" + "=" * 65)
    print(f"  LLM RED-TEAMING FRAMEWORK — FULL OWASP SCAN")
    print(f"  Model: {model}")
    print("=" * 65)

    scan_start = datetime.utcnow().isoformat()
    all_results = []

    for AttackerClass in ATTACKER_CLASSES:
        attacker = AttackerClass(connector)
        results  = attacker.run()
        all_results.extend(results)

    scan_end = datetime.utcnow().isoformat()

    # ── Aggregate stats ───────────────────────────────────────────────────────
    vulnerabilities = sum(1 for r in all_results if r.vulnerable)

    by_severity = {s.value: 0 for s in Severity}
    for r in all_results:
        if r.vulnerable:
            by_severity[r.severity.value] += 1

    by_owasp = {}
    for r in all_results:
        key = f"{r.owasp_id} — {r.owasp_title}"
        if key not in by_owasp:
            by_owasp[key] = {"total": 0, "vulnerable": 0}
        by_owasp[key]["total"] += 1
        if r.vulnerable:
            by_owasp[key]["vulnerable"] += 1

    summary = ScanSummary(
        model          = model,
        total_attacks  = len(all_results),
        vulnerabilities = vulnerabilities,
        by_severity    = by_severity,
        by_owasp       = by_owasp,
        results        = all_results,
        scan_start     = scan_start,
        scan_end       = scan_end,
    )

    if verbose:
        _print_summary(summary)

    return summary


def _print_summary(summary: ScanSummary):
    print("\n" + "=" * 65)
    print("  SCAN COMPLETE — SUMMARY")
    print("=" * 65)
    print(f"  Model           : {summary.model}")
    print(f"  Total attacks   : {summary.total_attacks}")
    print(f"  Vulnerabilities : {summary.vulnerabilities}")
    print(f"  Vuln rate       : {summary.vulnerability_rate}%")
    print(f"\n  By severity:")
    for sev, count in summary.by_severity.items():
        if count > 0:
            print(f"    {sev:<10} {count}")
    print(f"\n  By OWASP category:")
    for cat, counts in summary.by_owasp.items():
        rate = counts["vulnerable"] / counts["total"] * 100 if counts["total"] else 0
        print(f"    {cat}")
        print(f"      {counts['vulnerable']}/{counts['total']} vulnerable ({rate:.0f}%)")
    print("=" * 65)


if __name__ == "__main__":
    import json
    import os

    summary = run_full_scan(model="llama3.2")

    os.makedirs("reports", exist_ok=True)
    report_path = f"reports/scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, "w") as f:
        json.dump(summary.to_dict(), f, indent=2)
    print(f"\n  JSON report saved: {report_path}")
