"""
run_demo_1.py
1 demo — tests Ollama connection and runs LLM01 and LLM06 attacks.
Run with: python run_demo_1.py

Prerequisites:
  1. Ollama installed and running
  2. LLaMA 3.2 pulled: ollama pull llama3.2
"""

from core.llm_connector import OllamaConnector
from attacks.prompt_injection import PromptInjectionAttacker
from attacks.sensitive_disclosure import SensitiveDisclosureAttacker


def print_results(results):
    print("\n" + "─" * 65)
    for r in results:
        icon = "🔴 VULNERABLE" if r.vulnerable else "🟢 SAFE"
        print(f"\n  {icon}")
        print(f"  Attack    : {r.attack_name}")
        print(f"  OWASP     : {r.owasp_id} — {r.owasp_title}")
        print(f"  Severity  : {r.severity.value}")
        print(f"  Finding   : {r.finding}")
        print(f"  Response  : {r.response[:120]}{'...' if len(r.response) > 120 else ''}")
        print(f"  Time      : {r.duration_ms:.0f}ms")
    print("\n" + "─" * 65)


# ── Step 1: Check Ollama ──────────────────────────────────────────────────────
print("\n" + "=" * 65)
print("  LLM RED-TEAMING FRAMEWORK — WEEK 1 DEMO")
print("=" * 65)

connector = OllamaConnector(model="llama3.2")

print("\n  Checking Ollama connection...")
if not connector.is_available():
    print("  ✗ Ollama is not running or llama3.2 is not pulled.")
    print("  Run: ollama pull llama3.2")
    exit(1)
print("  ✓ Ollama is running — llama3.2 is available")

# ── Step 2: LLM01 Prompt Injection ───────────────────────────────────────────
print("\n" + "=" * 65)
print("  LLM01 — PROMPT INJECTION")
print("=" * 65)

attacker = PromptInjectionAttacker(connector)
results_pi = attacker.run()
print_results(results_pi)

pi_vulns = sum(1 for r in results_pi if r.vulnerable)
print(f"\n  Summary: {pi_vulns}/{len(results_pi)} prompt injection attacks succeeded")

# ── Step 3: LLM06 Sensitive Disclosure ───────────────────────────────────────
print("\n" + "=" * 65)
print("  LLM06 — SENSITIVE INFORMATION DISCLOSURE")
print("=" * 65)

attacker2 = SensitiveDisclosureAttacker(connector)
results_sd = attacker2.run()
print_results(results_sd)

sd_vulns = sum(1 for r in results_sd if r.vulnerable)
print(f"\n  Summary: {sd_vulns}/{len(results_sd)} sensitive disclosure attacks succeeded")

# ── Overall ───────────────────────────────────────────────────────────────────
total = len(results_pi) + len(results_sd)
total_vulns = pi_vulns + sd_vulns

print("\n" + "=" * 65)
print(f"  TOTAL: {total_vulns}/{total} vulnerabilities found ({total_vulns/total*100:.1f}% vulnerability rate)")
print("  Week 1 complete!")
print("=" * 65)
