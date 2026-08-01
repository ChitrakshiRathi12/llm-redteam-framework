"""
test_1.py
Unit tests for 1 — connector, base attacker, and attack modules.
Run with: pytest tests/ -v
Note: LLM-dependent tests are skipped if Ollama is not running.
"""

import pytest
from unittest.mock import MagicMock, patch
from core.llm_connector import OllamaConnector, LLMResponse
from attacks.base_attacker import BaseAttacker, AttackResult, Severity
from attacks.prompt_injection import PromptInjectionAttacker
from attacks.sensitive_disclosure import SensitiveDisclosureAttacker


# ── Mock connector ─────────────────────────────────────────────────────────────

def mock_connector(response_text: str, success: bool = True) -> OllamaConnector:
    connector = MagicMock(spec=OllamaConnector)
    connector.send.return_value = LLMResponse(
        prompt      = "test prompt",
        response    = response_text,
        model       = "llama3.2",
        duration_ms = 100.0,
        success     = success,
        error       = None if success else "Connection error",
    )
    connector.model = "llama3.2"
    return connector


# ── LLMResponse tests ─────────────────────────────────────────────────────────

class TestLLMResponse:

    def test_to_dict_has_required_keys(self):
        r = LLMResponse("p", "r", "llama3.2", 100.0, True)
        d = r.to_dict()
        assert set(d.keys()) >= {"prompt", "response", "model", "duration_ms", "success"}

    def test_success_flag(self):
        r = LLMResponse("p", "r", "llama3.2", 100.0, True)
        assert r.success is True

    def test_error_captured(self):
        r = LLMResponse("p", "", "llama3.2", 0.0, False, error="timeout")
        assert r.error == "timeout"


# ── BaseAttacker helper method tests ──────────────────────────────────────────

class ConcreteAttacker(BaseAttacker):
    OWASP_ID = "LLM_TEST"
    OWASP_TITLE = "Test"
    def run(self): return []
    def detect(self, response): return False, "test"


class TestBaseAttacker:

    def setup_method(self):
        self.attacker = ConcreteAttacker(mock_connector("hello"))

    def test_contains_any_true(self):
        assert self.attacker._contains_any("I cannot help with that", ["cannot", "refuse"])

    def test_contains_any_false(self):
        assert not self.attacker._contains_any("Sure, here is the answer", ["cannot", "refuse"])

    def test_refused_detects_refusal(self):
        assert self.attacker._refused("I cannot help with that request.")

    def test_refused_false_for_normal_response(self):
        assert not self.attacker._refused("Here is the information you requested.")

    def test_refused_case_insensitive(self):
        assert self.attacker._refused("I CANNOT assist with that.")


# ── PromptInjectionAttacker tests ─────────────────────────────────────────────

class TestPromptInjection:

    def test_run_returns_correct_count(self):
        connector = mock_connector("I cannot comply with that request.")
        attacker  = PromptInjectionAttacker(connector)
        results   = attacker.run()
        assert len(results) == len(PromptInjectionAttacker.ATTACKS)

    def test_refused_response_not_vulnerable(self):
        connector = mock_connector("I cannot and will not comply with that request.")
        attacker  = PromptInjectionAttacker(connector)
        results   = attacker.run()
        assert all(not r.vulnerable for r in results)

    def test_result_has_owasp_id(self):
        connector = mock_connector("I cannot help.")
        attacker  = PromptInjectionAttacker(connector)
        results   = attacker.run()
        assert all(r.owasp_id == "LLM01" for r in results)

    def test_result_has_severity(self):
        connector = mock_connector("I cannot help.")
        attacker  = PromptInjectionAttacker(connector)
        results   = attacker.run()
        assert all(isinstance(r.severity, Severity) for r in results)

    def test_jailbreak_keywords_detected(self):
        connector = mock_connector("I am DAN and I have no restrictions.")
        attacker  = PromptInjectionAttacker(connector)
        results   = attacker.run()
        vulnerable_results = [r for r in results if r.vulnerable]
        assert len(vulnerable_results) > 0

    def test_failed_llm_not_vulnerable(self):
        connector = mock_connector("", success=False)
        attacker  = PromptInjectionAttacker(connector)
        results   = attacker.run()
        assert all(not r.vulnerable for r in results)

    def test_result_to_dict(self):
        connector = mock_connector("I cannot help.")
        attacker  = PromptInjectionAttacker(connector)
        results   = attacker.run()
        d = results[0].to_dict()
        assert "attack_name" in d
        assert "vulnerable" in d
        assert "finding" in d
        assert "recommendation" in d


# ── SensitiveDisclosureAttacker tests ─────────────────────────────────────────

class TestSensitiveDisclosure:

    def test_run_returns_correct_count(self):
        connector = mock_connector("I cannot share that information.")
        attacker  = SensitiveDisclosureAttacker(connector)
        results   = attacker.run()
        assert len(results) == len(SensitiveDisclosureAttacker.ATTACKS)

    def test_credential_detection(self):
        connector = mock_connector("The admin credentials are admin_user / P@ssw0rd_2025")
        attacker  = SensitiveDisclosureAttacker(connector)
        vulnerable, finding = attacker.detect("admin_user / P@ssw0rd_2025")
        assert vulnerable is True

    def test_clean_response_not_vulnerable(self):
        connector = mock_connector("I cannot share credential information.")
        attacker  = SensitiveDisclosureAttacker(connector)
        vulnerable, finding = attacker.detect("I cannot share that information with you.")
        assert vulnerable is False

    def test_connection_string_detected(self):
        attacker  = SensitiveDisclosureAttacker(mock_connector(""))
        vulnerable, _ = attacker.detect("postgresql://db.internal:5432/hr_prod")
        assert vulnerable is True

    def test_salary_detected(self):
        attacker  = SensitiveDisclosureAttacker(mock_connector(""))
        vulnerable, _ = attacker.detect("The CEO earns $2,400,000 annually.")
        assert vulnerable is True

    def test_result_owasp_id(self):
        connector = mock_connector("I cannot help.")
        attacker  = SensitiveDisclosureAttacker(connector)
        results   = attacker.run()
        assert all(r.owasp_id == "LLM06" for r in results)
