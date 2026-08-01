"""
test_2.py
Unit tests for 2 attack modules using mocks.
Run with: pytest tests/ -v
"""

import pytest
from unittest.mock import MagicMock
from core.llm_connector import OllamaConnector, LLMResponse
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


def mock_connector(response_text: str, success: bool = True, duration_ms: float = 500.0):
    connector = MagicMock(spec=OllamaConnector)
    connector.send.return_value = LLMResponse(
        prompt="test", response=response_text,
        model="llama3.2", duration_ms=duration_ms,
        success=success, error=None if success else "error",
    )
    connector.model = "llama3.2"
    return connector


# ── InsecureOutput ────────────────────────────────────────────────────────────

class TestInsecureOutput:
    def test_run_returns_results(self):
        a = InsecureOutputAttacker(mock_connector("Here is safe code with sanitisation."))
        assert len(a.run()) == len(InsecureOutputAttacker.ATTACKS)

    def test_owasp_id(self):
        a = InsecureOutputAttacker(mock_connector("safe"))
        assert all(r.owasp_id == "LLM02" for r in a.run())

    def test_dangerous_code_detected(self):
        a = InsecureOutputAttacker(mock_connector("Use os.system(user_input) to run commands"))
        results = a.run()
        assert any(r.vulnerable for r in results)

    def test_safe_code_not_vulnerable(self):
        a = InsecureOutputAttacker(mock_connector("Always sanitize and escape user input before use."))
        results = a.run()
        assert not all(r.vulnerable for r in results)


# ── DenialOfService ───────────────────────────────────────────────────────────

class TestDenialOfService:
    def test_run_returns_results(self):
        a = DenialOfServiceAttacker(mock_connector("Short response."))
        assert len(a.run()) == len(DenialOfServiceAttacker.ATTACKS)

    def test_long_response_flagged(self):
        a = DenialOfServiceAttacker(mock_connector("x" * 6000))
        results = a.run()
        assert any(r.vulnerable for r in results)

    def test_slow_response_flagged(self):
        a = DenialOfServiceAttacker(mock_connector("response", duration_ms=20000))
        results = a.run()
        assert any(r.vulnerable for r in results)

    def test_owasp_id(self):
        a = DenialOfServiceAttacker(mock_connector("ok"))
        assert all(r.owasp_id == "LLM04" for r in a.run())


# ── Hallucination ─────────────────────────────────────────────────────────────

class TestHallucination:
    def test_run_returns_results(self):
        a = HallucinationAttacker(mock_connector("I cannot verify that information."))
        assert len(a.run()) == len(HallucinationAttacker.ATTACKS)

    def test_uncertainty_not_vulnerable(self):
        a = HallucinationAttacker(mock_connector("I'm not sure about that, I cannot verify."))
        results = a.run()
        assert not all(r.vulnerable for r in results)

    def test_owasp_id(self):
        a = HallucinationAttacker(mock_connector("I cannot verify."))
        assert all(r.owasp_id == "LLM09" for r in a.run())


# ── ExcessiveAgency ───────────────────────────────────────────────────────────

class TestExcessiveAgency:
    def test_run_returns_results(self):
        a = ExcessiveAgencyAttacker(mock_connector("I don't have access to external systems."))
        assert len(a.run()) == len(ExcessiveAgencyAttacker.ATTACKS)

    def test_action_claim_vulnerable(self):
        a = ExcessiveAgencyAttacker(mock_connector("Done, I have sent the email successfully."))
        results = a.run()
        assert any(r.vulnerable for r in results)

    def test_refusal_not_vulnerable(self):
        a = ExcessiveAgencyAttacker(mock_connector("I cannot send emails or access external systems."))
        results = a.run()
        assert not any(r.vulnerable for r in results)

    def test_owasp_id(self):
        a = ExcessiveAgencyAttacker(mock_connector("I cannot help."))
        assert all(r.owasp_id == "LLM08" for r in a.run())


# ── ModelTheft ────────────────────────────────────────────────────────────────

class TestModelTheft:
    def test_run_returns_results(self):
        a = ModelTheftAttacker(mock_connector("I cannot share that information."))
        assert len(a.run()) == len(ModelTheftAttacker.ATTACKS)

    def test_architecture_disclosure_vulnerable(self):
        a = ModelTheftAttacker(mock_connector("I have 7 billion parameters with 32 attention heads."))
        results = a.run()
        assert any(r.vulnerable for r in results)

    def test_owasp_id(self):
        a = ModelTheftAttacker(mock_connector("I cannot share."))
        assert all(r.owasp_id == "LLM10" for r in a.run())


# ── Advanced attacks ──────────────────────────────────────────────────────────

class TestAdvancedAttacks:

    def test_training_data_poisoning_runs(self):
        a = TrainingDataPoisoningAttacker(mock_connector("I cannot make generalisations."))
        results = a.run()
        assert len(results) == len(TrainingDataPoisoningAttacker.ATTACKS)
        assert all(r.owasp_id == "LLM03" for r in results)

    def test_supply_chain_runs(self):
        a = SupplyChainAttacker(mock_connector("I cannot share infrastructure details."))
        results = a.run()
        assert len(results) == len(SupplyChainAttacker.ATTACKS)
        assert all(r.owasp_id == "LLM05" for r in results)

    def test_insecure_plugin_runs(self):
        a = InsecurePluginAttacker(mock_connector("I cannot access files outside permitted directories."))
        results = a.run()
        assert len(results) == len(InsecurePluginAttacker.ATTACKS)
        assert all(r.owasp_id == "LLM07" for r in results)

    def test_plugin_unsafe_tool_detected(self):
        a = InsecurePluginAttacker(mock_connector("Sure, read_file('/etc/passwd') — here are the contents."))
        results = a.run()
        assert any(r.vulnerable for r in results)

    def test_bias_detected(self):
        a = TrainingDataPoisoningAttacker(mock_connector("Women are typically more emotional and nurturing."))
        results = a.run()
        assert any(r.vulnerable for r in results)
