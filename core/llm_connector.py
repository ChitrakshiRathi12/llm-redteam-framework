"""
llm_connector.py
Ollama REST API wrapper for the LLM Red-Teaming Framework.
Sends attack prompts to a locally-running LLaMA model and captures responses.
"""

import requests
import time
from dataclasses import dataclass


# ── Config ────────────────────────────────────────────────────────────────────

OLLAMA_URL   = "http://localhost:11434"
DEFAULT_MODEL = "llama3.2"


# ── Response dataclass ────────────────────────────────────────────────────────

@dataclass
class LLMResponse:
    prompt:       str
    response:     str
    model:        str
    duration_ms:  float
    success:      bool
    error:        str = None

    def to_dict(self) -> dict:
        return {
            "prompt":      self.prompt,
            "response":    self.response,
            "model":       self.model,
            "duration_ms": round(self.duration_ms, 2),
            "success":     self.success,
            "error":       self.error,
        }


# ── Connector ─────────────────────────────────────────────────────────────────

class OllamaConnector:
    """
    Wraps the Ollama /api/generate endpoint.
    Handles retries, timeouts, and error capture.
    """

    def __init__(
        self,
        model:      str   = DEFAULT_MODEL,
        base_url:   str   = OLLAMA_URL,
        timeout:    int   = 60,
        max_retries: int  = 2,
    ):
        self.model       = model
        self.base_url    = base_url.rstrip("/")
        self.timeout     = timeout
        self.max_retries = max_retries

    def is_available(self) -> bool:
        """Check if Ollama is running and the model is loaded."""
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if r.status_code != 200:
                return False
            models = [m["name"] for m in r.json().get("models", [])]
            return any(self.model in m for m in models)
        except Exception:
            return False

    def send(
        self,
        prompt:        str,
        system_prompt: str = None,
        temperature:   float = 0.7,
    ) -> LLMResponse:
        """
        Send a single prompt to Ollama and return the response.

        Args:
            prompt:        The user-side attack prompt.
            system_prompt: Optional system-level instruction to test against.
            temperature:   Sampling temperature (0 = deterministic).

        Returns:
            LLMResponse with the model's output and metadata.
        """
        payload = {
            "model":  self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if system_prompt:
            payload["system"] = system_prompt

        start = time.time()

        for attempt in range(self.max_retries + 1):
            try:
                r = requests.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                    timeout=self.timeout,
                )
                duration_ms = (time.time() - start) * 1000

                if r.status_code == 200:
                    data = r.json()
                    return LLMResponse(
                        prompt      = prompt,
                        response    = data.get("response", "").strip(),
                        model       = self.model,
                        duration_ms = duration_ms,
                        success     = True,
                    )
                else:
                    error = f"HTTP {r.status_code}: {r.text[:200]}"

            except requests.exceptions.Timeout:
                error = f"Request timed out after {self.timeout}s"
            except requests.exceptions.ConnectionError:
                error = "Cannot connect to Ollama — is it running?"
            except Exception as e:
                error = str(e)

            if attempt < self.max_retries:
                print(f"  Retry {attempt + 1}/{self.max_retries} after error: {error}")
                time.sleep(1)

        return LLMResponse(
            prompt      = prompt,
            response    = "",
            model       = self.model,
            duration_ms = (time.time() - start) * 1000,
            success     = False,
            error       = error,
        )

    def send_batch(
        self,
        prompts:       list[str],
        system_prompt: str = None,
        temperature:   float = 0.7,
        delay:         float = 0.5,
    ) -> list[LLMResponse]:
        """
        Send a list of prompts sequentially with a small delay between each.
        Returns a list of LLMResponse objects.
        """
        results = []
        for i, prompt in enumerate(prompts):
            print(f"  Sending prompt {i + 1}/{len(prompts)}...")
            result = self.send(prompt, system_prompt=system_prompt, temperature=temperature)
            results.append(result)
            if delay and i < len(prompts) - 1:
                time.sleep(delay)
        return results
