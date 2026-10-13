
import requests


class LocalLLM:
    """Client for the locally running Ollama model."""

    def __init__(
        self,
        model="qwen3:8b",
        base_url="http://localhost:11434",
        timeout=300,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def generate(self, prompt: str) -> str:
        """Send a prompt to Ollama and return its response."""
        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
            },
            timeout=self.timeout,
        )
        response.raise_for_status()

        result = response.json().get("response", "").strip()
        if not result:
            raise RuntimeError("Ollama returned an empty response.")

        return result