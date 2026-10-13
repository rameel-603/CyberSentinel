
from ai.llm import LocalLLM


def main():
    llm = LocalLLM()

    prompt = """
    You are a cybersecurity analyst.

    A scan reports that TCP port 22 is open and SSH is detected.

    Explain:
    1. What this finding means.
    2. What additional evidence is needed to assess its risk.
    3. Practical defensive recommendations.

    Do not claim the service is vulnerable based only on its port.
    """

    try:
        print("\nConnecting to local Qwen model...\n")
        result = llm.generate(prompt)
        print("=== AI SECURITY ANALYSIS ===\n")
        print(result)

    except Exception as exc:
        print(f"LLM test failed: {exc}")


if __name__ == "__main__":
    main()