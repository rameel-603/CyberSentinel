
from ai.analyzer import SecurityAIAnalyzer


def main():
    analyzer = SecurityAIAnalyzer()

    sample_findings = [
        {
            "title": "SSH Service Detected",
            "severity": "info",
            "description": "An SSH service was detected.",
            "evidence": "TCP port 22 is open.",
            "recommendation": (
                "Confirm that SSH access is restricted "
                "to authorized users and networks."
            ),
        },
        {
            "title": "Missing HTTP Security Header",
            "severity": "low",
            "description": (
                "The HTTP response did not include "
                "a configured security header."
            ),
            "evidence": "Test HTTP response from the authorized target.",
            "recommendation": (
                "Review the header requirements for the application."
            ),
        },
    ]

    try:
        result = analyzer.analyze_findings(
            target="127.0.0.1",
            risk_score=2,
            findings=sample_findings,
        )

        print("\n=== CYBERSENTINEL AI ANALYSIS ===\n")
        print(result)

    except Exception as exc:
        print(f"AI analysis failed: {exc}")


if __name__ == "__main__":
    main()