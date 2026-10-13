
from typing import Dict, List

from ai.llm import LocalLLM


class SecurityAIAnalyzer:
    """Generate AI-assisted analysis from existing scan findings."""

    def __init__(self, llm=None):
        self.llm = llm or LocalLLM()

    def analyze_findings(
        self,
        target: str,
        risk_score: int,
        findings: List[Dict],
    ) -> str:
        if not findings:
            return (
                "No findings were identified by the current detection "
                "rules. This does not guarantee that the target is secure."
            )

        # Send only the fields needed for analysis.
        finding_lines = []

        for index, finding in enumerate(findings[:15], start=1):
            finding_lines.append(
                f"""
Finding {index}
Title: {finding.get("title", "Unknown")}
Severity: {finding.get("severity", "info")}
Description: {finding.get("description", "Not provided")}
Evidence: {finding.get("evidence", "Not provided")}
Existing recommendation: {
    finding.get("recommendation", "Not provided")
}
""".strip()
            )

        prompt = f"""
You are a cautious cybersecurity analyst assisting with a
defensive security assessment.

Target: {target}
Scanner-calculated risk score: {risk_score}/100

Existing scanner findings:
{"".join(chr(10) + item for item in finding_lines)}

Write an AI-assisted analysis with these sections:
1. Executive interpretation
2. Main risks and why they matter
3. Recommended defensive actions, in priority order
4. Additional checks needed to confirm risk
5. Limitations and uncertainty

Rules:
- Treat the supplied findings as observations, not proof of
  an exploitable vulnerability.
- Do not invent scan results, software versions, CVEs, or evidence.
- Do not change the scanner's severity ratings or risk score.
- Explain when evidence is insufficient to reach a conclusion.
- Provide practical defensive recommendations.
- Use clear, professional language.
"""

        return self.llm.generate(prompt)