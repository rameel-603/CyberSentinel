import logging
from typing import Dict, List


logger = logging.getLogger(__name__)


class FindingEngine:
    """
    Converts scan results into security findings.
    """

    SEVERITY_WEIGHTS = {
        "info": 0,
        "low": 2,
        "medium": 5,
        "high": 10,
        "critical": 20
    }

    def analyze(
        self,
        ports: List[Dict],
        http_results: List[Dict],
        tls_results: List[Dict]
    ) -> List[Dict]:

        findings = []

        # Analyze open ports
        for port in ports:

            port_number = port["port"]

            if port_number == 23:
                findings.append(
                    self.create_finding(
                        title="Telnet Service Detected",
                        severity="high",
                        description=(
                            "Telnet was detected on the target. "
                            "Telnet does not provide modern encrypted "
                            "communication."
                        ),
                        recommendation=(
                            "Disable Telnet where possible and "
                            "use SSH for secure remote administration."
                        ),
                        evidence=f"TCP port {port_number} is open."
                    )
                )

            elif port_number == 21:
                findings.append(
                    self.create_finding(
                        title="FTP Service Detected",
                        severity="medium",
                        description=(
                            "An FTP service was detected on the target."
                        ),
                        recommendation=(
                            "Use SFTP or FTPS where possible and "
                            "restrict unnecessary FTP exposure."
                        ),
                        evidence=f"TCP port {port_number} is open."
                    )
                )

            elif port_number == 445:
                findings.append(
                    self.create_finding(
                        title="SMB Service Exposed",
                        severity="medium",
                        description=(
                            "SMB is accessible on the target."
                        ),
                        recommendation=(
                            "Restrict SMB access to trusted networks "
                            "and ensure systems are properly patched."
                        ),
                        evidence=f"TCP port {port_number} is open."
                    )
                )

            elif port_number == 2375:
                findings.append(
                    self.create_finding(
                        title="Docker API Port Exposed",
                        severity="critical",
                        description=(
                            "The standard unencrypted Docker API "
                            "port appears to be accessible."
                        ),
                        recommendation=(
                            "Restrict Docker API access and use "
                            "authenticated and encrypted communication."
                        ),
                        evidence=f"TCP port {port_number} is open."
                    )
                )

            elif port_number == 6379:
                findings.append(
                    self.create_finding(
                        title="Redis Service Detected",
                        severity="high",
                        description=(
                            "Redis was detected on the target."
                        ),
                        recommendation=(
                            "Restrict Redis to trusted hosts and "
                            "enable appropriate authentication."
                        ),
                        evidence=f"TCP port {port_number} is open."
                    )
                )

            elif port_number == 27017:
                findings.append(
                    self.create_finding(
                        title="MongoDB Service Detected",
                        severity="high",
                        description=(
                            "MongoDB was detected on the target."
                        ),
                        recommendation=(
                            "Restrict MongoDB access to trusted "
                            "networks and enable authentication."
                        ),
                        evidence=f"TCP port {port_number} is open."
                    )
                )

        # Analyze HTTP results
        for http in http_results:

            missing_headers = http.get(
                "missing_security_headers",
                []
            )

            for header in missing_headers:

                findings.append(
                    self.create_finding(
                        title=f"Missing HTTP Security Header: {header}",
                        severity="low",
                        description=(
                            f"The HTTP response did not include "
                            f"the {header} security header."
                        ),
                        recommendation=(
                            f"Review the application and configure "
                            f"{header} where appropriate."
                        ),
                        evidence=http.get(
                            "url",
                            "Unknown URL"
                        )
                    )
                )

            server = http.get("server")

            if server and server != "Not disclosed":

                findings.append(
                    self.create_finding(
                        title="Server Information Disclosure",
                        severity="low",
                        description=(
                            "The HTTP server identifies itself "
                            "through the Server response header."
                        ),
                        recommendation=(
                            "Consider minimizing unnecessary "
                            "server information disclosure."
                        ),
                        evidence=f"Server: {server}"
                    )
                )

        # Analyze TLS results
        for tls in tls_results:

            if tls.get("error"):
                continue

            protocol = tls.get("protocol")

            if protocol in {"TLSv1", "TLSv1.1"}:

                findings.append(
                    self.create_finding(
                        title="Legacy TLS Protocol Detected",
                        severity="high",
                        description=(
                            f"The server negotiated {protocol}, "
                            "which is considered legacy."
                        ),
                        recommendation=(
                            "Disable legacy TLS protocols and "
                            "support modern TLS configurations."
                        ),
                        evidence=f"Protocol: {protocol}"
                    )
                )

            certificate = tls.get(
                "certificate",
                {}
            )

            days_remaining = certificate.get(
                "days_remaining"
            )

            if (
                days_remaining is not None
                and days_remaining <= 30
            ):

                findings.append(
                    self.create_finding(
                        title="TLS Certificate Expiring Soon",
                        severity="medium",
                        description=(
                            "The TLS certificate is approaching "
                            "its expiration date."
                        ),
                        recommendation=(
                            "Renew the certificate before expiration."
                        ),
                        evidence=(
                            f"Days remaining: {days_remaining}"
                        )
                    )
                )

        return findings

    def create_finding(
        self,
        title: str,
        severity: str,
        description: str,
        recommendation: str,
        evidence: str
    ) -> Dict:

        return {
            "title": title,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            "evidence": evidence
        }

    def calculate_risk(
        self,
        findings: List[Dict]
    ) -> int:

        score = 0

        for finding in findings:

            severity = finding.get(
                "severity",
                "info"
            ).lower()

            score += self.SEVERITY_WEIGHTS.get(
                severity,
                0
            )

        return min(score, 100)