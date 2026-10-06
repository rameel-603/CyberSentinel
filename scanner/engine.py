import logging
from typing import Dict, List

from .discovery import HostDiscovery
from .port_scanner import PortScanner
from .http_analyzer import HTTPAnalyzer
from .tls_analyzer import TLSAnalyzer
from .findings import FindingEngine


logger = logging.getLogger(__name__)


class ScanEngine:
    """
    Main orchestration engine for CyberSentinel.
    """

    def __init__(
        self,
        config: Dict
    ):

        scanner_config = config.get(
            "scanner",
            {}
        )

        http_config = config.get(
            "http",
            {}
        )

        self.timeout = scanner_config.get(
            "timeout",
            1.5
        )

        self.threads = scanner_config.get(
            "threads",
            50
        )

        self.ports = scanner_config.get(
            "ports",
            []
        )

        self.discovery = HostDiscovery(
            timeout=self.timeout
        )

        self.port_scanner = PortScanner(
            timeout=self.timeout,
            threads=self.threads
        )

        self.http_analyzer = HTTPAnalyzer(
            timeout=http_config.get(
                "timeout",
                5
            ),
            user_agent=http_config.get(
                "user_agent",
                "CyberSentinel/1.0"
            )
        )

        self.tls_analyzer = TLSAnalyzer(
            timeout=http_config.get(
                "timeout",
                5
            )
        )

        self.finding_engine = FindingEngine()

    def scan_target(
        self,
        target: str
    ) -> Dict:

        logger.info(
            "Starting scan against target: %s",
            target
        )

        discovery_result = (
            self.discovery.check_host(target)
        )

        ip_address = discovery_result["ip"]

        logger.info(
            "Target resolved to %s",
            ip_address
        )

        logger.info(
            "Starting port scan against %s",
            ip_address
        )

        ports = self.port_scanner.scan(
            ip_address,
            self.ports
        )

        http_results = []

        tls_results = []

        for port_result in ports:

            port = port_result["port"]

            if port in {
                80,
                3000,
                5000,
                5601,
                8000,
                8080
            }:

                logger.info(
                    "Analyzing HTTP service on port %s",
                    port
                )

                result = self.http_analyzer.analyze(
                    ip_address,
                    port
                )

                http_results.append(
                    result
                )

            elif port in {
                443,
                8443
            }:

                logger.info(
                    "Analyzing HTTPS service on port %s",
                    port
                )

                http_result = (
                    self.http_analyzer.analyze(
                        ip_address,
                        port
                    )
                )

                http_results.append(
                    http_result
                )

                tls_result = (
                    self.tls_analyzer.analyze(
                        ip_address,
                        port
                    )
                )

                tls_results.append(
                    tls_result
                )

        findings = self.finding_engine.analyze(
            ports=ports,
            http_results=http_results,
            tls_results=tls_results
        )

        risk_score = (
            self.finding_engine.calculate_risk(
                findings
            )
        )

        result = {
            "target": target,
            "ip": ip_address,
            "discovery": discovery_result,
            "ports": ports,
            "http": http_results,
            "tls": tls_results,
            "findings": findings,
            "risk_score": risk_score
        }

        logger.info(
            "Scan completed for %s. Risk score: %s",
            target,
            risk_score
        )

        return result

    def scan_targets(
        self,
        targets: List[str]
    ) -> List[Dict]:

        results = []

        for target in targets:

            try:

                result = self.scan_target(
                    target
                )

                results.append(
                    result
                )

            except Exception as error:

                logger.error(
                    "Scan failed for %s: %s",
                    target,
                    error
                )

                results.append({
                    "target": target,
                    "error": str(error)
                })

        return results