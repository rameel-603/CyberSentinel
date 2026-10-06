import logging
import time
import urllib.request
import urllib.error
from typing import Dict


logger = logging.getLogger(__name__)


class HTTPAnalyzer:
    """
    Performs basic HTTP security analysis.
    """

    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    def __init__(
        self,
        timeout: float = 5,
        user_agent: str = "CyberSentinel/1.0"
    ):
        self.timeout = timeout
        self.user_agent = user_agent

    def analyze(
        self,
        host: str,
        port: int
    ) -> Dict:

        scheme = "https" if port in {
            443,
            8443
        } else "http"

        url = f"{scheme}://{host}:{port}/"

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": self.user_agent
            }
        )

        start_time = time.perf_counter()

        try:

            with urllib.request.urlopen(
                request,
                timeout=self.timeout
            ) as response:

                elapsed = (
                    time.perf_counter()
                    - start_time
                )

                headers = dict(
                    response.headers
                )

                missing_headers = [
                    header
                    for header in self.SECURITY_HEADERS
                    if header not in headers
                ]

                server = headers.get(
                    "Server",
                    "Not disclosed"
                )

                return {
                    "url": url,
                    "status_code": response.status,
                    "server": server,
                    "headers": headers,
                    "missing_security_headers": missing_headers,
                    "response_time": round(
                        elapsed,
                        4
                    ),
                    "error": None
                }

        except urllib.error.HTTPError as error:

            elapsed = (
                time.perf_counter()
                - start_time
            )

            headers = dict(
                error.headers
            )

            missing_headers = [
                header
                for header in self.SECURITY_HEADERS
                if header not in headers
            ]

            return {
                "url": url,
                "status_code": error.code,
                "server": headers.get(
                    "Server",
                    "Not disclosed"
                ),
                "headers": headers,
                "missing_security_headers": missing_headers,
                "response_time": round(
                    elapsed,
                    4
                ),
                "error": None
            }

        except Exception as error:

            logger.debug(
                "HTTP analysis failed for %s: %s",
                url,
                error
            )

            return {
                "url": url,
                "status_code": None,
                "server": None,
                "headers": {},
                "missing_security_headers": [],
                "response_time": None,
                "error": str(error)
            }