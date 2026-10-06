import socket
import ssl
import logging
from datetime import datetime, timezone
from typing import Dict


logger = logging.getLogger(__name__)


class TLSAnalyzer:
    """
    Performs basic TLS and certificate inspection.
    """

    def __init__(
        self,
        timeout: float = 5
    ):
        self.timeout = timeout

    def analyze(
        self,
        host: str,
        port: int = 443
    ) -> Dict:

        result = {
            "host": host,
            "port": port,
            "protocol": None,
            "cipher": None,
            "certificate": {},
            "error": None
        }

        context = ssl.create_default_context()

        try:

            with socket.create_connection(
                (host, port),
                timeout=self.timeout
            ) as raw_socket:

                with context.wrap_socket(
                    raw_socket,
                    server_hostname=host
                ) as tls_socket:

                    result["protocol"] = (
                        tls_socket.version()
                    )

                    cipher = tls_socket.cipher()

                    if cipher:
                        result["cipher"] = {
                            "name": cipher[0],
                            "protocol": cipher[1],
                            "bits": cipher[2]
                        }

                    certificate = (
                        tls_socket.getpeercert()
                    )

                    result["certificate"] = (
                        self.parse_certificate(
                            certificate
                        )
                    )

        except Exception as error:

            logger.debug(
                "TLS analysis failed for %s:%s - %s",
                host,
                port,
                error
            )

            result["error"] = str(error)

        return result

    def parse_certificate(
        self,
        certificate: Dict
    ) -> Dict:

        if not certificate:
            return {}

        subject = self.extract_name(
            certificate.get(
                "subject",
                ()
            )
        )

        issuer = self.extract_name(
            certificate.get(
                "issuer",
                ()
            )
        )

        expiry_string = certificate.get(
            "notAfter"
        )

        days_remaining = None

        if expiry_string:

            try:

                expiry_date = datetime.strptime(
                    expiry_string,
                    "%b %d %H:%M:%S %Y %Z"
                ).replace(
                    tzinfo=timezone.utc
                )

                now = datetime.now(
                    timezone.utc
                )

                days_remaining = (
                    expiry_date - now
                ).days

            except ValueError:

                days_remaining = None

        return {
            "subject": subject,
            "issuer": issuer,
            "expires": expiry_string,
            "days_remaining": days_remaining
        }

    @staticmethod
    def extract_name(
        name_structure
    ) -> Dict:

        result = {}

        for attribute_group in name_structure:

            for key, value in attribute_group:

                result[key] = value

        return result