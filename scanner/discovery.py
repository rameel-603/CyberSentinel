import socket
import logging
from typing import Dict, List


logger = logging.getLogger(__name__)


class HostDiscovery:
    

    DEFAULT_CHECK_PORTS = [
        22,
        80,
        443,
        445,
        3389
    ]

    def __init__(self, timeout: float = 1.5):
        self.timeout = timeout

    def resolve_hostname(self, target: str) -> str:
        

        try:
            ip_address = socket.gethostbyname(target)

            logger.debug(
                "Resolved %s to %s",
                target,
                ip_address
            )

            return ip_address

        except socket.gaierror as error:
            logger.error(
                "Unable to resolve target %s: %s",
                target,
                error
            )

            raise ValueError(
                f"Unable to resolve target: {target}"
            ) from error

    def check_port(
        self,
        ip_address: str,
        port: int
    ) -> bool:
        """
        Check whether a TCP port accepts a connection.
        """

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(self.timeout)

        try:
            result = sock.connect_ex(
                (ip_address, port)
            )

            return result == 0

        except socket.error:
            return False

        finally:
            sock.close()

    def check_host(
        self,
        target: str,
        ports: List[int] | None = None
    ) -> Dict:

        if ports is None:
            ports = self.DEFAULT_CHECK_PORTS

        ip_address = self.resolve_hostname(target)

        responsive_ports = []

        for port in ports:

            logger.debug(
                "Checking %s:%s",
                ip_address,
                port
            )

            if self.check_port(
                ip_address,
                port
            ):
                responsive_ports.append(port)

        reachable = len(responsive_ports) > 0

        return {
            "target": target,
            "ip": ip_address,
            "reachable": reachable,
            "responsive_ports": responsive_ports
        }