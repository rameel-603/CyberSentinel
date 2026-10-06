import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional


logger = logging.getLogger(__name__)


SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker API",
    3000: "HTTP",
    3306: "MySQL",
    3389: "RDP",
    5000: "HTTP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5900: "VNC",
    6379: "Redis",
    6443: "Kubernetes API",
    8000: "HTTP",
    8080: "HTTP Proxy",
    8443: "HTTPS",
    9200: "Elasticsearch",
    27017: "MongoDB"
}


class PortScanner:
    """
    Multi-threaded TCP port scanner.
    """

    def __init__(
        self,
        timeout: float = 1.5,
        threads: int = 50
    ):
        self.timeout = timeout
        self.threads = threads

    def scan_port(
        self,
        host: str,
        port: int
    ) -> Optional[Dict]:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(self.timeout)

        try:

            result = sock.connect_ex(
                (host, port)
            )

            if result != 0:
                return None

            service = SERVICE_MAP.get(
                port,
                "Unknown"
            )

            banner = self.grab_banner(
                sock,
                port
            )

            return {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner
            }

        except socket.error as error:

            logger.debug(
                "Error scanning %s:%s - %s",
                host,
                port,
                error
            )

            return None

        finally:
            sock.close()

    def grab_banner(
        self,
        sock: socket.socket,
        port: int
    ) -> Optional[str]:

        banner_ports = {
            21,
            22,
            25,
            110,
            143,
            587
        }

        if port not in banner_ports:
            return None

        try:

            sock.settimeout(
                min(self.timeout, 2.0)
            )

            data = sock.recv(1024)

            if not data:
                return None

            banner = data.decode(
                "utf-8",
                errors="replace"
            ).strip()

            return banner[:500]

        except socket.timeout:
            return None

        except socket.error:
            return None

    def scan(
        self,
        host: str,
        ports: List[int]
    ) -> List[Dict]:

        results = []

        logger.info(
            "Starting port scan against %s",
            host
        )

        with ThreadPoolExecutor(
            max_workers=self.threads
        ) as executor:

            futures = {
                executor.submit(
                    self.scan_port,
                    host,
                    port
                ): port

                for port in ports
            }

            for future in as_completed(futures):

                port = futures[future]

                try:

                    result = future.result()

                    if result:

                        results.append(result)

                        logger.info(
                            "Port %s is open on %s",
                            port,
                            host
                        )

                except Exception as error:

                    logger.error(
                        "Port %s scan failed: %s",
                        port,
                        error
                    )

        results.sort(
            key=lambda item: item["port"]
        )

        logger.info(
            "Port scan completed. %s open ports found.",
            len(results)
        )

        return results