import argparse
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional


from database.db import Database
from scanner.engine import ScanEngine
from reports.comparison import ScanComparator
from reports.dashboard import DashboardGenerator
from reports.security_report import SecurityReportGenerator


VERSION = "5.0.0"

LOGGER_NAME = "CyberSentinel"


def setup_logging(config: Dict) -> logging.Logger:
    """
    Configure CyberSentinel logging.
    """

    logging_config = config.get(
        "logging",
        {}
    )

    log_file = logging_config.get(
        "file",
        "logs/cybersentinel.log"
    )

    log_level = logging_config.get(
        "level",
        "INFO"
    ).upper()

    log_directory = os.path.dirname(
        log_file
    )

    if log_directory:
        os.makedirs(
            log_directory,
            exist_ok=True
        )

    logger = logging.getLogger(
        LOGGER_NAME
    )

    logger.setLevel(
        getattr(
            logging,
            log_level,
            logging.INFO
        )
    )

    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | "
        "%(name)s | %(message)s"
    )

    file_handler = logging.FileHandler(
        log_file,
        encoding="utf-8"
    )

    file_handler.setFormatter(
        formatter
    )

    console_handler = logging.StreamHandler(
        sys.stdout
    )

    console_handler.setFormatter(
        formatter
    )

    logger.addHandler(
        file_handler
    )

    logger.addHandler(
        console_handler
    )

    return logger


def load_config(
    config_path: str = "config.json"
) -> Dict:
    """
    Load CyberSentinel configuration.
    """

    if not os.path.exists(
        config_path
    ):
        raise FileNotFoundError(
            f"Configuration file not found: "
            f"{config_path}"
        )

    with open(
        config_path,
        "r",
        encoding="utf-8"
    ) as config_file:

        return json.load(
            config_file
        )


def list_profiles(
    config: Dict
) -> None:
    """
    Display configured scan profiles.
    """

    profiles = config.get(
        "profiles",
        {}
    )

    print()
    print("=" * 70)
    print("                  SCAN PROFILES")
    print("=" * 70)

    if not profiles:
        print("No profiles configured.")
        return

    for name, profile in profiles.items():

        ports = profile.get(
            "ports",
            []
        )

        print()
        print(f"Profile: {name}")
        print(f"Ports:   {', '.join(map(str, ports))}")

    print()
    print("=" * 70)


def parse_ports(
    ports_string: str
) -> List[int]:
    """
    Convert a comma-separated port list into integers.
    """

    ports = []

    for item in ports_string.split(","):

        item = item.strip()

        if not item:
            continue

        try:
            port = int(item)

        except ValueError:
            raise ValueError(
                f"Invalid port: {item}"
            )

        if port < 1 or port > 65535:
            raise ValueError(
                f"Port out of range: {port}"
            )

        ports.append(
            port
        )

    return sorted(
        set(ports)
    )


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    """

    parser = argparse.ArgumentParser(
        prog="cybersentinel",
        description=(
            "CyberSentinel - Defensive "
            "Network Security Auditor"
        )
    )

    parser.add_argument(
        "command",
        nargs="?",
        default="scan",
        choices=[
            "scan",
            "history",
            "compare",
            "report"
        ],
        help="Command to execute."
    )

    parser.add_argument(
        "targets",
        nargs="*",
        help=(
            "Target hostnames or IP addresses "
            "for scanning."
        )
    )

    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to configuration file."
    )

    parser.add_argument(
        "--ports",
        help=(
            "Comma-separated ports to scan. "
            "Overrides profile."
        )
    )

    parser.add_argument(
        "--profile",
        help="Scan profile to use."
    )

    parser.add_argument(
        "--timeout",
        type=float,
        help="TCP scanner timeout."
    )

    parser.add_argument(
        "--threads",
        type=int,
        help="Number of scanning threads."
    )

    parser.add_argument(
        "--scan-id",
        type=int,
        help="Database scan ID."
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Number of historical scans to display."
    )

    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List available scan profiles."
    )

    parser.add_argument(
        "--version",
        action="store_true",
        help="Display CyberSentinel version."
    )

    return parser.parse_args()


def prepare_scan_config(
    config: Dict,
    args: argparse.Namespace
) -> Dict:
    """
    Prepare scanner configuration using
    profile and command-line overrides.
    """

    scanner_config = config.setdefault(
        "scanner",
        {}
    )

    profiles = config.get(
        "profiles",
        {}
    )

    if args.profile:

        if args.profile not in profiles:
            raise ValueError(
                f"Unknown profile: "
                f"{args.profile}"
            )

        profile = profiles[
            args.profile
        ]

        scanner_config[
            "ports"
        ] = list(
            profile.get(
                "ports",
                []
            )
        )

    if args.ports:

        scanner_config[
            "ports"
        ] = parse_ports(
            args.ports
        )

    if args.timeout is not None:

        if args.timeout <= 0:
            raise ValueError(
                "Timeout must be greater than zero."
            )

        scanner_config[
            "timeout"
        ] = args.timeout

    if args.threads is not None:

        if args.threads <= 0:
            raise ValueError(
                "Threads must be greater than zero."
            )

        scanner_config[
            "threads"
        ] = args.threads

    return config


def save_json_report(
    result: Dict,
    output_directory: str = "output"
) -> str:
    """
    Save scan results as JSON.
    """

    os.makedirs(
        output_directory,
        exist_ok=True
    )

    path = os.path.join(
        output_directory,
        "scan_results.json"
    )

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as json_file:

        json.dump(
            result,
            json_file,
            indent=4,
            default=str
        )

    return path


def save_results_to_database(
    database: Database,
    result: Dict,
    started_at: str,
    completed_at: str,
    profile: Optional[str] = None
) -> Optional[int]:
    """
    Save a completed scan and its results
    to the SQLite database.
    """

    target = result.get(
        "target"
    )

    ip_address = result.get(
        "ip",
        result.get(
            "ip_address"
        )
    )

    try:

        scan_id = database.create_scan(
            target=target,
            started_at=started_at,
            ip_address=ip_address,
            profile=profile
        )

    except TypeError:

        # Compatibility fallback for an older
        # Database implementation that may not
        # support the profile parameter.

        scan_id = database.create_scan(
            target=target,
            started_at=started_at,
            ip_address=ip_address
        )

    for port in result.get(
        "ports",
        []
    ):

        database.save_port(
            scan_id,
            port
        )

    for finding in result.get(
        "findings",
        []
    ):

        database.save_finding(
            scan_id,
            finding
        )

    try:

        database.complete_scan(
            scan_id=scan_id,
            completed_at=completed_at,
            risk_score=result.get(
                "risk_score",
                0
            ),
            status="completed"
        )

    except TypeError:

        # Compatibility fallback for an older
        # complete_scan implementation.

        database.complete_scan(
            scan_id=scan_id,
            completed_at=completed_at,
            risk_score=result.get(
                "risk_score",
                0
            )
        )

    return scan_id


def print_scan_summary(
    result: Dict,
    scan_id: Optional[int] = None
) -> None:
    """
    Display a scan summary.
    """

    print()
    print("=" * 70)
    print("                     SCAN SUMMARY")
    print("=" * 70)

    print(
        f"Target:      "
        f"{result.get('target', 'Unknown')}"
    )

    print(
        f"IP Address:  "
        f"{result.get('ip', 'Unknown')}"
    )

    print(
        f"Open Ports:  "
        f"{len(result.get('ports', []))}"
    )

    print(
        f"Findings:    "
        f"{len(result.get('findings', []))}"
    )

    print(
        f"Risk Score:  "
        f"{result.get('risk_score', 0)}/100"
    )

    if scan_id is not None:

        print(
            f"Scan ID:     {scan_id}"
        )

    print("=" * 70)


def show_history(
    database: Database,
    limit: int = 10
) -> None:
    """
    Display historical scans.
    """

    scans = database.get_recent_scans(
        limit=limit
    )

    print()
    print("=" * 100)
    print("                         SCAN HISTORY")
    print("=" * 100)

    if not scans:

        print(
            "No scans have been recorded."
        )

        print("=" * 100)
        return

    print(
        f"{'ID':<6}"
        f"{'Target':<28}"
        f"{'IP':<18}"
        f"{'Risk':<10}"
        f"{'Status':<15}"
        f"{'Started'}"
    )

    print("-" * 100)

    for scan in scans:

        scan_id = scan.get(
            "id",
            ""
        )

        target = str(
            scan.get(
                "target",
                ""
            )
        )[:26]

        ip_address = str(
            scan.get(
                "ip_address",
                scan.get(
                    "ip",
                    ""
                )
            )
        )[:16]

        risk = scan.get(
            "risk_score",
            0
        )

        status = str(
            scan.get(
                "status",
                ""
            )
        )[:13]

        started = scan.get(
            "started_at",
            ""
        )

        print(
            f"{str(scan_id):<6}"
            f"{target:<28}"
            f"{ip_address:<18}"
            f"{str(risk):<10}"
            f"{status:<15}"
            f"{started}"
        )

    print("=" * 100)


def build_scan_from_database(
    database: Database,
    scan_id: int
) -> Optional[Dict]:
    """
    Reconstruct a complete scan from the database.
    """

    return database.get_complete_scan(
        scan_id
    )


def compare_scans(
    database: Database,
    scan_id: int
) -> bool:
    """
    Compare the selected scan with the
    previous available scan.
    """

    current = database.get_complete_scan(
        scan_id
    )

    if current is None:

        print(
            f"[!] Scan ID {scan_id} "
            f"was not found."
        )

        return False

    recent_scans = database.get_recent_scans(
        limit=50
    )

    previous_scan = None

    for scan in recent_scans:

        current_id = scan.get(
            "id"
        )

        if current_id is None:
            continue

        if int(current_id) != int(
            scan_id
        ):

            previous_scan = (
                database.get_complete_scan(
                    int(current_id)
                )
            )

            if previous_scan is not None:
                break

    if previous_scan is None:

        print()
        print(
            "[!] No previous scan is available "
            "for comparison."
        )

        print(
            "[*] Run another scan against the "
            "same authorized target first."
        )

        return False

    comparator = ScanComparator()

    comparison = comparator.compare(
        previous_scan,
        current
    )

    comparator.print_comparison(
        comparison
    )

    return True


def generate_dashboard(
    database: Database,
    scan_id: int,
    output_path: str = "output/dashboard.html"
) -> bool:
    """
    Generate the HTML dashboard for a stored scan.
    """

    scan = database.get_complete_scan(
        scan_id
    )

    if scan is None:

        print(
            f"[!] Scan ID {scan_id} "
            f"was not found."
        )

        return False

    comparison = None

    recent_scans = database.get_recent_scans(
        limit=50
    )

    previous_scan = None

    for historical_scan in recent_scans:

        historical_id = historical_scan.get(
            "id"
        )

        if historical_id is None:
            continue

        if int(historical_id) != int(
            scan_id
        ):

            previous_scan = (
                database.get_complete_scan(
                    int(historical_id)
                )
            )

            if previous_scan is not None:
                break

    if previous_scan is not None:

        comparator = ScanComparator()

        comparison = comparator.compare(
            previous_scan,
            scan
        )

    generator = DashboardGenerator()

    try:

        generator.generate(
            scan=scan,
            comparison=comparison,
            database=database,
            output_path=output_path
        )

    except TypeError:

        # Compatibility fallback for dashboard
        # generator implementations with a
        # different method signature.

        try:

            generator.generate(
                scan=scan,
                comparison=comparison,
                output_path=output_path
            )

        except TypeError:

            generator.generate(
                scan,
                comparison,
                output_path
            )

    print(
        f"[*] Dashboard generated: "
        f"{output_path}"
    )

    return True


def generate_security_report(
    database: Database,
    scan_id: int
) -> bool:
    """
    Generate a professional HTML security
    assessment report from a stored scan.
    """

    scan = database.get_complete_scan(
        scan_id
    )

    if scan is None:

        print(
            f"[!] Scan ID {scan_id} "
            f"was not found."
        )

        return False

    comparison = None

    try:

        recent_scans = database.get_recent_scans(
            limit=50
        )

        previous_scan = None

        for historical_scan in recent_scans:

            historical_id = historical_scan.get(
                "id"
            )

            if historical_id is None:
                continue

            if int(historical_id) != int(
                scan_id
            ):

                previous_scan = (
                    database.get_complete_scan(
                        int(historical_id)
                    )
                )

                if previous_scan is not None:
                    break

        if previous_scan is not None:

            comparator = ScanComparator()

            comparison = comparator.compare(
                previous_scan,
                scan
            )

    except Exception as error:

        logging.getLogger(
            LOGGER_NAME
        ).warning(
            "Historical comparison unavailable: %s",
            error
        )

    generator = SecurityReportGenerator(
        output_directory="output/reports"
    )

    report_path = generator.generate(
        scan=scan,
        comparison=comparison,
        filename=(
            f"security_report_scan_"
            f"{scan_id}.html"
        )
    )

    print()
    print("=" * 70)
    print("                SECURITY REPORT GENERATED")
    print("=" * 70)

    print(
        f"Scan ID:    {scan_id}"
    )

    print(
        f"Target:     "
        f"{scan.get('target', 'Unknown')}"
    )

    print(
        f"Risk Score: "
        f"{scan.get('risk_score', 0)}/100"
    )

    print()
    print(
        f"Report:     {report_path}"
    )

    print("=" * 70)

    return True


def run_scan(
    database: Database,
    config: Dict,
    target: str,
    profile: Optional[str]
) -> Optional[Dict]:
    """
    Execute a scan, save the results,
    generate the dashboard, and return
    the scan result.
    """

    logger = logging.getLogger(
        LOGGER_NAME
    )

    print()
    print(
        f"[*] Starting scan: {target}"
    )

    started_at = datetime.now().isoformat()

    try:

        engine = ScanEngine(
            config
        )

        # IMPORTANT:
        # ScanEngine uses scan_target(),
        # not scan().

        result = engine.scan_target(
            target
        )

        completed_at = datetime.now().isoformat()

        scan_id = save_results_to_database(
            database=database,
            result=result,
            started_at=started_at,
            completed_at=completed_at,
            profile=profile
        )

        json_path = save_json_report(
            result
        )

        print_scan_summary(
            result,
            scan_id=scan_id
        )

        print()
        print(
            f"[*] JSON report: {json_path}"
        )

        # Generate dashboard automatically.

        if scan_id is not None:

            try:

                generate_dashboard(
                    database,
                    scan_id
                )

            except Exception as dashboard_error:

                logger.warning(
                    "Dashboard generation failed: %s",
                    dashboard_error
                )

                print(
                    "[!] Dashboard generation "
                    "failed, but the scan itself "
                    "completed successfully."
                )

        print()
        print(
            f"[*] Scan completed successfully."
        )

        return result

    except Exception:

        logger.exception(
            "Scan failed."
        )

        print()
        print(
            "[!] Scan failed. "
            "Check the log for details."
        )

        return None


def main() -> int:
    """
    CyberSentinel application entry point.
    """

    args = parse_arguments()

    if args.version:

        print(
            f"CyberSentinel {VERSION}"
        )

        return 0

    try:

        config = load_config(
            args.config
        )

    except Exception as error:

        print(
            f"[!] Configuration error: "
            f"{error}"
        )

        return 1

    try:

        logger = setup_logging(
            config
        )

    except Exception as error:

        print(
            f"[!] Logging setup failed: "
            f"{error}"
        )

        return 1

    if args.list_profiles:

        list_profiles(
            config
        )

        return 0

    try:

        config = prepare_scan_config(
            config,
            args
        )

    except Exception as error:

        print(
            f"[!] Configuration error: "
            f"{error}"
        )

        return 1

    database_config = config.get(
        "database",
        {}
    )

    database_path = database_config.get(
        "path",
        "cybersentinel.db"
    )

    database = Database(
        database_path
    )

    try:

        # --------------------------------------------------
        # HISTORY
        # --------------------------------------------------

        if args.command == "history":

            if args.scan_id is not None:

                scan = database.get_complete_scan(
                    args.scan_id
                )

                if scan is None:

                    print(
                        f"[!] Scan ID "
                        f"{args.scan_id} "
                        f"was not found."
                    )

                    return 1

                print_scan_summary(
                    scan,
                    scan_id=args.scan_id
                )

                return 0

            show_history(
                database,
                limit=args.limit
            )

            return 0

        # --------------------------------------------------
        # COMPARE
        # --------------------------------------------------

        if args.command == "compare":

            if args.scan_id is None:

                print(
                    "[!] --scan-id is required "
                    "for comparison."
                )

                print()
                print(
                    "Example:"
                )
                print(
                    "python3 main.py "
                    "compare --scan-id 4"
                )

                return 1

            return (
                0
                if compare_scans(
                    database,
                    args.scan_id
                )
                else 1
            )

        # --------------------------------------------------
        # REPORT
        # --------------------------------------------------

        if args.command == "report":

            if args.scan_id is None:

                print(
                    "[!] --scan-id is required "
                    "to generate a report."
                )

                print()
                print(
                    "Example:"
                )

                print(
                    "python3 main.py "
                    "report --scan-id 4"
                )

                return 1

            return (
                0
                if generate_security_report(
                    database,
                    args.scan_id
                )
                else 1
            )

        # --------------------------------------------------
        # SCAN
        # --------------------------------------------------

        if args.command == "scan":

            if not args.targets:

                print(
                    "[!] No target specified."
                )

                print()
                print(
                    "Example:"
                )

                print(
                    "python3 main.py "
                    "scan 127.0.0.1 "
                    "--profile quick"
                )

                return 1

            successful_scans = 0

            for target in args.targets:

                result = run_scan(
                    database=database,
                    config=config,
                    target=target,
                    profile=args.profile
                )

                if result is not None:
                    successful_scans += 1

            if successful_scans == 0:

                print()
                print(
                    "[!] No scans completed "
                    "successfully."
                )

                return 1

            print()
            print(
                f"[*] {successful_scans} "
                f"scan(s) completed successfully."
            )

            return 0

        return 0

    finally:

        try:
            database.close()

        except Exception as error:

            logger.warning(
                "Database close failed: %s",
                error
            )


if __name__ == "__main__":
    sys.exit(
        main()
    )