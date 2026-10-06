"""
CyberSentinel Database Module

Responsible for:

- SQLite database initialization
- Scan records
- IP address storage
- Port storage
- Security finding storage
- Scan history
- Complete scan retrieval
- Database compatibility/migration
"""

import sqlite3
import logging
from datetime import datetime
from typing import Optional, Dict, List, Any


logger = logging.getLogger(__name__)


class Database:
    """
    SQLite database manager for CyberSentinel.
    """

    # ============================================================
    # INITIALIZATION
    # ============================================================

    def __init__(self, database_path: str):
        """
        Initialize the SQLite database.
        """

        self.database_path = database_path

        self.connection = sqlite3.connect(
            database_path
        )

        # Allows rows to behave like dictionaries.
        self.connection.row_factory = sqlite3.Row

        # Enable foreign key support.
        self.connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        self._create_tables()

        logger.info(
            "Database initialized: %s",
            database_path
        )

    # ============================================================
    # TABLE CREATION / MIGRATION
    # ============================================================

    def _create_tables(self) -> None:
        """
        Create the CyberSentinel database tables.

        Existing databases are preserved.
        Missing columns are added automatically.
        """

        cursor = self.connection.cursor()

        # --------------------------------------------------------
        # SCANS TABLE
        # --------------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                ip_address TEXT,
                started_at TEXT,
                completed_at TEXT,
                status TEXT DEFAULT 'running',
                risk_score INTEGER DEFAULT 0,
                profile TEXT
            )
            """
        )

        # --------------------------------------------------------
        # MIGRATE EXISTING SCANS TABLE
        # --------------------------------------------------------

        cursor.execute(
            """
            PRAGMA table_info(scans)
            """
        )

        existing_columns = {
            row["name"]
            for row in cursor.fetchall()
        }

        required_scan_columns = {
            "ip_address": "TEXT",
            "started_at": "TEXT",
            "completed_at": "TEXT",
            "status": "TEXT",
            "risk_score": "INTEGER",
            "profile": "TEXT"
        }

        for column_name, column_type in required_scan_columns.items():

            if column_name not in existing_columns:

                cursor.execute(
                    f"""
                    ALTER TABLE scans
                    ADD COLUMN {column_name} {column_type}
                    """
                )

                logger.info(
                    "Database migration: added scans.%s",
                    column_name
                )

        # --------------------------------------------------------
        # PORTS TABLE
        # --------------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT DEFAULT 'tcp',
                service TEXT,
                state TEXT,
                banner TEXT,
                FOREIGN KEY (scan_id)
                    REFERENCES scans(id)
                    ON DELETE CASCADE
            )
            """
        )

        # --------------------------------------------------------
        # FINDINGS TABLE
        # --------------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                severity TEXT,
                description TEXT,
                evidence TEXT,
                recommendation TEXT,
                FOREIGN KEY (scan_id)
                    REFERENCES scans(id)
                    ON DELETE CASCADE
            )
            """
        )

        self.connection.commit()

        logger.info(
            "Database tables verified"
        )

    # ============================================================
    # CREATE SCAN
    # ============================================================

    def create_scan(
        self,
        target: str,
        started_at: Optional[str] = None,
        ip_address: Optional[str] = None,
        profile: Optional[str] = None,
        **kwargs
    ) -> int:
        """
        Create a new scan.

        started_at is optional so that different versions of
        main.py can use this database module safely.

        Additional keyword arguments are accepted for compatibility.
        """

        # --------------------------------------------------------
        # TIMESTAMP
        # --------------------------------------------------------

        if started_at is None:

            started_at = datetime.now().isoformat()

        # --------------------------------------------------------
        # COMPATIBILITY
        # --------------------------------------------------------
        #
        # Some versions of main.py may use slightly different
        # names for the resolved IP address or scan profile.
        # --------------------------------------------------------

        if ip_address is None:

            ip_address = kwargs.get(
                "ip"
            )

        if ip_address is None:

            ip_address = kwargs.get(
                "resolved_ip"
            )

        if profile is None:

            profile = kwargs.get(
                "scan_profile"
            )

        # --------------------------------------------------------
        # INSERT SCAN
        # --------------------------------------------------------

        cursor = self.connection.cursor()

        cursor.execute(
            """
            INSERT INTO scans (
                target,
                ip_address,
                started_at,
                completed_at,
                status,
                risk_score,
                profile
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target,
                ip_address,
                started_at,
                None,
                "running",
                0,
                profile
            )
        )

        self.connection.commit()

        scan_id = cursor.lastrowid

        logger.info(
            "Created scan %s for target %s",
            scan_id,
            target
        )

        return int(scan_id)

    # ============================================================
    # COMPLETE SCAN
    # ============================================================

    def complete_scan(
        self,
        scan_id: int,
        completed_at: Optional[str] = None,
        risk_score: int = 0,
        status: str = "completed",
        **kwargs
    ) -> None:
        """
        Mark a scan as completed.
        """

        if completed_at is None:

            completed_at = datetime.now().isoformat()

        # Allow alternate argument names from main.py.
        if "score" in kwargs:

            risk_score = kwargs["score"]

        cursor = self.connection.cursor()

        cursor.execute(
            """
            UPDATE scans
            SET
                completed_at = ?,
                status = ?,
                risk_score = ?
            WHERE id = ?
            """,
            (
                completed_at,
                status,
                risk_score,
                scan_id
            )
        )

        self.connection.commit()

        logger.info(
            "Completed scan %s with risk score %s",
            scan_id,
            risk_score
        )

    # ============================================================
    # GET SINGLE SCAN
    # ============================================================

    def get_scan(
        self,
        scan_id: int
    ) -> Optional[Dict]:
        """
        Retrieve one scan record.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM scans
            WHERE id = ?
            """,
            (scan_id,)
        )

        row = cursor.fetchone()

        if row is None:

            return None

        return dict(row)

    # ============================================================
    # GET RECENT SCANS
    # ============================================================

    def get_recent_scans(
        self,
        limit: int = 10
    ) -> List[Dict]:
        """
        Retrieve the most recent scans.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )

        rows = cursor.fetchall()

        return [
            dict(row)
            for row in rows
        ]

    # ============================================================
    # SAVE PORT
    # ============================================================

    def save_port(
        self,
        scan_id: int,
        port_data: Dict[str, Any]
    ) -> None:
        """
        Save an open port.
        """

        port_number = port_data.get(
            "port"
        )

        protocol = port_data.get(
            "protocol",
            "tcp"
        )

        service = port_data.get(
            "service",
            "Unknown"
        )

        state = port_data.get(
            "state",
            "open"
        )

        banner = port_data.get(
            "banner"
        )

        cursor = self.connection.cursor()

        cursor.execute(
            """
            INSERT INTO ports (
                scan_id,
                port,
                protocol,
                service,
                state,
                banner
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                port_number,
                protocol,
                service,
                state,
                banner
            )
        )

        self.connection.commit()

        logger.debug(
            "Saved port %s for scan %s",
            port_number,
            scan_id
        )

    # ============================================================
    # GET SCAN PORTS
    # ============================================================

    def get_scan_ports(
        self,
        scan_id: int
    ) -> List[Dict]:
        """
        Retrieve all ports belonging to a scan.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM ports
            WHERE scan_id = ?
            ORDER BY port
            """,
            (scan_id,)
        )

        rows = cursor.fetchall()

        return [
            dict(row)
            for row in rows
        ]

    # ============================================================
    # SAVE FINDING
    # ============================================================

    def save_finding(
        self,
        scan_id: int,
        finding_data: Dict[str, Any]
    ) -> None:
        """
        Save a security finding.
        """

        title = finding_data.get(
            "title",
            "Unknown Finding"
        )

        severity = finding_data.get(
            "severity",
            "info"
        )

        description = finding_data.get(
            "description",
            ""
        )

        evidence = finding_data.get(
            "evidence",
            ""
        )

        recommendation = finding_data.get(
            "recommendation",
            ""
        )

        cursor = self.connection.cursor()

        cursor.execute(
            """
            INSERT INTO findings (
                scan_id,
                title,
                severity,
                description,
                evidence,
                recommendation
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                title,
                severity,
                description,
                evidence,
                recommendation
            )
        )

        self.connection.commit()

        logger.debug(
            "Saved finding '%s' for scan %s",
            title,
            scan_id
        )

    # ============================================================
    # GET SCAN FINDINGS
    # ============================================================

    def get_scan_findings(
        self,
        scan_id: int
    ) -> List[Dict]:
        """
        Retrieve all findings belonging to a scan.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM findings
            WHERE scan_id = ?
            ORDER BY id
            """,
            (scan_id,)
        )

        rows = cursor.fetchall()

        return [
            dict(row)
            for row in rows
        ]

    # ============================================================
    # GET COMPLETE SCAN
    # ============================================================

    def get_complete_scan(
        self,
        scan_id: int
    ) -> Optional[Dict]:
        """
        Retrieve a complete scan.

        Includes:

        - Scan information
        - Target
        - IP address
        - Risk score
        - Ports
        - Findings
        """

        scan = self.get_scan(
            scan_id
        )

        if scan is None:

            return None

        scan["ports"] = self.get_scan_ports(
            scan_id
        )

        scan["findings"] = self.get_scan_findings(
            scan_id
        )

        return scan

    # ============================================================
    # DELETE SCAN
    # ============================================================

    def delete_scan(
        self,
        scan_id: int
    ) -> bool:
        """
        Delete a scan and its associated ports/findings.

        Foreign-key cascade handles the related records.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            DELETE FROM scans
            WHERE id = ?
            """,
            (scan_id,)
        )

        deleted = cursor.rowcount > 0

        self.connection.commit()

        if deleted:

            logger.info(
                "Deleted scan %s",
                scan_id
            )

        return deleted

    # ============================================================
    # DATABASE CONNECTION
    # ============================================================

    def close(self) -> None:
        """
        Close the database connection.
        """

        if self.connection:

            self.connection.close()

            logger.info(
                "Database connection closed"
            )