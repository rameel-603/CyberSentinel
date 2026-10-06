# CyberSentinel

CyberSentinel is a defensive network security auditing and reconnaissance tool written in Python.

It is designed for authorized security assessments, cybersecurity labs, internal network auditing, and educational purposes.

## Features

- TCP host discovery
- Threaded port scanning
- Service identification
- Banner collection
- HTTP analysis
- HTTP security-header checks
- TLS analysis
- Certificate information
- Security findings
- Severity classification
- Risk scoring
- SQLite persistence
- Scan IDs
- Scan history
- Historical comparison
- JSON output
- HTML dashboard
- Professional HTML assessment report
- Scan profiles
- Custom ports
- Timeout configuration
- Thread configuration
- Logging
- CLI

## Project Architecture

CyberSentinel is divided into several components.

```text
main.py
   |
   v
engine.py
   |
   +-- discovery.py
   |
   +-- port_scanner.py
   |
   +-- http_analyzer.py
   |
   +-- tls_analyzer.py
   |
   +-- findings.py
   |
   v
Database / Reports