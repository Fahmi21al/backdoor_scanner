# System Forensic Scanner (SFS)

System Forensic Scanner (SFS) is a digital forensic and incident response platform designed to investigate web applications suspected of security compromises. It operates strictly in **read-only** mode without modifying target files, ensuring forensic integrity.

## Features

- **Core File Forensics**: Detects modified files, unauthorized additional files, malware/webshells, and Indicators of Compromise (IOC) by comparing source code with clean baselines.
- **Malware & Webshell Detection**: Integrates YARA rules and IOC regex scanning to identify backdoors, webshells, and malicious payloads.
- **Attack Surface Discovery**: Utilizes specialized tools like Katana and Httpx to discover exposed endpoints and profile the technology stack.
- **Vulnerability Assessment**: Runs Nuclei templates to discover CVEs and misconfigurations in the target application.
- **Database Forensics**: Parses and analyzes `.sql` and `.sql.gz` dumps to detect new administrator accounts or suspicious roles.
- **Timeline Reconstruction**: Reconstructs events sequentially from filesystem changes, access logs, and database events.
- **Risk Scoring Engine**: Calculates an overall risk score using defined weights based on findings.
- **Comprehensive Reporting**: Generates detailed reports in JSON, HTML, and PDF formats for further analysis.

## Supported Target Applications
- Open Journal Systems (OJS)
- WordPress
- Laravel
- Moodle
- Generic PHP Applications

## Tech Stack

- **Backend Language**: Golang 1.25+
- **Database**: PostgreSQL 17+
- **Frontend UI**: HTML, CSS, JavaScript (Vanilla)
- **Engines & Tools**:
  - `go-yara/v4` for YARA rule matching
  - `go-difflib` for generating unified diffs
  - [Nuclei](https://github.com/projectdiscovery/nuclei) for vulnerability scanning
  - [Katana](https://github.com/projectdiscovery/katana) for crawling and attack surface discovery
  - [Httpx](https://github.com/projectdiscovery/httpx) for HTTP probing

## Getting Started

### Prerequisites
- Go 1.25 or higher
- PostgreSQL 17 or higher
- Make sure Nuclei, Katana, and Httpx are installed and accessible in your system's PATH.

### Setup Instructions

1. **Clone the Repository**
   ```bash
   git clone https://github.com/Fahmi21al/backdoor_scanner.git
   cd backdoor_scanner/sfs
   ```

2. **Install Dependencies**
   Run the following command to download and install all required Go modules:
   ```bash
   go mod tidy
   ```

3. **Configure the Database**
   - Create a PostgreSQL database for SFS.
   - Update your connection settings as required by the application configuration.

4. **Run the Application**
   ```bash
   go run cmd/api/main.go
   ```

5. **Access the Web Interface**
   Open your browser and navigate to the application web interface.

## Architecture

SFS uses a **Modular Monolith** architecture, consisting of specialized engines: Baseline, Hash, Diff, YARA, IOC, Katana, Httpx, Nuclei, Audit, Database Forensic, Timeline, Risk, and Reporting. 

## Development Roadmap
- Live Database Connections
- Multi-User and API Authentication
- Cluster / Distributed Scanning
- SIEM / SOC / EDR Integration
- Real-time continuous monitoring (Agent Mode)
