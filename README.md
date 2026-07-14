# SecurScout 🔍
### **An Automated Service & CVE Vulnerability Auditor**

SecurScout is a portfolio-grade security scanner and reporting tool designed for automated network scoping, port auditing, service version mapping, and prioritized risk profiling. It combines the speed of Nmap network discovery with context-weighted CVSS risk calculations, SQLite history tracking, and a local browser-based security dashboard.

---

## 🌟 Key Features

* **Target Validation & Scoping:** Automatically validates IPv4 addresses, CIDR ranges, and hostnames while filtering out excluded nodes.
* **Service & Version Audit:** Programmatically invokes Nmap to identify open ports, active services, protocol information, and software version banners.
* **Web Vulnerability Scanning:** Actively detects SQL Injections, XSS, CSRF, and SSL weaknesses by running Nmap NSE web-scanning scripts.
* **CVE Mapping:** Matches parsed CPE strings against NVD (National Vulnerability Database) and CIRCL APIs to identify known vulnerabilities.
* **Context-Weighted Risk Math:** Computes adjusted vulnerability risks using host criticalities, service exposures, and vulnerability density factors.
* **Client-Ready HTML Reports:** Compiles findings into print-optimized HTML reports containing KPIs, actionable version upgrade advisories, and severity distribution SVG charts.
* **Security Analyst Dashboard:** A sleek, responsive, dark-themed Single-Page Application (SPA) dashboard powered by Flask to launch scans, monitor active tasks, inspect logs, and download reports.

---

## 🛠️ Prerequisites & Installation

### 1. Install Nmap
To perform live network scans, Nmap must be installed on the host system:
* **Windows:** Download the installer from [nmap.org/download.html](https://nmap.org/download.html) and verify that Nmap is added to your System PATH during installation.
* **Linux:** Run `sudo apt install nmap` or `sudo yum install nmap`.
* **macOS:** Run `brew install nmap`.

### 2. Clone and Setup
1. Clone this repository to your local machine.
2. Install the Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Create a `.env` file in the root directory to store your NVD API Key (optional, increases API rate limits):
   ```text
   NVD_API_KEY=your_nvd_api_key_here
   ```

---

## 🚀 How to Run

### 1. Launch the Web UI Dashboard
To boot the local web server and automatically open the analyst console in your default browser, run:
```bash
python -m SecurScout --web
```
*(On Windows, you can simply double-click the **`run_dashboard.bat`** file).*

### 2. Command Line Interface (CLI) Examples

* **Display Help Options:**
  ```bash
  python -m SecurScout --help
  ```
* **Fast Network Scan (Outputs JSON):**
  ```bash
  python -m SecurScout 192.168.1.15 --fast
  ```
* **Scan & Generate HTML Report:**
  ```bash
  python -m SecurScout 192.168.1.0/24 --html report.html
  ```
* **Intensive Web-Scan with OS Detection:**
  ```bash
  python -m SecurScout scanme.nmap.org -O --web-scan --html web_report.html
  ```
* **View Past Scan Logs from SQLite History:**
  ```bash
  python -m SecurScout --history
  ```

---

## 📁 Repository Structure

* **`SecurScout/`** - Core package source code:
  * `scan_engine/` - Scoping, Nmap subprocess executions, XML parsing.
  * `vuln_lookup/` - CPE mappings, NVD API clients, SQLite caching.
  * `scoring/` - Context-weighted host risk calculators.
  * `reporter/` - HTML report compiler & Jinja2 templates.
  * `web_ui/` - Flask REST APIs and web dashboard templates.
* **`requirements.txt`** - Dependency manifest.
* **`run_dashboard.bat`** - One-click launcher script.
* **`vulnerability_assessment_report_template.md`** - A professional 15-part vulnerability assessment report template for project documentation.

---

## 🔒 Legal Notice & Compliance
SecurScout is intended strictly for authorized security testing and research purposes. Scanning target systems without explicit authorization from the asset owner is illegal and violates network policies. The author assumes no liability for misuse of this tool.
