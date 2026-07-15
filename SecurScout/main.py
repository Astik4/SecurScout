import argparse
import json
import sys
import os

# Add parent directory to sys.path to support direct execution (python SecurScout/main.py)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import threading
import uuid
from datetime import datetime, timezone
from typing import List
import webbrowser

from SecurScout.scan_engine.validator import validate_and_filter_targets
from SecurScout.scan_engine.nmap_wrapper import NmapWrapper
from SecurScout.scan_engine.xml_parser import parse_nmap_xml
from SecurScout.vuln_lookup.cve_mapper import CVEMapper
from SecurScout.scoring.risk_prioritization import RiskCalculator
from SecurScout.vuln_lookup.db_manager import DBManager
from SecurScout.reporter.generator import ReportGenerator
from SecurScout.web_ui.web_server import create_app

def load_dotenv():
    # Load environment variables from .env file if it exists
    paths = [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    ]
    for path in paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            key, val = line.split("=", 1)
                            val = val.strip().strip("'\"")
                            os.environ[key.strip()] = val
            except Exception:
                pass

load_dotenv()

LEGAL_NOTICE = """================================================================================
[LEGAL COMPLIANCE NOTICE]
SecurScout is intended only for authorized security testing on systems/assets
owned by you or where you have explicit, written authorization from the owner.
Unauthorized scanning can be considered malicious activity and may violate
local/national laws and terms of service.

By proceeding, you represent that you have obtained all necessary consents.
================================================================================\n"""

def main(argv: List[str] = None):
    try:
        _main_impl(argv)
    except KeyboardInterrupt:
        sys.stderr.write("\n\n[INFO] Scan aborted by user (Ctrl+C). Exiting cleanly...\n")
        sys.exit(130)

def _main_impl(argv: List[str] = None):
    # Print legal disclaimer to stderr so it does not pollute stdout redirected output
    sys.stderr.write(LEGAL_NOTICE)
    
    parser = argparse.ArgumentParser(
        description="SecurScout - Vulnerability Assessment & Reporting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Examples:
  Scan a single host and output JSON:
    python -m SecurScout 192.168.1.15
    
  Fast port scan and generate HTML report:
    python -m SecurScout 10.0.0.0/24 --fast --html report.html
    
  View past scan runs logged in database:
    python -m SecurScout --history
    
  Export a past scan report to HTML:
    python -m SecurScout --show-scan <uuid> --html report.html
        """
    )
    
    parser.add_argument(
        "targets",
        nargs="*",
        help="Space-separated list of targets (IPv4 addresses, CIDR ranges, or hostnames)."
    )
    parser.add_argument(
        "-e", "--exclude-file",
        help="Path to a file containing IP addresses/subnets to exclude from the scan."
    )
    parser.add_argument(
        "-f", "--fast",
        action="store_true",
        help="Perform a fast scan (scans top 100 ports instead of top 1000)."
    )
    parser.add_argument(
        "-O", "--detect-os",
        action="store_true",
        help="Attempt OS detection (requires administrative/root privileges)."
    )
    parser.add_argument(
        "-Pn", "--skip-discovery",
        action="store_true",
        help="Treat all hosts as online -- bypass host discovery (ping sweep)."
    )
    
    parser.add_argument(
        "--fallback-circl",
        action="store_true",
        help="Fallback or force query the CIRCL API instead of NVD."
    )
    parser.add_argument(
        "--cve-limit",
        type=int,
        default=5,
        help="Max number of CVEs to map per service (default: 5)."
    )
    parser.add_argument(
        "--scoring-config",
        help="Path to a JSON configuration file specifying custom asset criticalities or service weights."
    )
    parser.add_argument(
        "--db-path",
        default="vulnerability_scanner.db",
        help="Path to SQLite database to save cache and history (default: vulnerability_scanner.db)."
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="List all past scans saved in the local database and exit."
    )
    parser.add_argument(
        "--show-scan",
        help="UUID of a previous scan to retrieve and output as JSON."
    )
    parser.add_argument(
        "--html",
        help="Path to save the generated HTML report (e.g. report.html)."
    )
    parser.add_argument(
        "--web-scan",
        action="store_true",
        help="Perform an intensive vulnerability scan targeting web vulnerabilities (runs Nmap NSE vuln scripts)."
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Launch the local browser-based Security Audit Dashboard."
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host address to bind the web server to (default: 127.0.0.1)."
    )
    parser.add_argument(
        "-o", "--output",
        help="Path to save the JSON output. If not specified, results are printed to stdout."
    )

    args = parser.parse_args(argv)

    # Initialize Database Manager
    try:
        db_mgr = DBManager(db_path=args.db_path)
    except Exception as e:
        sys.stderr.write(f"\n[ERROR] Database initialization failed: {e}\n")
        sys.exit(1)

    # Handle Web UI Launcher
    if args.web:
        import socket
        
        # Helper to resolve local network IP
        def get_network_ip():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                return ip
            except Exception:
                return "127.0.0.1"

        net_ip = get_network_ip()
        
        if args.host == "0.0.0.0":
            sys.stderr.write(f"\n==========================================================\n")
            sys.stderr.write(f"[INFO] Starting local Web UI Server...\n")
            sys.stderr.write(f"[INFO] Local Access:   http://127.0.0.1:5000/\n")
            sys.stderr.write(f"[INFO] Network Access: http://{net_ip}:5000/ (Share this URL with other users!)\n")
            sys.stderr.write(f"==========================================================\n\n")
        else:
            sys.stderr.write(f"\n==========================================================\n")
            sys.stderr.write(f"[INFO] Starting local Web UI Server...\n")
            sys.stderr.write(f"[INFO] Local Access:   http://{args.host}:5000/\n")
            sys.stderr.write(f"==========================================================\n\n")
        
        app = create_app(db_path=args.db_path, nvd_key=os.environ.get("NVD_API_KEY"))
        
        def open_browser():
            import time
            time.sleep(1.5)
            sys.stderr.write("[INFO] Opening browser for local dashboard access...\n")
            webbrowser.open(f"http://{args.host if args.host != '0.0.0.0' else '127.0.0.1'}:5000/")
            
        t = threading.Thread(target=open_browser)
        t.daemon = True
        t.start()
        
        try:
            # Bind to configured host (default: 127.0.0.1 for local security)
            app.run(host=args.host, port=5000, debug=False)
        except KeyboardInterrupt:
            sys.stderr.write("\n[INFO] Web UI Server stopped.\n")
        sys.exit(0)

    # Handle History Query CLI Options
    if args.history:
        history = db_mgr.get_scan_history()
        if not history:
            print("No scan history found.")
        else:
            print(f"{'SCAN ID':<36} | {'START TIME':<26} | {'MAX RISK':<8} | {'TARGETS'}")
            print("-" * 110)
            for s in history:
                print(f"{s['scan_id']:<36} | {s['start_time'][:26]:<26} | {s['max_risk_score']:<8} | {s['targets']}")
        sys.exit(0)

    if args.show_scan:
        scan_details = db_mgr.get_scan_details(args.show_scan)
        if not scan_details:
            sys.stderr.write(f"\n[ERROR] Scan ID '{args.show_scan}' not found in database.\n")
            sys.exit(1)
            
        if args.html:
            try:
                generator = ReportGenerator()
                generator.render_report(scan_details, args.html)
                sys.stderr.write(f"\n[SUCCESS] Generated HTML report from past scan. Saved to {args.html}\n")
            except Exception as e:
                sys.stderr.write(f"\n[ERROR] Failed to generate HTML report: {e}\n")
                sys.exit(1)
        else:
            print(json.dumps(scan_details, indent=2))
        sys.exit(0)

    # Enforce targets requirements when not querying history
    if not args.targets:
        parser.print_usage()
        sys.stderr.write("\nerror: the following arguments are required: targets\n")
        sys.exit(2)

    # 1. Target Scoping & Exclusion Filtering
    try:
        filtered_targets = validate_and_filter_targets(args.targets, args.exclude_file)
    except Exception as e:
        sys.stderr.write(f"\n[ERROR] Input validation failed: {e}\n")
        sys.exit(1)

    if not filtered_targets:
        sys.stderr.write("\n[WARNING] No targets remaining to scan after filtering exclusion list.\n")
        sys.exit(0)

    sys.stderr.write(f"\n[INFO] Validated and scoped targets: {', '.join(filtered_targets)}\n")
    sys.stderr.write("[INFO] Launching scan (this may take a few moments)...\n")

    # Record scan start timestamp
    start_time_iso = datetime.now(timezone.utc).isoformat()

    # 2. Execute Scan
    wrapper = NmapWrapper()
    try:
        raw_xml = wrapper.run_scan(
            targets=filtered_targets,
            fast_mode=args.fast,
            detect_os=args.detect_os,
            exclude_file=args.exclude_file,
            web_scan=args.web_scan,
            skip_discovery=args.skip_discovery
        )
    except Exception as e:
        sys.stderr.write(f"\n[ERROR] Scan execution failed: {e}\n")
        sys.exit(1)

    # 3. Parse XML Output
    try:
        parsed_results = parse_nmap_xml(raw_xml)
    except Exception as e:
        sys.stderr.write(f"\n[ERROR] Parsing scan results failed: {e}\n")
        sys.exit(1)

    # Overwrite XML parsed start time with our precise high-res CLI start time
    parsed_results["scan_metadata"]["start_time"] = start_time_iso

    # 4. Map CVEs for each identified service
    nvd_key = os.environ.get("NVD_API_KEY")
    sys.stderr.write("\n[INFO] Initializing CVE Lookup & Vulnerability Mapping...\n")
    mapper = CVEMapper(api_key=nvd_key, force_circl=args.fallback_circl, db_manager=db_mgr)
    
    for host in parsed_results.get("hosts", []):
        for port in host.get("ports", []):
            service = port.get("service", {})
            vulns = []
            
            # 1. Map CVEs using CPE or keywords (NVD / CIRCL)
            if port.get("state") == "open" and (service.get("cpes") or service.get("product")):
                vulns = mapper.get_vulnerabilities(service)
                # Sort vulnerabilities by CVSS score descending (highest risk first)
                vulns = sorted(
                    vulns,
                    key=lambda x: x.get("cvss_score") if x.get("cvss_score") is not None else -1.0,
                    reverse=True
                )
                # Apply limits
                if args.cve_limit is not None and args.cve_limit >= 0:
                    vulns = vulns[:args.cve_limit]

            # 2. Extract Nmap NSE script findings as web vulnerabilities
            for script in port.get("scripts", []):
                script_id = script["id"]
                output = script["output"]
                
                # Determine default CVSS rating based on script family
                cvss = 5.0
                risk_t = "MEDIUM"
                
                script_lower = script_id.lower()
                if any(x in script_lower for x in ["sql-injection", "injection", "rce", "backdoor", "exploit", "shellshock"]):
                    cvss = 9.0
                    risk_t = "CRITICAL"
                elif any(x in script_lower for x in ["xss", "stored-xss", "csrf", "traversal", "unsafe"]):
                    cvss = 7.5
                    risk_t = "HIGH"
                elif "slowloris" in script_lower or "dos" in script_lower:
                    cvss = 6.0
                    risk_t = "MEDIUM"
                elif "ssl" in script_lower or "tls" in script_lower or "cipher" in script_lower:
                    cvss = 4.0
                    risk_t = "MEDIUM"
                
                # Search for a CVE number in the script output
                cve_match = re.search(r'CVE-\d{4}-\d{4,7}', output, re.IGNORECASE)
                vuln_id = cve_match.group(0).upper() if cve_match else script_id
                
                # Append script finding as a vulnerability
                vulns.append({
                    "id": vuln_id,
                    "description": f"Nmap NSE script '{script_id}' reported finding:\n{output.strip()}",
                    "cvss_score": cvss,
                    "cvss_vector": "N/A (Nmap NSE script detection)",
                    "adjusted_score": cvss,
                    "risk_tier": risk_t,
                    "source": f"Nmap Script ({script_id})"
                })
                
            port["vulnerabilities"] = vulns

    # 5. Perform Risk Scoring & Prioritization
    sys.stderr.write("\n[INFO] Running Risk Prioritization Scoring...\n")
    try:
        calculator = RiskCalculator(config_path=args.scoring_config)
    except Exception as e:
        sys.stderr.write(f"\n[ERROR] Failed to initialize risk calculator: {e}\n")
        sys.exit(1)

    scored_hosts = []
    max_risk_score = 0.0
    for host in parsed_results.get("hosts", []):
        ip = host.get("ip", "")
        hostnames = host.get("hostnames", [])
        ports = host.get("ports", [])
        
        # Calculate Host-level & Port-level risk scores
        scored_host = calculator.score_host(ip, hostnames, ports)
        scored_host["os"] = host.get("os", "Unknown")
        
        # Track overall maximum risk score across all hosts scanned
        if scored_host["host_risk_score"] > max_risk_score:
            max_risk_score = scored_host["host_risk_score"]
            
        scored_hosts.append(scored_host)
        
    parsed_results["hosts"] = scored_hosts

    # 6. Save Scan Results to SQLite history
    scan_id = str(uuid.uuid4())
    end_time_iso = datetime.now(timezone.utc).isoformat()
    
    parsed_results["scan_metadata"]["end_time"] = end_time_iso
    parsed_results["scan_metadata"]["scan_id"] = scan_id
    parsed_results["scan_metadata"]["targets"] = args.targets

    try:
        db_mgr.save_scan(
            scan_id=scan_id,
            start_time=start_time_iso,
            end_time=end_time_iso,
            targets=args.targets,
            max_risk_score=max_risk_score,
            results=parsed_results
        )
        sys.stderr.write(f"[INFO] Scan logged to database history (ID: {scan_id})\n")
    except Exception as e:
        sys.stderr.write(f"[WARNING] Failed to write scan to history: {e}\n")

    # 7. Generate and open HTML Report
    html_path = args.html if args.html else "securscout_report.html"
    sys.stderr.write(f"\n[INFO] Compiling HTML report...\n")
    try:
        generator = ReportGenerator()
        generator.render_report(parsed_results, html_path)
        sys.stderr.write(f"[SUCCESS] Report successfully generated and saved to: {os.path.abspath(html_path)}\n")
        
        # Open in default browser
        report_url = "file://" + os.path.abspath(html_path)
        sys.stderr.write(f"[INFO] Opening report in default web browser...\n")
        webbrowser.open(report_url)
    except Exception as e:
        sys.stderr.write(f"[ERROR] Failed to compile HTML report: {e}\n")

    # 8. Output JSON Results if requested
    json_output = json.dumps(parsed_results, indent=2)
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(json_output)
            sys.stderr.write(f"[SUCCESS] JSON results saved to {args.output}\n")
        except IOError as e:
            sys.stderr.write(f"[ERROR] Failed to write JSON output: {e}\n")
            sys.exit(1)
    else:
        sys.stderr.write("\n[SUCCESS] Scan execution complete.\n")

if __name__ == "__main__":
    main()
