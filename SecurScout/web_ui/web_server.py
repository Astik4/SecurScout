import os
import sys
import uuid
import threading
import tempfile
import re
from datetime import datetime, timezone
from typing import List, Dict, Any

from flask import Flask, request, jsonify, render_template, send_file

def load_dotenv():
    # Load environment variables from .env file if it exists
    paths = [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env")
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

from SecurScout.scan_engine.validator import validate_and_filter_targets
from SecurScout.scan_engine.nmap_wrapper import NmapWrapper
from SecurScout.scan_engine.xml_parser import parse_nmap_xml
from SecurScout.vuln_lookup.cve_mapper import CVEMapper
from SecurScout.scoring.risk_prioritization import RiskCalculator
from SecurScout.vuln_lookup.db_manager import DBManager
from SecurScout.reporter.generator import ReportGenerator

# Global scan status state
scan_status: Dict[str, Any] = {
    "is_running": False,
    "current_scan_id": None,
    "last_error": None,
    "targets": None
}

def execute_background_scan(
    scan_id: str,
    targets: List[str],
    fast_mode: bool,
    detect_os: bool,
    exclude_file: str,
    web_scan: bool,
    db_path: str,
    nvd_key: str = None,
    skip_discovery: bool = False
):
    """Orchestrates scanner engine pipeline inside a separate thread."""
    global scan_status
    scan_status["is_running"] = True
    scan_status["current_scan_id"] = scan_id
    scan_status["last_error"] = None
    scan_status["targets"] = targets
    
    try:
        db_mgr = DBManager(db_path=db_path)
        
        # 1. Target Scoping
        filtered_targets = validate_and_filter_targets(targets, exclude_file)
        if not filtered_targets:
            raise ValueError("No targets remaining to scan after exclude list filtering.")
            
        start_time_iso = datetime.now(timezone.utc).isoformat()
        
        # 2. Port Scanning
        wrapper = NmapWrapper()
        raw_xml = wrapper.run_scan(
            targets=filtered_targets,
            fast_mode=fast_mode,
            detect_os=detect_os,
            exclude_file=exclude_file,
            web_scan=web_scan,
            skip_discovery=skip_discovery
        )
        
        # 3. XML Parsing
        parsed_results = parse_nmap_xml(raw_xml)
        parsed_results["scan_metadata"]["start_time"] = start_time_iso
        
        # 4. CVE Mapping & Web NSE Script findings
        mapper = CVEMapper(api_key=nvd_key, db_manager=db_mgr)
        for host in parsed_results.get("hosts", []):
            for port in host.get("ports", []):
                service = port.get("service", {})
                vulns = []
                
                # Fetch CVEs from NVD/CIRCL
                if port.get("state") == "open" and (service.get("cpes") or service.get("product")):
                    vulns = mapper.get_vulnerabilities(service)
                    vulns = sorted(
                        vulns,
                        key=lambda x: x.get("cvss_score") if x.get("cvss_score") is not None else -1.0,
                        reverse=True
                    )
                    vulns = vulns[:5] # Limit NVD queries per port
                
                # Translate Nmap scripts findings to vulnerabilities
                for script in port.get("scripts", []):
                    script_id = script["id"]
                    output = script["output"]
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
                        
                    cve_match = re.search(r'CVE-\d{4}-\d{4,7}', output, re.IGNORECASE)
                    vuln_id = cve_match.group(0).upper() if cve_match else script_id
                    
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
                
        # 5. Risk Prioritization Scoring
        calculator = RiskCalculator()
        scored_hosts = []
        max_risk_score = 0.0
        for host in parsed_results.get("hosts", []):
            ip = host.get("ip", "")
            hostnames = host.get("hostnames", [])
            ports = host.get("ports", [])
            
            scored_host = calculator.score_host(ip, hostnames, ports)
            scored_host["os"] = host.get("os", "Unknown")
            if scored_host["host_risk_score"] > max_risk_score:
                max_risk_score = scored_host["host_risk_score"]
                
            scored_hosts.append(scored_host)
            
        parsed_results["hosts"] = scored_hosts
        
        # 6. Save Scan to database
        end_time_iso = datetime.now(timezone.utc).isoformat()
        parsed_results["scan_metadata"]["end_time"] = end_time_iso
        parsed_results["scan_metadata"]["scan_id"] = scan_id
        parsed_results["scan_metadata"]["targets"] = targets
        
        db_mgr.save_scan(
            scan_id=scan_id,
            start_time=start_time_iso,
            end_time=end_time_iso,
            targets=targets,
            max_risk_score=max_risk_score,
            results=parsed_results
        )
        
    except Exception as e:
        scan_status["last_error"] = str(e)
        sys.stderr.write(f"[ERROR] Web scan execution failed: {e}\n")
    finally:
        scan_status["is_running"] = False

def create_app(db_path: str = "vulnerability_scanner.db", template_folder: str = None, nvd_key: str = None) -> Flask:
    """Configures and returns the web server Flask app instance."""
    if not template_folder:
        template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
        
    app = Flask(__name__, template_folder=template_folder)
    db_mgr = DBManager(db_path=db_path)
    
    # Fallback to environment variable if not explicitly passed
    resolved_nvd_key = nvd_key or os.environ.get("NVD_API_KEY")

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/api/scans", methods=["GET"])
    def get_scans():
        try:
            scans = db_mgr.get_scan_history()
            return jsonify(scans)
        except Exception as e:
            return jsonify({"error": f"Failed to retrieve history: {e}"}), 500

    @app.route("/api/scans/<scan_id>", methods=["GET"])
    def get_scan_details(scan_id):
        try:
            details = db_mgr.get_scan_details(scan_id)
            if not details:
                return jsonify({"error": f"Scan ID '{scan_id}' not found"}), 404
            return jsonify(details)
        except Exception as e:
            return jsonify({"error": f"Failed to retrieve details: {e}"}), 500

    @app.route("/api/scans/<scan_id>/report", methods=["GET"])
    def download_report(scan_id):
        try:
            details = db_mgr.get_scan_details(scan_id)
            if not details:
                return jsonify({"error": f"Scan ID '{scan_id}' not found"}), 404
                
            generator = ReportGenerator()
            # Compile to a temporary file
            fd, temp_path = tempfile.mkstemp(suffix=".html")
            os.close(fd)
            try:
                generator.render_report(details, temp_path)
                return send_file(
                    temp_path,
                    as_attachment=True,
                    download_name=f"vulnerability_report_{scan_id}.html",
                    mimetype="text/html"
                )
            except Exception as render_err:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                raise render_err
        except Exception as e:
            return jsonify({"error": f"Report rendering failed: {e}"}), 500

    @app.route("/api/scan/status", methods=["GET"])
    def get_scan_status():
        global scan_status
        response_status = scan_status.copy()
        # Reset the error key once it has been retrieved to avoid infinite loops on page reloads
        if scan_status["last_error"] is not None:
            scan_status["last_error"] = None
        return jsonify(response_status)

    @app.route("/api/scan", methods=["POST"])
    def start_scan():
        global scan_status
        if scan_status["is_running"]:
            return jsonify({"error": "A scan run is already active in the background"}), 400
            
        data = request.json or {}
        targets_input = data.get("targets", "")
        
        # Parse targets string
        if isinstance(targets_input, str):
            targets = [t.strip() for t in targets_input.split(",") if t.strip()]
        elif isinstance(targets_input, list):
            targets = [str(t).strip() for t in targets_input if str(t).strip()]
        else:
            targets = []
            
        if not targets:
            return jsonify({"error": "No valid targets provided"}), 400
            
        fast_mode = data.get("fast_mode", True)
        detect_os = data.get("detect_os", False)
        web_scan = data.get("web_scan", False)
        exclude_file = data.get("exclude_file", None)
        
        scan_id = str(uuid.uuid4())
        skip_discovery = data.get("skip_discovery", False)
        
        # Execute active scan on background daemon thread
        thread = threading.Thread(
            target=execute_background_scan,
            args=(scan_id, targets, fast_mode, detect_os, exclude_file, web_scan, db_path, resolved_nvd_key, skip_discovery)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            "message": "Scan execution launched successfully",
            "scan_id": scan_id
        }), 202

    return app
