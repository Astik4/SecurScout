import json
import fnmatch
import ipaddress
import sys
from typing import List, Dict, Any, Optional

CRITICALITY_MULTIPLIERS = {
    "CRITICAL": 1.5,
    "HIGH": 1.25,
    "MEDIUM": 1.0,
    "LOW": 0.75
}

DEFAULT_CVSS_MAP = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 2.0,
    "NONE": 0.0
}

HIGH_EXPOSURE_PORTS = {21, 22, 23, 445, 1433, 3306, 3389, 5432}
HIGH_EXPOSURE_SERVICES = {"ssh", "telnet", "ftp", "microsoft-ds", "ms-sql-s", "mysql", "postgresql", "ms-wbt-server", "rdp"}

STANDARD_EXPOSURE_PORTS = {80, 443, 8080}
STANDARD_EXPOSURE_SERVICES = {"http", "https", "http-alt"}

class RiskCalculator:
    """Calculates risk prioritization scores for vulnerabilities and scanned hosts."""

    def __init__(self, config_path: Optional[str] = None):
        self.asset_rules: List[Dict[str, Any]] = []
        self.service_rules: Dict[str, float] = {}
        
        if config_path:
            self._load_config(config_path)

    def _load_config(self, config_path: str):
        """Loads customized scoring rules from a JSON configuration file."""
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)
                
            self.asset_rules = data.get("asset_criticality", [])
            self.service_rules = data.get("service_exposure", {})
            sys.stderr.write(f"[INFO] Loaded scoring configuration from {config_path}\n")
        except FileNotFoundError:
            raise FileNotFoundError(f"Scoring config file not found: {config_path}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in scoring config: {e}")

    def get_asset_criticality(self, ip: str, hostnames: List[str]) -> str:
        """
        Determines the criticality tier (CRITICAL, HIGH, MEDIUM, LOW) of a host.
        Evaluates rules in the order defined in the config.
        """
        for rule in self.asset_rules:
            pattern = rule.get("pattern", "")
            criticality = rule.get("criticality", "").upper()
            
            if criticality not in CRITICALITY_MULTIPLIERS:
                continue

            # 1. Match CIDR / IP Network
            if "/" in pattern or self._is_single_ip(pattern):
                try:
                    net = ipaddress.IPv4Network(pattern, strict=False)
                    ip_addr = ipaddress.IPv4Address(ip)
                    if ip_addr in net:
                        return criticality
                except ValueError:
                    pass
            
            # 2. Match hostnames using wildcards (fnmatch)
            for hostname in hostnames:
                if fnmatch.fnmatch(hostname.lower(), pattern.lower()):
                    return criticality

        return "MEDIUM"  # Default fallback

    def _is_single_ip(self, pattern: str) -> bool:
        try:
            ipaddress.IPv4Address(pattern)
            return True
        except ValueError:
            return False

    def get_service_exposure(self, port: int, service_name: str) -> float:
        """Determines the exposure multiplier based on port or service name."""
        # 1. Check custom user configuration rules first
        port_str = str(port)
        if port_str in self.service_rules:
            return float(self.service_rules[port_str])
        
        if service_name in self.service_rules:
            return float(self.service_rules[service_name])

        # 2. Apply default heuristics
        if port in HIGH_EXPOSURE_PORTS or service_name in HIGH_EXPOSURE_SERVICES:
            return 1.2
        elif port in STANDARD_EXPOSURE_PORTS or service_name in STANDARD_EXPOSURE_SERVICES:
            return 1.0
        
        return 0.8  # Lower exposure for internal / custom ports

    def get_risk_tier(self, score: float) -> str:
        """Converts a numerical risk score back to a risk tier."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 0.1:
            return "LOW"
        return "NONE"

    def score_vulnerability(
        self,
        cve_info: Dict[str, Any],
        asset_criticality: str,
        service_exposure: float
    ) -> Dict[str, Any]:
        """
        Calculates the risk score for a single vulnerability.
        """
        # Resolve CVSS Base Score
        cvss = cve_info.get("cvss_score")
        if cvss is None:
            # Fallback to estimation based on severity string
            severity = cve_info.get("cvss_severity", "MEDIUM").upper()
            cvss = DEFAULT_CVSS_MAP.get(severity, 5.5)

        asset_mult = CRITICALITY_MULTIPLIERS.get(asset_criticality, 1.0)
        
        # Calculate raw and capped risk score
        adjusted_score = cvss * asset_mult * service_exposure
        final_score = round(min(10.0, adjusted_score), 1)
        
        # Determine risk tier
        risk_tier = self.get_risk_tier(final_score)

        return {
            "id": cve_info.get("id", "Unknown"),
            "description": cve_info.get("description", ""),
            "cvss_score": cvss,
            "cvss_vector": cve_info.get("cvss_vector", ""),
            "adjusted_score": final_score,
            "risk_tier": risk_tier,
            "source": cve_info.get("source", "Unknown")
        }

    def score_host(self, ip: str, hostnames: List[str], ports_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculates host-level risk scoring and aggregates vulnerability metrics.
        """
        asset_crit = self.get_asset_criticality(ip, hostnames)
        
        # Score all vulnerabilities found on this host
        all_vuln_scores: List[float] = []
        enriched_ports: List[Dict[str, Any]] = []

        for port_item in ports_data:
            port = port_item.get("port", 0)
            service = port_item.get("service", {})
            service_name = service.get("name", "")
            exposure = self.get_service_exposure(port, service_name)
            
            vulns = port_item.get("vulnerabilities", [])
            enriched_vulns = []
            
            for v in vulns:
                scored_v = self.score_vulnerability(v, asset_crit, exposure)
                enriched_vulns.append(scored_v)
                all_vuln_scores.append(scored_v["adjusted_score"])

            # Sort port vulnerabilities descending by adjusted score
            enriched_vulns = sorted(enriched_vulns, key=lambda x: x["adjusted_score"], reverse=True)
            
            port_copy = port_item.copy()
            port_copy["vulnerabilities"] = enriched_vulns
            enriched_ports.append(port_copy)

        # Host-level density scoring math
        # Host Score = max(vulns) + 0.1 * sum(remaining)
        host_score = 0.0
        if all_vuln_scores:
            sorted_scores = sorted(all_vuln_scores, reverse=True)
            max_score = sorted_scores[0]
            remaining_sum = sum(sorted_scores[1:])
            host_score = round(min(10.0, max_score + (0.1 * remaining_sum)), 1)

        host_risk_tier = self.get_risk_tier(host_score)

        return {
            "ip": ip,
            "status": "up",
            "hostnames": hostnames,
            "os": "Unknown",  # Placeholder updated in parsing layer
            "asset_criticality": asset_crit,
            "host_risk_score": host_score,
            "host_risk_tier": host_risk_tier,
            "ports": enriched_ports
        }
