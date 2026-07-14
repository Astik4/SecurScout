import os
import re
from typing import Dict, Any
from jinja2 import Environment, FileSystemLoader, select_autoescape

def generate_remediation_advisory(description: str, product: str) -> str:
    """
    Parses a vulnerability description to extract recommendations or fallback
    to generic security advisories for clients.
    """
    if not description:
        return f"Apply the latest vendor patches for {product or 'the running service'}."

    # Look for version patterns like "upgrade to 9.0.96" or "fixed in 1.2.3"
    pattern = re.compile(
        r'(?:upgrade to version|fixed in version|upgrade to|update to|fixed in|patched in)\s+([0-9a-zA-Z\.\-]+)',
        re.IGNORECASE
    )
    match = pattern.search(description)
    product_str = product if product else "the running service"
    
    if match:
        version = match.group(1).strip(".,;")
        return f"Upgrade **{product_str}** to version **{version}** or higher to patch this vulnerability. Review vendor advisories for specific update details."

    desc_lower = description.lower()
    if "denial of service" in desc_lower or "dos" in desc_lower:
        return f"Apply vendor security updates for **{product_str}**. In the interim, restrict access to authorized IP addresses and enable rate-limiting/DoS protections at the firewall."
    elif "remote code execution" in desc_lower or "rce" in desc_lower or "overflow" in desc_lower:
        return f"**CRITICAL PATCH REQUIRED.** Immediately apply vendor security patches for **{product_str}**. Disable or restrict access to the affected port from untrusted networks until patched."
    elif "directory traversal" in desc_lower or "local file inclusion" in desc_lower or "path traversal" in desc_lower:
        return f"Upgrade **{product_str}** and verify application path sanitization. Restrict write/read permissions on filesystem directories associated with the service."
        
    return f"Apply the latest security updates provided by the vendor for **{product_str}**. If patches are unavailable, restrict exposure of this service at the network perimeter."

class ReportGenerator:
    """Compiles and generates a professional HTML Vulnerability Assessment Report."""

    def __init__(self, template_dir: str = None):
        if not template_dir:
            # Default to the directory of this file
            template_dir = os.path.dirname(os.path.abspath(__file__))
        
        self.env = Environment(  # nosemgrep: direct-use-of-jinja2
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        self.template_name = "report_template.html"

    def calculate_stats(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculates host, port, and vulnerability counts to render in the summary tables."""
        total_hosts = len(results.get("hosts", []))
        total_ports = 0
        max_risk = 0.0
        
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        
        for host in results.get("hosts", []):
            host_score = host.get("host_risk_score", 0.0)
            if host_score > max_risk:
                max_risk = host_score
                
            for port in host.get("ports", []):
                if port.get("state") == "open":
                    total_ports += 1
                    
                for vuln in port.get("vulnerabilities", []):
                    tier = vuln.get("risk_tier", "LOW").upper()
                    if tier in severity_counts:
                        severity_counts[tier] += 1

        # Calculate heights/widths for SVG bar chart
        max_count = max(severity_counts.values()) if any(severity_counts.values()) else 1
        svg_widths = {
            k: int((v / max_count) * 100) for k, v in severity_counts.items()
        }

        # Humanized overall security status statement
        if max_risk >= 9.0:
            overall_status = "CRITICAL RISK"
            status_color = "#8c1d1d"
        elif max_risk >= 7.0:
            overall_status = "HIGH RISK"
            status_color = "#d97706"
        elif max_risk >= 4.0:
            overall_status = "MEDIUM RISK"
            status_color = "#ca8a04"
        elif max_risk >= 0.1:
            overall_status = "LOW RISK"
            status_color = "#2563eb"
        else:
            overall_status = "SECURE / NO VULNERABILITIES"
            status_color = "#16a34a"

        return {
            "total_hosts": total_hosts,
            "total_ports": total_ports,
            "max_risk": max_risk,
            "severity_counts": severity_counts,
            "svg_widths": svg_widths,
            "overall_status": overall_status,
            "status_color": status_color
        }

    def render_report(self, results: Dict[str, Any], output_path: str):
        """Renders the HTML report with enriched remediation actions and stats."""
        stats = self.calculate_stats(results)
        
        # Make a deep copy to avoid mutating the original input data
        results_copy = json.loads(json.dumps(results))
        
        # Inject remediation advisories into each vulnerability in the results copy
        for host in results_copy.get("hosts", []):
            for port in host.get("ports", []):
                product = port.get("service", {}).get("product", "")
                for vuln in port.get("vulnerabilities", []):
                    description = vuln.get("description", "")
                    vuln["remediation"] = generate_remediation_advisory(description, product)

        template = self.env.get_template(self.template_name)
        html_content = template.render(  # nosemgrep: direct-use-of-jinja2
            results=results_copy,
            stats=stats,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

# We import json and datetime inside methods to avoid top-level issues,
# but let's add them at module level for cleaner structure.
import json
from datetime import datetime
