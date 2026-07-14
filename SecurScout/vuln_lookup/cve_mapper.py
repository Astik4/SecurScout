import requests
import time
import sys
from typing import List, Dict, Any, Optional

def cpe_22_to_23(cpe_22: str) -> str:
    """
    Convert a CPE v2.2 string (e.g. cpe:/a:apache:http_server:2.4.41)
    to a CPE v2.3 string (e.g. cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*).
    """
    if not cpe_22.startswith("cpe:"):
        return cpe_22
    if cpe_22.startswith("cpe:2.3:"):
        return cpe_22

    cpe_clean = cpe_22
    if cpe_clean.startswith("cpe:/"):
        cpe_clean = cpe_clean[5:]
    elif cpe_clean.startswith("cpe:"):
        cpe_clean = cpe_clean[4:]

    parts = cpe_clean.split(":")
    if not parts:
        return cpe_22

    # Clean the part indicator (e.g., 'a', 'o', 'h')
    part = parts[0].strip('/')

    cpe_23_parts = ["cpe", "2.3", part]
    cpe_23_parts.extend(parts[1:])

    # Pad with wildcards up to 13 fields (CPE 2.3 standard fields)
    while len(cpe_23_parts) < 13:
        cpe_23_parts.append("*")

    return ":".join(cpe_23_parts)

def get_severity_from_score(score: float) -> str:
    """Helper to convert CVSS base score to standard severity tier."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score >= 0.1:
        return "LOW"
    return "NONE"

class CVEMapper:
    """Queries vulnerability databases to map services to CVEs."""

    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CIRCL_BASE_URL = "https://cve.circl.lu/api/search"

    def __init__(
        self,
        api_key: Optional[str] = None,
        force_circl: bool = False,
        db_manager: Optional[Any] = None
    ):
        self.api_key = api_key
        self.force_circl = force_circl
        self.db_manager = db_manager
        self.cache: Dict[str, List[Dict[str, Any]]] = {}

    def get_vulnerabilities(self, service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities for a service by CPE or product name/version.
        Uses in-memory cache and SQLite cache to optimize queries.
        """
        cpes = service_info.get("cpes", [])
        product = service_info.get("product", "")
        version = service_info.get("version", "")

        # Try to resolve by CPEs first
        if cpes:
            for cpe in cpes:
                # 1. Check in-memory session cache
                if cpe in self.cache:
                    sys.stderr.write(f"[DEBUG] Memory cache hit for CPE: {cpe}\n")
                    return self.cache[cpe]

                # 2. Check persistent SQLite cache
                if self.db_manager:
                    cached_results = self.db_manager.get_cached_cve(cpe)
                    if cached_results is not None:
                        sys.stderr.write(f"[DEBUG] Database cache hit for CPE: {cpe}\n")
                        self.cache[cpe] = cached_results
                        return cached_results

                # 3. Query external API
                results = self._lookup_cpe(cpe)
                if results:
                    self.cache[cpe] = results
                    if self.db_manager:
                        self.db_manager.save_cve_to_cache(cpe, results)
                    return results

        # Fallback to keyword search if no CPE matched or CPEs were empty
        keyword = f"{product} {version}".strip()
        if keyword and len(keyword) > 2:  # Avoid matching generic terms
            # 1. Check in-memory session cache
            if keyword in self.cache:
                sys.stderr.write(f"[DEBUG] Memory cache hit for keyword: {keyword}\n")
                return self.cache[keyword]

            # 2. Check persistent SQLite cache
            if self.db_manager:
                cached_results = self.db_manager.get_cached_cve(keyword)
                if cached_results is not None:
                    sys.stderr.write(f"[DEBUG] Database cache hit for keyword: {keyword}\n")
                    self.cache[keyword] = cached_results
                    return cached_results

            # 3. Query external API
            results = self._lookup_keyword(product, version)
            self.cache[keyword] = results
            if self.db_manager:
                self.db_manager.save_cve_to_cache(keyword, results)
            return results

        return []

    def _lookup_cpe(self, cpe: str) -> List[Dict[str, Any]]:
        """Query external APIs using a CPE string."""
        if self.force_circl:
            return self._query_circl_cpe(cpe)

        try:
            return self._query_nvd_cpe(cpe)
        except Exception as e:
            sys.stderr.write(f"[WARNING] NVD CPE lookup failed ({e}). Falling back to CIRCL.\n")
            return self._query_circl_cpe(cpe)

    def _lookup_keyword(self, product: str, version: str) -> List[Dict[str, Any]]:
        """Query external APIs using a keyword search (fallback)."""
        keyword = f"{product} {version}"
        if self.force_circl:
            return self._query_circl_keyword(product, version)

        try:
            return self._query_nvd_keyword(keyword)
        except Exception as e:
            sys.stderr.write(f"[WARNING] NVD keyword lookup failed ({e}). Falling back to CIRCL.\n")
            return self._query_circl_keyword(product, version)

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "User-Agent": "VulnerabilityAssessmentTool/1.0 (Python; Requests)"
        }
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _query_nvd_cpe(self, cpe: str) -> List[Dict[str, Any]]:
        """Query the official NVD API 2.0 using CPE 2.3 format."""
        cpe_23 = cpe_22_to_23(cpe)
        params = {"cpeName": cpe_23}
        
        sys.stderr.write(f"[INFO] Querying NVD API for CPE: {cpe_23}\n")
        
        # Retry logic for NVD rate-limiting
        for attempt in range(2):
            response = requests.get(
                self.NVD_BASE_URL,
                params=params,
                headers=self._get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                return self._parse_nvd_response(response.json())
            elif response.status_code in (403, 429) and attempt == 0:
                # Throttled, sleep briefly and retry
                sys.stderr.write("[WARNING] NVD API rate-limit hit. Retrying in 2 seconds...\n")
                time.sleep(2)
            else:
                response.raise_for_status()
                
        return []

    def _query_nvd_keyword(self, keyword: str) -> List[Dict[str, Any]]:
        """Query NVD API using a text keyword."""
        params = {
            "keywordSearch": keyword,
            "keywordExactMatch": ""
        }
        
        sys.stderr.write(f"[INFO] Querying NVD API for keyword: '{keyword}'\n")
        
        for attempt in range(2):
            response = requests.get(
                self.NVD_BASE_URL,
                params=params,
                headers=self._get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                return self._parse_nvd_response(response.json())
            elif response.status_code in (403, 429) and attempt == 0:
                sys.stderr.write("[WARNING] NVD API rate-limit hit. Retrying in 2 seconds...\n")
                time.sleep(2)
            else:
                response.raise_for_status()
                
        return []

    def _parse_nvd_response(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse NVD API v2.0 JSON response into our internal vulnerability format."""
        results = []
        vulns = data.get("vulnerabilities", [])
        
        for item in vulns:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "Unknown")
            
            # Extract English description
            desc_text = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    desc_text = desc.get("value", "")
                    break
            
            # CVSS details
            cvss_score = None
            cvss_severity = "UNKNOWN"
            cvss_vector = ""
            
            metrics = cve_data.get("metrics", {})
            cvss_metrics = None
            
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_metrics = metrics["cvssMetricV31"][0]
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                cvss_metrics = metrics["cvssMetricV30"][0]
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_metrics = metrics["cvssMetricV2"][0]
                
            if cvss_metrics:
                cvss_data = cvss_metrics.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString", "")
                cvss_severity = cvss_data.get("baseSeverity", "").upper()
                
                # Fallback severity categorization
                if not cvss_severity and cvss_score is not None:
                    cvss_severity = get_severity_from_score(cvss_score)
            
            results.append({
                "id": cve_id,
                "description": desc_text,
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity or "UNKNOWN",
                "cvss_vector": cvss_vector,
                "source": "NVD"
            })
            
        return results

    def _query_circl_cpe(self, cpe: str) -> List[Dict[str, Any]]:
        """Query the CIRCL API using vendor and product extracted from CPE."""
        # CPE format: cpe:/a:vendor:product:version
        cpe_clean = cpe
        if cpe_clean.startswith("cpe:/"):
            cpe_clean = cpe_clean[5:]
        elif cpe_clean.startswith("cpe:"):
            cpe_clean = cpe_clean[4:]
            
        parts = cpe_clean.split(":")
        if len(parts) < 3:
            return []
            
        vendor = parts[1]
        product = parts[2]
        
        sys.stderr.write(f"[INFO] Querying CIRCL API for vendor/product: {vendor}/{product}\n")
        
        url = f"{self.CIRCL_BASE_URL}/{vendor}/{product}"
        response = requests.get(url, headers=self._get_headers(), timeout=10)
        
        if response.status_code != 200:
            return []
            
        circl_vulns = response.json()
        if not isinstance(circl_vulns, list):
            return []
            
        # Filter findings in Python by matching the specific CPE
        # CIRCL results contain a 'vulnerable_configuration' array listing CPEs
        cpe_23 = cpe_22_to_23(cpe)
        matching_results = []
        
        for item in circl_vulns:
            configs = item.get("vulnerable_configuration", [])
            is_vulnerable = False
            for conf in configs:
                # Check for CPE alignment (simple substring containment or prefix check)
                if cpe in conf or cpe_23 in conf or conf in cpe or conf in cpe_23:
                    is_vulnerable = True
                    break
            
            if is_vulnerable:
                matching_results.append(self._parse_circl_cve(item))
                
        return matching_results

    def _query_circl_keyword(self, product: str, version: str) -> List[Dict[str, Any]]:
        """Query the CIRCL API as a fallback when no CPE is present."""
        if not product:
            return []
            
        sys.stderr.write(f"[INFO] Querying CIRCL API (keyword search) for: {product}\n")
        
        # CIRCL does not have a general text search endpoint like NVD,
        # but we can query by product under vendor if product has a standard structure.
        # Let's guess the vendor name equals the product name as a fallback.
        url = f"{self.CIRCL_BASE_URL}/{product}/{product}"
        try:
            response = requests.get(url, headers=self._get_headers(), timeout=10)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    # Filter items whose summary mentions our version
                    results = []
                    for item in data:
                        summary = item.get("summary", "")
                        if version in summary:
                            results.append(self._parse_circl_cve(item))
                    return results
        except Exception:
            pass
        return []

    def _parse_circl_cve(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Convert CIRCL JSON structure to internal schema."""
        cve_id = item.get("id", "Unknown")
        desc = item.get("summary", "")
        
        cvss_score = item.get("cvss")
        if cvss_score is not None:
            try:
                cvss_score = float(cvss_score)
            except ValueError:
                cvss_score = None
                
        cvss_severity = "UNKNOWN"
        if cvss_score is not None:
            cvss_severity = get_severity_from_score(cvss_score)
            
        return {
            "id": cve_id,
            "description": desc,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "cvss_vector": "",  # CIRCL API does not supply formatted vector strings cleanly
            "source": "CIRCL"
        }
