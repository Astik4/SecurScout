import xml.etree.ElementTree as ET
from typing import Dict, Any, List

def parse_nmap_xml(xml_content: str) -> Dict[str, Any]:
    """
    Parse Nmap XML output string into our unified JSON schema.
    
    Args:
        xml_content: The raw XML output string from Nmap.
        
    Returns:
        A dict matching the unified scan results schema.
    """
    if not xml_content.strip():
        raise ValueError("XML content is empty.")

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        raise ValueError(f"Failed to parse Nmap XML content: {e}") from e

    # Extract metadata
    scanner = root.get("scanner", "nmap")
    args = root.get("args", "")
    start_time = root.get("startstr", "")
    
    # Try to find end time in runstats
    end_time = ""
    finished_el = root.find(".//runstats/finished")
    if finished_el is not None:
        end_time = finished_el.get("timestr", "")

    scan_metadata = {
        "scanner": scanner,
        "args": args,
        "start_time": start_time,
        "end_time": end_time
    }

    hosts_list: List[Dict[str, Any]] = []

    # Iterate over hosts
    for host_el in root.findall("host"):
        # IP address extraction
        ip = "unknown"
        # Nmap usually lists IPv4, then IPv6 or MAC. We check for ipv4 first, then ipv6
        address_el = host_el.find("./address[@addrtype='ipv4']")
        if address_el is None:
            address_el = host_el.find("./address[@addrtype='ipv6']")
        if address_el is None:
            address_el = host_el.find("./address")
            
        if address_el is not None:
            ip = address_el.get("addr", "unknown")

        # Status
        status = "unknown"
        status_el = host_el.find("status")
        if status_el is not None:
            status = status_el.get("state", "unknown")

        # Hostnames
        hostnames: List[str] = []
        hostname_els = host_el.findall(".//hostnames/hostname")
        for h_el in hostname_els:
            name = h_el.get("name")
            if name:
                hostnames.append(name)
        # Deduplicate hostnames preserving order
        hostnames = list(dict.fromkeys(hostnames))

        # OS detection parsing
        os_name = "Unknown"
        osmatch_el = host_el.find(".//os/osmatch")
        if osmatch_el is not None:
            os_name = osmatch_el.get("name", "Unknown")
        else:
            # Fallback to osclass if osmatch is not present
            osclass_el = host_el.find(".//os/osclass")
            if osclass_el is not None:
                os_vendor = osclass_el.get("vendor", "")
                os_family = osclass_el.get("osfamily", "")
                os_gen = osclass_el.get("osgen", "")
                parts = [p for p in [os_vendor, os_family, os_gen] if p]
                if parts:
                    os_name = " ".join(parts)

        # Port scanning results
        ports: List[Dict[str, Any]] = []
        port_els = host_el.findall(".//ports/port")
        for port_el in port_els:
            port_id_str = port_el.get("portid")
            if not port_id_str:
                continue
            
            try:
                port_id = int(port_id_str)
            except ValueError:
                continue

            protocol = port_el.get("protocol", "tcp")
            
            # State
            state = "unknown"
            state_el = port_el.find("state")
            if state_el is not None:
                state = state_el.get("state", "unknown")

            # Service info
            service_el = port_el.find("service")
            if service_el is not None:
                cpes = []
                for cpe_el in service_el.findall("cpe"):
                    if cpe_el.text:
                        cpes.append(cpe_el.text.strip())
                service_info = {
                    "name": service_el.get("name", "unknown"),
                    "product": service_el.get("product", ""),
                    "version": service_el.get("version", ""),
                    "extrainfo": service_el.get("extrainfo", ""),
                    "cpes": cpes
                }
            else:
                service_info = {
                    "name": "unknown",
                    "product": "",
                    "version": "",
                    "extrainfo": "",
                    "cpes": []
                }

            # Script results (NSE scripts like http-sql-injection, http-xssed, vuln etc.)
            scripts = []
            script_els = port_el.findall("script")
            for s_el in script_els:
                s_id = s_el.get("id")
                s_output = s_el.get("output")
                if not s_output and s_el.text:
                    s_output = s_el.text.strip()
                if s_id and s_output:
                    scripts.append({
                        "id": s_id,
                        "output": s_output
                    })

            ports.append({
                "port": port_id,
                "protocol": protocol,
                "state": state,
                "service": service_info,
                "scripts": scripts
            })

        hosts_list.append({
            "ip": ip,
            "status": status,
            "hostnames": hostnames,
            "os": os_name,
            "ports": ports
        })

    return {
        "scan_metadata": scan_metadata,
        "hosts": hosts_list
    }
