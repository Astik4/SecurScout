import ipaddress
import re
import socket
from typing import List, Set

# Standard hostname regex (RFC 1123)
HOSTNAME_REGEX = re.compile(
    r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])'
    r'(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]))*$'
)

def is_valid_ipv4(ip_str: str) -> bool:
    """Check if the string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ValueError:
        return False

def is_valid_cidr(cidr_str: str) -> bool:
    """Check if the string is a valid IPv4 CIDR range."""
    try:
        ipaddress.IPv4Network(cidr_str, strict=False)
        return True
    except ValueError:
        return False

def is_valid_hostname(host_str: str) -> bool:
    """Check if the string is a valid hostname/domain name."""
    if not host_str or len(host_str) > 253:
        return False
    # Strip trailing dot if present (fully qualified domain name)
    if host_str.endswith('.'):
        host_str = host_str[:-1]
        
    # If the string contains only digits and dots, it must be a valid IPv4 address
    if all(char.isdigit() or char == '.' for char in host_str):
        return is_valid_ipv4(host_str)
        
    labels = host_str.split('.')
    return all(
        len(label) >= 1 and len(label) <= 63 and HOSTNAME_REGEX.match(label)
        for label in labels
    )

def validate_target(target: str) -> str:
    """
    Validate if target is a valid IPv4, CIDR, or hostname.
    Returns the target type: 'ip', 'cidr', or 'hostname'.
    Raises ValueError if invalid.
    """
    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty.")
    
    if is_valid_ipv4(target):
        return 'ip'
    elif is_valid_cidr(target) and '/' in target:
        return 'cidr'
    elif is_valid_hostname(target):
        return 'hostname'
    else:
        raise ValueError(f"Invalid target format: '{target}'. Must be a valid IPv4 address, CIDR subnet, or hostname.")

def load_exclude_networks(exclude_file_path: str) -> List[ipaddress.IPv4Network]:
    """
    Load exclude IPs and subnets from a file.
    Supports comments starting with '#' and ignores empty lines.
    """
    exclude_networks = []
    try:
        with open(exclude_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # If it's a single IP, represent it as a /32 network
                try:
                    net = ipaddress.IPv4Network(line, strict=False)
                    exclude_networks.append(net)
                except ValueError as e:
                    # Let's log or raise a clear error message
                    raise ValueError(f"Invalid entry in exclude file: '{line}'. Details: {e}")
    except FileNotFoundError:
        raise FileNotFoundError(f"Exclude file not found: {exclude_file_path}")
    return exclude_networks

def is_ip_excluded(ip: ipaddress.IPv4Address, exclude_networks: List[ipaddress.IPv4Network]) -> bool:
    """Check if a given IP is contained within any of the excluded networks."""
    for net in exclude_networks:
        if ip in net:
            return True
    return False

def validate_and_filter_targets(targets: List[str], exclude_file: str = None) -> List[str]:
    """
    Validates a list of target strings.
    If exclude_file is provided, filters out targets that are completely excluded.
    For hostnames, resolves to IP and excludes if the IP is excluded.
    Raises ValueError if any target has an invalid format.
    """
    if not targets:
        return []

    # First, validate all targets to raise errors for any malformed input
    validated_targets = []
    for target in targets:
        target_clean = target.strip()
        validate_target(target_clean)
        validated_targets.append(target_clean)

    if not exclude_file:
        return validated_targets

    exclude_nets = load_exclude_networks(exclude_file)
    if not exclude_nets:
        return validated_targets

    filtered_targets = []
    for target in validated_targets:
        target_type = validate_target(target)

        if target_type == 'ip':
            ip_obj = ipaddress.IPv4Address(target)
            if is_ip_excluded(ip_obj, exclude_nets):
                # Target is excluded, skip it
                continue
            filtered_targets.append(target)

        elif target_type == 'cidr':
            net_obj = ipaddress.IPv4Network(target, strict=False)
            # Check if the entire CIDR range is excluded
            # (i.e. is subnet of or equals any excluded network)
            entirely_excluded = False
            for ex_net in exclude_nets:
                # If target network is a subnetwork of or matches the excluded network
                if net_obj.subnet_of(ex_net):
                    entirely_excluded = True
                    break
            if entirely_excluded:
                continue
            filtered_targets.append(target)

        elif target_type == 'hostname':
            try:
                # Resolve hostname to check its IP
                resolved_ip_str = socket.gethostbyname(target)
                ip_obj = ipaddress.IPv4Address(resolved_ip_str)
                if is_ip_excluded(ip_obj, exclude_nets):
                    continue
            except (socket.gaierror, ValueError):
                # If hostname cannot be resolved, we'll keep it in targets so Nmap can try
                # to resolve it or fail during scan execution.
                pass
            filtered_targets.append(target)

    return filtered_targets
