import subprocess
import shutil
from typing import List, Optional

class NmapWrapper:
    """Handles subprocess execution of Nmap scanner."""
    
    def __init__(self, nmap_path: str = "nmap"):
        self.nmap_path = nmap_path

    def is_nmap_available(self) -> bool:
        """Check if the nmap executable is available in the system path."""
        if shutil.which(self.nmap_path):
            return True
        try:
            # Fallback: try calling version command directly
            subprocess.run(
                [self.nmap_path, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            return True
        except (FileNotFoundError, OSError):
            return False

    def run_scan(
        self,
        targets: List[str],
        fast_mode: bool = True,
        detect_os: bool = False,
        exclude_file: Optional[str] = None,
        web_scan: bool = False,
        skip_discovery: bool = False
    ) -> str:
        """
        Execute Nmap scan via subprocess and return the XML output string.
        
        Args:
            targets: List of validated target IPs/subnets/hostnames.
            fast_mode: Scan top 100 ports instead of top 1000.
            detect_os: Attempt OS detection (requires administrative privileges).
            exclude_file: Path to an exclude file containing subnets/IPs to exclude.
            web_scan: Run Nmap vulnerability and http-vuln NSE scripts.
            
        Returns:
            Raw XML string returned by Nmap.
        """
        if not self.is_nmap_available():
            raise RuntimeError(
                "Nmap is not installed or not found in the system PATH.\n"
                "Please install Nmap to use this tool:\n"
                "  - Windows: Download and run the installer from https://nmap.org/download.html and ensure it is in system PATH.\n"
                "  - Linux: Run 'sudo apt install nmap' or 'sudo yum install nmap'.\n"
                "  - macOS: Run 'brew install nmap'."
            )

        if not targets:
            raise ValueError("No targets provided for the scan.")

        # Build command list
        cmd = [self.nmap_path]
        
        # Add scan parameters
        cmd.append("-sT")  # TCP Connect scan (no Administrator privileges required)
        cmd.append("-sV")  # Service version detection
        
        if fast_mode:
            cmd.append("-F")  # Fast port scan (top 100)
            
        if detect_os:
            cmd.append("-O")  # OS detection (requires root/admin)
            
        if exclude_file:
            cmd.extend(["--excludefile", exclude_file])
            
        if web_scan:
            cmd.append("--script=vuln,http-vuln-*")
            
        cmd.append("-Pn")  # Always assume host is online (bypasses ping sweep blocks)
            
        cmd.extend(["-oX", "-"])  # Output XML directly to stdout
        
        # Add targets
        cmd.extend(targets)

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
            
            if result.returncode != 0:
                stderr_lower = result.stderr.lower()
                # Detect permission/privilege errors
                if any(x in stderr_lower for x in ["requires root", "privilege", "permission", "dnet: failed"]):
                    raise RuntimeError(
                        "Nmap requires Administrator/root privileges for OS detection (-O).\n"
                        "Please run this tool as Administrator/root, or disable OS detection (remove --detect-os)."
                    )
                raise RuntimeError(f"Nmap execution failed (exit code {result.returncode}): {result.stderr}")
            
            return result.stdout
            
        except Exception as e:
            if not isinstance(e, (RuntimeError, ValueError)):
                raise RuntimeError(f"An unexpected error occurred while executing Nmap: {e}") from e
            raise
