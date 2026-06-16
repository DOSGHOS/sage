#!/usr/bin/env python3
"""
Non-IP IoT Vulnerability Scanner
Multi-protocol security analysis tool for Zigbee, BLE, and other non-IP IoT protocols
Author: yahya al hayajneh
Version: 1.0
"""
import argparse
import json
import importlib
import pathlib
import sys
import time
from typing import List, Dict, Any
from datetime import datetime

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Registry of plugin classes (imported lazily)
PLUGIN_PATHS = [
    "plugins.zigbee_plugin:ZigbeePlugin",
    "plugins.ble_plugin:BLEPlugin","plugins.zwave_plugin:ZWavePlugin",
]

class Finding(dict):
    """Vulnerability finding data structure"""
    pass

class BasePlugin:
    """Base class for protocol plugins"""
    name = "base"
    
    def supports(self, pcap_path: str) -> bool:
        """Check if plugin supports this file"""
        return True
    
    def scan(self, pcap_path: str) -> Dict[str, Any]:
        """Scan pcap file for vulnerabilities"""
        raise NotImplementedError

def print_banner():
    """Print scanner banner"""
    banner = f"""
{Colors.CYAN}{'='*70}
{Colors.BOLD}    Non-IP IoT Vulnerability Scanner v1.0
{Colors.END}{Colors.CYAN}                ----SAGE-----
{'='*70}{Colors.END}
"""
    print(banner)

def load_plugins() -> List[BasePlugin]:
    """Load all available plugins"""
    loaded = []
    print(f"{Colors.BLUE}[*] Loading plugins...{Colors.END}")
    
    for entry in PLUGIN_PATHS:
        try:
            mod_path, cls_name = entry.split(":")
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            plugin = cls()
            loaded.append(plugin)
            print(f"  {Colors.GREEN}✓{Colors.END} Loaded: {plugin.name}")
        except Exception as e:
            print(f"  {Colors.RED}✗{Colors.END} Failed to load {entry}: {e}")
    
    print(f"{Colors.GREEN}[✓] {len(loaded)} plugins loaded{Colors.END}\n")
    return loaded

def format_severity(severity: str) -> str:
    """Format severity with color"""
    colors = {
        "CRITICAL": Colors.RED + Colors.BOLD,
        "HIGH": Colors.RED,
        "MEDIUM": Colors.YELLOW,
        "LOW": Colors.CYAN
    }
    color = colors.get(severity, "")
    return f"{color}{severity}{Colors.END}"

def print_vulnerability(vuln: Dict, index: int):
    """Pretty print a vulnerability"""
    severity = format_severity(vuln.get('severity', 'UNKNOWN'))
    vuln_id = vuln.get('id', 'UNKNOWN')
    title = vuln.get('title', 'No title')
    
    print(f"\n  {Colors.BOLD}[{index}] {severity} - {vuln_id}{Colors.END}")
    print(f"      {Colors.BOLD}Title:{Colors.END} {title}")
    
    if vuln.get('description'):
        print(f"      {Colors.BOLD}Description:{Colors.END} {vuln['description']}")
    
    if vuln.get('cve'):
        cves = vuln['cve'] if isinstance(vuln['cve'], list) else [vuln['cve']]
        print(f"      {Colors.BOLD}CVE:{Colors.END} {', '.join(cves)}")
    
    if vuln.get('evidence'):
        print(f"      {Colors.BOLD}Evidence:{Colors.END} {vuln['evidence']}")
    
    if vuln.get('attack_vector'):
        print(f"      {Colors.BOLD}Attack Vector:{Colors.END} {vuln['attack_vector']}")
    
    if vuln.get('remediation'):
        print(f"      {Colors.BOLD}Remediation:{Colors.END} {vuln['remediation']}")

def print_statistics(stats: Dict):
    """Print scan statistics"""
    if not stats:
        return
    
    print(f"\n  {Colors.BOLD}Statistics:{Colors.END}")
    for key, value in stats.items():
        print(f"    • {key}: {value}")

def get_risk_level(score: int) -> str:
    """Get risk level from score"""
    if score >= 86:
        return f"{Colors.RED}{Colors.BOLD}CRITICAL{Colors.END}"
    elif score >= 61:
        return f"{Colors.RED}HIGH{Colors.END}"
    elif score >= 31:
        return f"{Colors.YELLOW}MEDIUM{Colors.END}"
    else:
        return f"{Colors.GREEN}LOW{Colors.END}"

def print_summary(all_reports: List[Dict]):
    """Print scan summary"""
    print(f"\n{Colors.CYAN}{'='*70}")
    print(f"{Colors.BOLD}Scan Summary{Colors.END}")
    print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")
    
    total_files = len(all_reports)
    total_vulns = 0
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    for file_report in all_reports:
        for report in file_report.get('reports', []):
            vulns = report.get('vulns', [])
            total_vulns += len(vulns)
            
            for vuln in vulns:
                severity = vuln.get('severity', 'UNKNOWN')
                if severity in severity_count:
                    severity_count[severity] += 1
    
    print(f"  Files Scanned: {Colors.BOLD}{total_files}{Colors.END}")
    print(f"  Total Vulnerabilities: {Colors.BOLD}{total_vulns}{Colors.END}")
    print(f"\n  Severity Breakdown:")
    print(f"    {format_severity('CRITICAL')}: {severity_count['CRITICAL']}")
    print(f"    {format_severity('HIGH')}: {severity_count['HIGH']}")
    print(f"    {format_severity('MEDIUM')}: {severity_count['MEDIUM']}")
    print(f"    {format_severity('LOW')}: {severity_count['LOW']}")

def main():
    """Main scanner function"""
    print_banner()
    
    # Parse arguments
    ap = argparse.ArgumentParser(
        description="Multi-protocol non-IP IoT vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s sample.pcap                    # Scan single file
  %(prog)s *.pcap                         # Scan multiple files
  %(prog)s sample.pcap --json             # Output JSON report
  %(prog)s sample.pcap --output report    # Save reports to files
        """
    )
    ap.add_argument("pcaps", nargs="+", help="Paths to .pcap/.pcapng files")
    ap.add_argument("--json", action="store_true", help="Print full JSON reports")
    ap.add_argument("--output", "-o", help="Save reports to file (without extension)")
    ap.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    ap.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = ap.parse_args()
    
    # Disable colors if requested
    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith('_'):
                setattr(Colors, attr, '')
    
    # Load plugins
    plugins = load_plugins()
    
    if not plugins:
        print(f"{Colors.RED}[!] No plugins loaded. Exiting.{Colors.END}")
        return 1
    
    # Scan files
    all_reports = []
    start_time = time.time()
    
    for pcap_path in args.pcaps:
        pcap_path = str(pathlib.Path(pcap_path))
        
        # Check file exists
        if not pathlib.Path(pcap_path).exists():
            print(f"{Colors.RED}[!] File not found: {pcap_path}{Colors.END}")
            continue
        
        print(f"{Colors.BLUE}[*] Scanning: {pcap_path}{Colors.END}")
        
        file_reports = []
        for plugin in plugins:
            if plugin.supports(pcap_path):
                try:
                    if args.verbose:
                        print(f"  {Colors.CYAN}→{Colors.END} Running {plugin.name} plugin...")
                    
                    rep = plugin.scan(pcap_path)
                    
                    if rep and rep.get("vulns"):
                        file_reports.append(rep)
                    else:
                        file_reports.append(rep or {
                            "protocol": plugin.name,
                            "pcap": pcap_path,
                            "vulns": []
                        })
                        
                except Exception as e:
                    print(f"  {Colors.RED}✗{Colors.END} {plugin.name} error: {e}")
                    if args.verbose:
                        import traceback
                        traceback.print_exc()
                    
                    file_reports.append({
                        "protocol": plugin.name,
                        "pcap": pcap_path,
                        "error": str(e),
                        "vulns": []
                    })
        
        all_reports.append({
            "pcap": pcap_path,
            "timestamp": datetime.now().isoformat(),
            "reports": file_reports
        })
    
    elapsed_time = time.time() - start_time
    
    # Pretty print results
    print(f"\n{Colors.CYAN}{'='*70}")
    print(f"{Colors.BOLD}Scan Results{Colors.END}")
    print(f"{Colors.CYAN}{'='*70}{Colors.END}")
    
    for file_report in all_reports:
        pcap_file = file_report['pcap']
        print(f"\n{Colors.BOLD}{Colors.UNDERLINE}File: {pcap_file}{Colors.END}")
        
        for report in file_report['reports']:
            protocol = report.get("protocol", "?")
            
            # Print error if any
            if report.get("error"):
                print(f"\n  {Colors.RED}[{protocol}] Error: {report['error']}{Colors.END}")
                continue
            
            # Print statistics
            if report.get("statistics"):
                print_statistics(report["statistics"])
            
            # Print vulnerabilities
            vulns = report.get("vulns", [])
            print(f"\n  {Colors.BOLD}[{protocol}] Vulnerabilities Found: {len(vulns)}{Colors.END}")

            if not vulns:
                print(f"  {Colors.GREEN}✓ No vulnerabilities detected{Colors.END}")
            else:
                for idx, vuln in enumerate(vulns, 1):
                    print_vulnerability(vuln, idx)

            # Print risk score
            if report.get("risk_score") is not None:
                risk_score = report["risk_score"]
                risk_level = get_risk_level(risk_score)
                print(f"\n  {Colors.BOLD}Risk Score:{Colors.END} {risk_score}/100 ({risk_level})")
    
    # Print summary
    print_summary(all_reports)
    
    # Print scan time
    print(f"\n{Colors.CYAN}Scan completed in {elapsed_time:.2f} seconds{Colors.END}\n")
    
    # Save JSON report if requested
    if args.json or args.output:
        if args.json:
            print(json.dumps(all_reports, indent=2))
        
        if args.output:
            # Save text report
            text_file = f"{args.output}.txt"
            with open(text_file, 'w') as f:
                # Redirect print to file (simplified)
                f.write(f"IoT Vulnerability Scanner Report\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write(f"{'='*70}\n\n")
                
                for file_report in all_reports:
                    f.write(f"File: {file_report['pcap']}\n")
                    f.write(f"{'='*70}\n")
                    
                    for report in file_report['reports']:
                        protocol = report.get("protocol", "?")
                        f.write(f"\n[{protocol}]\n")
                        
                        if report.get("error"):
                            f.write(f"Error: {report['error']}\n")
                            continue
                        
                        if report.get("risk_score") is not None:
                            f.write(f"Risk Score: {report['risk_score']}/100\n")
                        
                        vulns = report.get("vulns", [])
                        f.write(f"Vulnerabilities: {len(vulns)}\n\n")
                        
                        for idx, vuln in enumerate(vulns, 1):
                            f.write(f"  [{idx}] {vuln.get('severity')} - {vuln.get('id')}\n")
                            f.write(f"      {vuln.get('title')}\n")
                            if vuln.get('cve'):
                                cves = vuln['cve'] if isinstance(vuln['cve'], list) else [vuln['cve']]
                                f.write(f"      CVE: {', '.join(cves)}\n")
                            if vuln.get('evidence'):
                                f.write(f"      Evidence: {vuln['evidence']}\n")
                            f.write("\n")
                    
                    f.write("\n")
            
            print(f"{Colors.GREEN}[✓] Text report saved to: {text_file}{Colors.END}")
            
            # Save JSON report
            json_file = f"{args.output}.json"
            with open(json_file, 'w') as f:
                json.dump(all_reports, f, indent=2)
            
            print(f"{Colors.GREEN}[✓] JSON report saved to: {json_file}{Colors.END}")
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Fatal error: {e}{Colors.END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
