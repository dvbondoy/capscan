import argparse
import json
from datetime import datetime
from pathlib import Path
import sys
import subprocess
import shlex

import nmap

# Ensure project root is on sys.path for direct script execution
PROJECT_ROOT = str(Path(__file__).resolve().parents[1])
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Reuse parsing and XML saving from the main Scanner implementation
from engine import Scanner


def build_aggressive_args(min_rate: int = 500, timing: str = "T2", dns: bool = False, use_vulscan: bool = True) -> str:
    """Construct aggressive nmap arguments string.

    Notes:
    - We keep -n (no DNS) by default to reduce variability; pass dns=True to resolve.
    - We embed -p- in the arguments (scan all ports).
    """
    dns_flag = "" if dns else "-n"
    scripts = [
        "vulners",
    ]
    if use_vulscan:
        scripts.append("vulscan")
    scripts.extend(["http-vuln-*", "ssl-*", "smb-vuln-*", "ssh-vuln-*"])

    args = (
        "-sV -sC -vv -Pn "
        f"--script {' ,'.join(scripts)} "
        "--script-args vulners.maxresults=10000,vulners.mincvss=0.0,vulscan.database=exploitdb "
        "--script-timeout=600s --max-retries 2 "
        f"--min-rate={min_rate} "
        f"-{timing} "
        f"{dns_flag} "
        "--version-intensity=9 --version-all -p-"
    ).strip()
    print(args)
    return args


def run_experimental_scan(target: str, aggressive_args: str, progress: bool = False, xml_output_path: str | None = None) -> dict:
    """Run an experimental scan and return a scan_results dict matching engine.Scanner.

    The structure mirrors Scanner.scan_host output so we can reuse save_as_xml.
    """
    nm = nmap.PortScanner()

    print(f"Running experimental nmap scan on {target}")
    print(f"Arguments: {aggressive_args}")
    if progress:
        if not xml_output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            xml_output_path = f"vuln_scan_{timestamp}.xml"
        cmd = f"nmap {shlex.quote(target)} {aggressive_args} -oX {shlex.quote(xml_output_path)} --stats-every 5s"
        print(f"Executing: {cmd}")
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            assert process.stderr is not None
            for line in process.stderr:
                line = line.rstrip()
                if not line:
                    continue
                print(line)
        finally:
            process.wait()
        if process.returncode != 0:
            return {
                'target': target,
                'scan_time': datetime.now().isoformat(),
                'scan_args': aggressive_args,
                'hosts': {},
                'vulnerabilities': [],
                'error': f"nmap exited with code {process.returncode}"
            }
        try:
            with open(xml_output_path, 'r', encoding='utf-8') as xf:
                xml_content = xf.read()
            nm.analyse_nmap_xml_scan(xml_content)
        except Exception as e:
            print(f"Failed to parse nmap XML: {e}")
            return {
                'target': target,
                'scan_time': datetime.now().isoformat(),
                'scan_args': aggressive_args,
                'hosts': {},
                'vulnerabilities': [],
                'error': f"XML parse error: {e}"
            }
    else:
        try:
            nm.scan(target, arguments=aggressive_args)
        except nmap.PortScannerError as e:
            print(f"nmap error: {e}")
            return {
                'target': target,
                'scan_time': datetime.now().isoformat(),
                'scan_args': aggressive_args,
                'hosts': {},
                'vulnerabilities': [],
                'error': str(e)
            }

    scanner = Scanner()  # Only to reuse parsing helpers and XML writer

    scan_data = {
        'target': target,
        'scan_time': datetime.now().isoformat(),
        'scan_args': aggressive_args,
        'hosts': {},
        'vulnerabilities': []
    }

    # Debug: show command line and scantats if available
    try:
        print(f"nmap command: {nm.command_line()}")
    except Exception:
        pass
    try:
        stats = nm.scanstats()
        print(f"scanstats: {stats}")
    except Exception:
        pass

    # Extract host information and vulnerabilities (mirror engine.Scanner logic)
    for host in nm.all_hosts():
        host_info = {
            'hostname': nm[host].hostname(),
            'state': nm[host].state(),
            'protocols': list(nm[host].all_protocols()),
            'ports': {},
            'vulnerabilities': []
        }

        for protocol in nm[host].all_protocols():
            ports = nm[host][protocol].keys()
            for port in ports:
                port_info = nm[host][protocol][port]
                host_info['ports'][f"{protocol}/{port}"] = {
                    'state': port_info.get('state', ''),
                    'name': port_info.get('name', ''),
                    'product': port_info.get('product', ''),
                    'version': port_info.get('version', ''),
                    'extrainfo': port_info.get('extrainfo', ''),
                    'script_results': port_info.get('script', {})
                }

                # Parse vulners output into normalized vulnerabilities list
                if 'script' in port_info:
                    for script_name, script_output in port_info['script'].items():
                        if 'vulners' in script_name.lower():
                            vulns = scanner._parse_vulners_output(script_output)
                            host_info['vulnerabilities'].extend(vulns)
                            scan_data['vulnerabilities'].extend(vulns)

        scan_data['hosts'][host] = host_info

    if not nm.all_hosts():
        print("No hosts reported by nmap. Consider adding -Pn or checking network reachability.")
    return scan_data


def save_outputs_like_main(scan_data: dict, vulnerabilities: list) -> None:
    """Persist XML and JSON outputs similarly to main.py CLI save behavior."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Use engine.Scanner to write XML from the constructed scan_data
    xml_scanner = Scanner()
    xml_scanner.scan_results = scan_data
    xml_scanner.vulnerabilities = vulnerabilities

    xml_file = xml_scanner.save_as_xml(f"scripts/vuln_scan_{timestamp}.xml")
    print(f"\n💾 Results saved to: {xml_file}")

    vuln_file = f"scripts/vulnerabilities_{timestamp}.json"
    with open(vuln_file, 'w') as f:
        json.dump(vulnerabilities, f, indent=2)
    print(f"💾 Vulnerabilities saved to: {vuln_file}")

    summary_file = f"scripts/summary_{timestamp}.json"
    with open(summary_file, 'w') as f:
        json.dump(xml_scanner.get_scan_summary(), f, indent=2)
    print(f"💾 Summary saved to: {summary_file}")


def main():
    parser = argparse.ArgumentParser(description="Run experimental aggressive nmap scan and save outputs like main.py")
    parser.add_argument("target", help="Target host or IP (or CIDR)")
    parser.add_argument("--min-rate", type=int, default=500, help="nmap --min-rate (default: 500)")
    parser.add_argument("--timing", default="T2", help="nmap timing template T0..T5 (default: T2)")
    parser.add_argument("--dns", action="store_true", help="Enable DNS resolution (omit -n)")
    parser.add_argument("--no-vulscan", action="store_true", help="Exclude vulscan NSE if not installed")
    parser.add_argument("--args", dest="extra_args", default=None,
                        help="Override aggressive args entirely (advanced)")
    parser.add_argument("--progress", action="store_true", help="Show live nmap progress and write -oX XML directly")

    args = parser.parse_args()

    if args.extra_args:
        aggressive_args = args.extra_args
    else:
        aggressive_args = build_aggressive_args(min_rate=args.min_rate, timing=args.timing, dns=args.dns, use_vulscan=not args.no_vulscan)

    preselected_xml = None
    if args.progress:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        preselected_xml = f"vuln_scan_{timestamp}.xml"
    scan_data = run_experimental_scan(args.target, aggressive_args, progress=args.progress, xml_output_path=preselected_xml)

    # Enhance scoring like engine does, so JSONs look similar
    scoring_scanner = Scanner()
    scoring_scanner.scan_results = scan_data
    scoring_scanner.vulnerabilities = scan_data.get('vulnerabilities', [])
    scoring_scanner.enhance_vulnerabilities_with_scores()

    save_outputs_like_main(scan_data, scoring_scanner.vulnerabilities)


if __name__ == "__main__":
    main()


