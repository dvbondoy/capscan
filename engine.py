import nmap
import xml.etree.ElementTree as ET
from datetime import datetime
import os
import json
from typing import Dict, List, Optional, Tuple


class Scanner:
    """
    A vulnerability scanner class that uses nmap with vulners NSE script
    to scan hosts for vulnerabilities and save results as XML.
    """
    
    def __init__(self):
        """Initialize the vulnerability scanner."""
        self.nm = nmap.PortScanner()
        self.vulnerabilities = []
        self.scan_results = {}
        self.xml_output_path = None
        
    def scan_host(self, target: str, ports: str = "1-65535", 
                  vulners_args: str = "--script-args vulners.maxreports=10") -> Dict:
        """
        Scan a host for vulnerabilities using nmap with vulners NSE script.
        
        Args:
            target (str): Target host or IP address to scan
            ports (str): Port range to scan (default: 1-65535)
            vulners_args (str): Additional arguments for vulners script
            
        Returns:
            Dict: Scan results containing vulnerabilities and port information
        """
        try:
            print(f"Starting vulnerability scan for target: {target}")
            
            # Perform nmap scan with vulners NSE script
            scan_args = f"-sV -sC --script vulners {vulners_args} -p {ports}"

            # scan_args = f"-sV -sC -vv -Pn --script vulners, vulscan,http-vuln-*, ssl-*, smb-vuln-*, ssh-vuln-*, {vulners_args} -p {ports}"

            # Experimental arguments:
            # Arguments: -sV -sC -vv -Pn --script vulners ,vulscan ,http-vuln-* ,ssl-* ,smb-vuln-* ,ssh-vuln-* --script-args vulners.maxresults=10000,vulners.mincvss=0.0,vulscan.database=exploitdb --script-timeout=600s --max-retries 2 --min-rate=500 -T2 -n --version-intensity=9 --version-all -p-

            print(f"Running nmap with arguments: {scan_args}")
            self.nm.scan(target, arguments=scan_args)
            
            # Process scan results
            scan_data = {
                'target': target,
                'scan_time': datetime.now().isoformat(),
                'scan_args': scan_args,
                'hosts': {},
                'vulnerabilities': []
            }
            
            # Extract host information and vulnerabilities
            for host in self.nm.all_hosts():
                host_info = {
                    'hostname': self.nm[host].hostname(),
                    'state': self.nm[host].state(),
                    'protocols': list(self.nm[host].all_protocols()),
                    'ports': {},
                    'vulnerabilities': []
                }
                
                # Extract port information
                for protocol in self.nm[host].all_protocols():
                    ports = self.nm[host][protocol].keys()
                    for port in ports:
                        port_info = self.nm[host][protocol][port]
                        host_info['ports'][f"{protocol}/{port}"] = {
                            'state': port_info['state'],
                            'name': port_info.get('name', ''),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', ''),
                            'script_results': port_info.get('script', {})
                        }
                        
                        # Extract vulnerabilities from script results
                        if 'script' in port_info:
                            for script_name, script_output in port_info['script'].items():
                                if 'vulners' in script_name.lower():
                                    vulns = self._parse_vulners_output(script_output)
                                    host_info['vulnerabilities'].extend(vulns)
                                    scan_data['vulnerabilities'].extend(vulns)
                
                scan_data['hosts'][host] = host_info
            
            # Store results
            self.scan_results = scan_data
            self.vulnerabilities = scan_data['vulnerabilities']
            
            print(f"Scan completed. Found {len(self.vulnerabilities)} vulnerabilities.")
            return scan_data
            
        except Exception as e:
            print(f"Error during scan: {str(e)}")
            return {'error': str(e)}
    
    def _parse_vulners_output(self, script_output: str) -> List[Dict]:
        """
        Parse vulners script output to extract vulnerability information.
        
        Args:
            script_output (str): Raw output from vulners script
            
        Returns:
            List[Dict]: Parsed vulnerability information
        """
        vulnerabilities = []
        lines = script_output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or 'CVE-' not in line:
                continue
                
            try:
                # Parse vulnerability line (format may vary)
                parts = line.split()
                if len(parts) >= 3:
                    vuln = {
                        'cve_id': parts[0] if parts[0].startswith('CVE-') else None,
                        'score': self._extract_score(line),
                        'description': ' '.join(parts[1:]) if len(parts) > 1 else line,
                        'raw_output': line
                    }
                    vulnerabilities.append(vuln)
            except Exception as e:
                print(f"Error parsing vulnerability line: {line} - {str(e)}")
                continue
                
        return vulnerabilities
    
    def _extract_score(self, line: str) -> Optional[float]:
        """Extract CVSS score from vulnerability line."""
        import re
        # Look for CVSS score patterns
        score_patterns = [
            r'CVSS:3\.0/AV:[NAL]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HL]/I:[HL]/A:[HL]\s+(\d+\.\d+)',
            r'Score:\s*(\d+\.\d+)',
            r'(\d+\.\d+)\s*CVSS'
        ]
        
        for pattern in score_patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    return float(match.group(1))
                except ValueError:
                    continue
        return None
    
    def _score_by_keywords(self, description: str) -> float:
        """Score vulnerability based on keywords in description."""
        if not description:
            return 1.0
        
        high_severity_keywords = [
            'remote code execution', 'rce', 'arbitrary code execution',
            'buffer overflow', 'sql injection', 'cross-site scripting',
            'privilege escalation', 'authentication bypass', 'command injection',
            'code execution', 'arbitrary file', 'path traversal', 'directory traversal',
            'memory corruption', 'heap overflow', 'stack overflow', 'format string',
            'integer overflow', 'use after free', 'double free', 'null pointer',
            'deserialization', 'unserialize', 'pickle', 'yaml', 'xml external entity',
            'xxe', 'server-side request forgery', 'ssrf', 'no-sql injection',
            'ldap injection', 'xpath injection', 'template injection',
            'server-side template injection', 'ssti', 'log4j', 'log4shell',
            'spring4shell', 'zeroday', 'zero-day', '0-day'
        ]
        
        medium_severity_keywords = [
            'denial of service', 'dos', 'information disclosure',
            'cross-site request forgery', 'csrf', 'open redirect',
            'session fixation', 'session hijacking', 'clickjacking',
            'cors', 'cross-origin resource sharing', 'http parameter pollution',
            'http response splitting', 'cache poisoning', 'dns rebinding',
            'time-of-check time-of-use', 'toctou', 'race condition',
            'timing attack', 'side-channel', 'brute force', 'dictionary attack',
            'password cracking', 'credential stuffing', 'account enumeration',
            'username enumeration', 'email enumeration', 'user enumeration'
        ]
        
        low_severity_keywords = [
            'information leak', 'disclosure', 'enumeration', 'fingerprinting',
            'version disclosure', 'banner disclosure', 'error message',
            'debug information', 'stack trace', 'path disclosure',
            'directory listing', 'file disclosure', 'source code disclosure',
            'configuration disclosure', 'internal ip disclosure',
            'port scanning', 'service enumeration', 'banner grabbing'
        ]
        
        desc_lower = description.lower()
        
        # Check for high severity keywords
        for keyword in high_severity_keywords:
            if keyword in desc_lower:
                return 8.5  # High severity
        
        # Check for medium severity keywords
        for keyword in medium_severity_keywords:
            if keyword in desc_lower:
                return 5.5  # Medium severity
        
        # Check for low severity keywords
        for keyword in low_severity_keywords:
            if keyword in desc_lower:
                return 3.0  # Low severity
        
        # Additional scoring based on CVE year
        if 'cve-2024' in desc_lower or 'cve-2023' in desc_lower:
            return 6.0  # Recent vulnerabilities get higher score
        elif 'cve-2022' in desc_lower or 'cve-2021' in desc_lower:
            return 4.0  # Recent but not latest
        elif 'cve-' in desc_lower:
            return 2.0  # Older CVE references
        
        return 1.0  # Default low score for unknown vulnerabilities
    
    def _score_by_cve_year(self, cve_id: str) -> float:
        """Score based on CVE year (newer = potentially more relevant)."""
        if not cve_id or not cve_id.startswith('CVE-'):
            return 1.0
        
        try:
            year = int(cve_id.split('-')[1])
            current_year = datetime.now().year
            
            if year >= current_year - 1:  # Last 2 years
                return 7.0
            elif year >= current_year - 3:  # Last 3-4 years
                return 5.0
            elif year >= current_year - 5:  # Last 5-6 years
                return 3.0
            else:
                return 1.5  # Older vulnerabilities
        except (ValueError, IndexError):
            return 1.0
    
    def enhance_vulnerabilities_with_scores(self):
        """Enhance vulnerabilities with scores using keyword analysis and CVE year."""
        enhanced_count = 0
        
        for vuln in self.vulnerabilities:
            if vuln.get('score') is None:
                # Try keyword-based scoring first
                description = vuln.get('description', '')
                keyword_score = self._score_by_keywords(description)
                
                # Try CVE year-based scoring
                cve_id = vuln.get('cve_id', '')
                year_score = self._score_by_cve_year(cve_id)
                
                # Use the higher score
                final_score = max(keyword_score, year_score)
                
                vuln['score'] = final_score
                vuln['score_source'] = 'keyword_analysis'
                vuln['keyword_score'] = keyword_score
                vuln['year_score'] = year_score
                
                enhanced_count += 1
            
            # Always set severity based on score
            vuln['severity'] = self._score_to_severity(vuln.get('score', 0))
        
        print(f"Enhanced {enhanced_count} vulnerabilities with keyword-based scoring")
        return enhanced_count
    
    def _score_to_severity(self, score: float) -> str:
        """Convert numeric score to severity level."""
        if score is None or score == 0:
            return 'unknown'
        elif score >= 7.0:
            return 'critical'
        elif score >= 4.0:
            return 'high'
        elif score >= 2.0:
            return 'medium'
        else:
            return 'low'
    
    def get_scoring_statistics(self) -> Dict:
        """Get statistics about the scoring system."""
        if not self.vulnerabilities:
            return {}
        
        total_vulns = len(self.vulnerabilities)
        scored_vulns = len([v for v in self.vulnerabilities if v.get('score') is not None])
        
        # Count by score ranges
        high_count = len([v for v in self.vulnerabilities if v.get('score', 0) >= 7.0])
        medium_count = len([v for v in self.vulnerabilities if 4.0 <= v.get('score', 0) < 7.0])
        low_count = len([v for v in self.vulnerabilities if 1.0 <= v.get('score', 0) < 4.0])
        
        # Count by source
        keyword_scored = len([v for v in self.vulnerabilities if v.get('score_source') == 'keyword_analysis'])
        
        return {
            'total_vulnerabilities': total_vulns,
            'scored_vulnerabilities': scored_vulns,
            'unscored_vulnerabilities': total_vulns - scored_vulns,
            'high_severity': high_count,
            'medium_severity': medium_count,
            'low_severity': low_count,
            'keyword_scored': keyword_scored,
            'scoring_coverage': (scored_vulns / total_vulns * 100) if total_vulns > 0 else 0
        }
    
    def save_as_xml(self, output_path: str = None) -> str:
        """
        Save scan results as XML file.
        
        Args:
            output_path (str): Path to save XML file. If None, auto-generates filename.
            
        Returns:
            str: Path to saved XML file
        """
        if not self.scan_results:
            raise ValueError("No scan results to save. Run scan_host() first.")
        
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"vuln_scan_{timestamp}.xml"
        
        # Create XML structure
        root = ET.Element("vulnerability_scan")
        root.set("timestamp", self.scan_results.get('scan_time', ''))
        root.set("target", self.scan_results.get('target', ''))
        root.set("scan_args", self.scan_results.get('scan_args', ''))
        
        # Add hosts
        hosts_elem = ET.SubElement(root, "hosts")
        for host_ip, host_info in self.scan_results.get('hosts', {}).items():
            host_elem = ET.SubElement(hosts_elem, "host")
            host_elem.set("ip", host_ip)
            host_elem.set("hostname", host_info.get('hostname', ''))
            host_elem.set("state", host_info.get('state', ''))
            
            # Add ports
            ports_elem = ET.SubElement(host_elem, "ports")
            for port, port_info in host_info.get('ports', {}).items():
                port_elem = ET.SubElement(ports_elem, "port")
                port_elem.set("id", port)
                port_elem.set("state", port_info.get('state', ''))
                port_elem.set("name", port_info.get('name', ''))
                port_elem.set("product", port_info.get('product', ''))
                port_elem.set("version", port_info.get('version', ''))
                port_elem.set("extrainfo", port_info.get('extrainfo', ''))
                
                # Add script results
                if port_info.get('script_results'):
                    scripts_elem = ET.SubElement(port_elem, "scripts")
                    for script_name, script_output in port_info['script_results'].items():
                        script_elem = ET.SubElement(scripts_elem, "script")
                        script_elem.set("name", script_name)
                        script_elem.text = script_output
            
            # Add vulnerabilities for this host
            if host_info.get('vulnerabilities'):
                vulns_elem = ET.SubElement(host_elem, "vulnerabilities")
                for vuln in host_info['vulnerabilities']:
                    vuln_elem = ET.SubElement(vulns_elem, "vulnerability")
                    vuln_elem.set("cve_id", vuln.get('cve_id') or '')
                    vuln_elem.set("score", str(vuln.get('score') or ''))
                    vuln_elem.text = vuln.get('description') or ''
        
        # Add summary vulnerabilities
        summary_vulns = ET.SubElement(root, "summary_vulnerabilities")
        for vuln in self.scan_results.get('vulnerabilities', []):
            vuln_elem = ET.SubElement(summary_vulns, "vulnerability")
            vuln_elem.set("cve_id", vuln.get('cve_id') or '')
            vuln_elem.set("score", str(vuln.get('score') or ''))
            vuln_elem.text = vuln.get('description') or ''
        
        # Write XML to file
        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ", level=0)  # Pretty print
        tree.write(output_path, encoding='utf-8', xml_declaration=True)
        
        self.xml_output_path = output_path
        print(f"Scan results saved to: {output_path}")
        return output_path
    
    def get_vulnerabilities(self) -> List[Dict]:
        """Get all discovered vulnerabilities."""
        return self.vulnerabilities
    
    def get_scan_summary(self) -> Dict:
        """Get a summary of the scan results."""
        if not self.scan_results:
            return {}
        
        total_vulns = len(self.vulnerabilities)
        hosts_scanned = len(self.scan_results.get('hosts', {}))
        
        # Count vulnerabilities by severity
        severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}
        for vuln in self.vulnerabilities:
            score = vuln.get('score')
            if score is None:
                severity_counts['unknown'] += 1
            elif score >= 7.0:
                severity_counts['high'] += 1
            elif score >= 4.0:
                severity_counts['medium'] += 1
            else:
                severity_counts['low'] += 1
        
        return {
            'target': self.scan_results.get('target', ''),
            'scan_time': self.scan_results.get('scan_time', ''),
            'hosts_scanned': hosts_scanned,
            'total_vulnerabilities': total_vulns,
            'severity_breakdown': severity_counts,
            'xml_output_path': self.xml_output_path
        }
    
    def print_summary(self):
        """Print a formatted summary of scan results."""
        summary = self.get_scan_summary()
        if not summary:
            print("No scan results available.")
            return
        
        print("\n" + "="*50)
        print("VULNERABILITY SCAN SUMMARY")
        print("="*50)
        print(f"Target: {summary['target']}")
        print(f"Scan Time: {summary['scan_time']}")
        print(f"Hosts Scanned: {summary['hosts_scanned']}")
        print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        print("\nSeverity Breakdown:")
        for severity, count in summary['severity_breakdown'].items():
            print(f"  {severity.capitalize()}: {count}")
        
        if summary['xml_output_path']:
            print(f"\nResults saved to: {summary['xml_output_path']}")
        print("="*50)


# Example usage
# if __name__ == "__main__":
    # Create scanner instance
    # scanner = Scanner()
    
    # Example scan (uncomment to test)
    # results = scanner.scan_host("127.0.0.1", ports="22,80,443")
    # scanner.save_as_xml()
    # scanner.print_summary()
