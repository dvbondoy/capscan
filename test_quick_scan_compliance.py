#!/usr/bin/env python3
"""
Test compliance by quick scanning 192.168.88.250
This script performs a quick vulnerability scan and runs compliance analysis.
"""

import json
import sys
from datetime import datetime
from engine import Scanner
from compliance.analyzers import ComplianceAnalyzer
from compliance.frameworks import ComplianceStandard


def test_quick_scan_compliance():
    """Test compliance analysis with a quick scan of 192.168.88.250."""
    print("🚀 CapScan - Quick Scan Compliance Test")
    print("=" * 60)
    print(f"Target: 192.168.88.250")
    print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Initialize scanner
    scanner = Scanner()
    
    # Perform quick scan (common ports)
    print("\n🔍 Starting quick vulnerability scan...")
    print("Scanning common ports: 22,80,443,8080,8443,3389,5900,21,23,25,53,110,143,993,995")
    
    try:
        # Quick scan with common ports
        scan_results = scanner.scan_host(
            target="192.168.88.250",
            ports="22,80,443,8080,8443,3389,5900,21,23,25,53,110,143,993,995",
            vulners_args="--script-args vulners.maxreports=5"
        )
        
        print(f"✅ Scan completed successfully!")
        print(f"📊 Found {len(scan_results.get('vulnerabilities', []))} vulnerabilities")
        print(f"🖥️  Scanned {len(scan_results.get('hosts', {}))} hosts")
        
        # Display basic scan results
        print("\n📋 Scan Results Summary:")
        print("-" * 40)
        
        if scan_results.get('hosts'):
            for host_ip, host_info in scan_results['hosts'].items():
                print(f"Host: {host_ip}")
                print(f"  State: {host_info.get('state', 'unknown')}")
                if host_info.get('hostname'):
                    print(f"  Hostname: {host_info['hostname']}")
                
                ports = host_info.get('ports', {})
                if ports:
                    print(f"  Open Ports: {len(ports)}")
                    for port, port_info in ports.items():
                        service = port_info.get('name', 'unknown')
                        product = port_info.get('product', '')
                        version = port_info.get('version', '')
                        print(f"    {port}: {service} {product} {version}".strip())
                print()
        
        # Display vulnerabilities
        vulnerabilities = scan_results.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"🚨 Vulnerabilities Found ({len(vulnerabilities)}):")
            print("-" * 40)
            for i, vuln in enumerate(vulnerabilities[:10], 1):  # Show first 10
                cve_id = vuln.get('cve_id', 'Unknown')
                score = vuln.get('score', 0)
                severity = vuln.get('severity', 'unknown')
                description = vuln.get('description', 'No description')
                port = vuln.get('port', 'unknown')
                
                print(f"{i:2d}. {cve_id} (Score: {score}) [{severity.upper()}]")
                print(f"    Port: {port}")
                print(f"    Description: {description[:100]}{'...' if len(description) > 100 else ''}")
                print()
            
            if len(vulnerabilities) > 10:
                print(f"    ... and {len(vulnerabilities) - 10} more vulnerabilities")
        else:
            print("✅ No vulnerabilities found in this scan")
        
        # Run compliance analysis
        print("\n🔍 Running Compliance Analysis...")
        print("-" * 40)
        
        # Test with OWASP framework
        owasp_analyzer = ComplianceAnalyzer(ComplianceStandard.OWASP)
        compliance_result = owasp_analyzer.analyze_scan_results(scan_results)
        
        print("📊 OWASP Compliance Analysis Results:")
        print(f"  Compliance Score: {compliance_result.get('compliance_score', 0):.1f}%")
        print(f"  Risk Level: {compliance_result.get('risk_level', 'unknown').upper()}")
        print(f"  Total Violations: {len(compliance_result.get('violations', []))}")
        
        # Display violations
        violations = compliance_result.get('violations', [])
        if violations:
            print("\n🚨 Compliance Violations:")
            for i, violation in enumerate(violations[:5], 1):  # Show first 5
                requirement = violation.get('requirement', 'Unknown')
                severity = violation.get('severity', 'unknown')
                description = violation.get('description', 'No description')
                
                print(f"  {i}. {requirement} [{severity.upper()}]")
                print(f"     {description}")
                print()
            
            if len(violations) > 5:
                print(f"     ... and {len(violations) - 5} more violations")
        
        # Generate compliance report
        print("\n📋 Detailed Compliance Report:")
        print("-" * 40)
        report = owasp_analyzer.generate_compliance_report(compliance_result)
        print(report)
        
        # Save results to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f"quick_scan_compliance_{timestamp}.json"
        
        output_data = {
            'scan_info': {
                'target': '192.168.88.250',
                'scan_time': scan_results.get('scan_time'),
                'scan_type': 'quick_scan_compliance_test'
            },
            'scan_results': scan_results,
            'compliance_analysis': compliance_result
        }
        
        with open(results_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"\n💾 Results saved to: {results_file}")
        
        return True
        
    except Exception as e:
        print(f"❌ Scan failed with error: {e}")
        return False


def main():
    """Main function to run the quick scan compliance test."""
    print("🧪 CapScan Quick Scan Compliance Test")
    print("Testing compliance analysis with real vulnerability scan")
    print()
    
    success = test_quick_scan_compliance()
    
    if success:
        print("\n🎉 Quick scan compliance test completed successfully!")
        return 0
    else:
        print("\n❌ Quick scan compliance test failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
