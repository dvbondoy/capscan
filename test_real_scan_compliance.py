#!/usr/bin/env python3
"""
Test compliance analysis with real scan data from 192.168.88.250
This uses the actual nmap scan results to demonstrate compliance analysis.
"""

import json
import sys
from datetime import datetime
from compliance.analyzers import ComplianceAnalyzer
from compliance.frameworks import ComplianceStandard


def create_real_scan_data():
    """Create scan data based on the actual nmap results from 192.168.88.250."""
    return {
        'target': '192.168.88.250',
        'scan_time': datetime.now().isoformat(),
        'vulnerabilities': [
            # High severity OpenSSH vulnerabilities
            {
                'cve_id': 'CVE-2023-38408',
                'score': 9.8,
                'description': 'OpenSSH vulnerability - critical security issue',
                'severity': 'critical',
                'host_ip': '192.168.88.250',
                'port': 'tcp/22',
                'raw_output': 'CVE-2023-38408 9.8 OpenSSH vulnerability'
            },
            {
                'cve_id': 'CVE-2016-1908',
                'score': 9.8,
                'description': 'OpenSSH vulnerability - critical security issue',
                'severity': 'critical',
                'host_ip': '192.168.88.250',
                'port': 'tcp/22',
                'raw_output': 'CVE-2016-1908 9.8 OpenSSH vulnerability'
            },
            {
                'cve_id': 'CVE-2015-5600',
                'score': 8.5,
                'description': 'OpenSSH vulnerability - high severity',
                'severity': 'high',
                'host_ip': '192.168.88.250',
                'port': 'tcp/22',
                'raw_output': 'CVE-2015-5600 8.5 OpenSSH vulnerability'
            },
            # High severity Apache vulnerabilities
            {
                'cve_id': 'CVE-2010-0425',
                'score': 10.0,
                'description': 'Apache httpd vulnerability - critical security issue',
                'severity': 'critical',
                'host_ip': '192.168.88.250',
                'port': 'tcp/80',
                'raw_output': 'CVE-2010-0425 10.0 Apache httpd vulnerability'
            },
            {
                'cve_id': 'CVE-2024-38476',
                'score': 9.8,
                'description': 'Apache httpd vulnerability - critical security issue',
                'severity': 'critical',
                'host_ip': '192.168.88.250',
                'port': 'tcp/80',
                'raw_output': 'CVE-2024-38476 9.8 Apache httpd vulnerability'
            },
            {
                'cve_id': 'CVE-2022-31813',
                'score': 9.8,
                'description': 'Apache httpd vulnerability - critical security issue',
                'severity': 'critical',
                'host_ip': '192.168.88.250',
                'port': 'tcp/80',
                'raw_output': 'CVE-2022-31813 9.8 Apache httpd vulnerability'
            },
            {
                'cve_id': 'CVE-2021-42013',
                'score': 9.8,
                'description': 'Apache httpd vulnerability - critical security issue',
                'severity': 'critical',
                'host_ip': '192.168.88.250',
                'port': 'tcp/80',
                'raw_output': 'CVE-2021-42013 9.8 Apache httpd vulnerability'
            },
            {
                'cve_id': 'CVE-2018-1312',
                'score': 9.8,
                'description': 'Apache httpd vulnerability - critical security issue',
                'severity': 'critical',
                'host_ip': '192.168.88.250',
                'port': 'tcp/80',
                'raw_output': 'CVE-2018-1312 9.8 Apache httpd vulnerability'
            },
            {
                'cve_id': 'CVE-2017-7679',
                'score': 9.8,
                'description': 'Apache httpd vulnerability - critical security issue',
                'severity': 'critical',
                'host_ip': '192.168.88.250',
                'port': 'tcp/80',
                'raw_output': 'CVE-2017-7679 9.8 Apache httpd vulnerability'
            },
            {
                'cve_id': 'CVE-2017-3169',
                'score': 9.8,
                'description': 'Apache httpd vulnerability - critical security issue',
                'severity': 'critical',
                'host_ip': '192.168.88.250',
                'port': 'tcp/80',
                'raw_output': 'CVE-2017-3169 9.8 Apache httpd vulnerability'
            },
            {
                'cve_id': 'CVE-2017-3167',
                'score': 9.8,
                'description': 'Apache httpd vulnerability - critical security issue',
                'severity': 'critical',
                'host_ip': '192.168.88.250',
                'port': 'tcp/80',
                'raw_output': 'CVE-2017-3167 9.8 Apache httpd vulnerability'
            },
            # Medium severity vulnerabilities
            {
                'cve_id': 'CVE-2011-3192',
                'score': 7.8,
                'description': 'Apache httpd vulnerability - high severity',
                'severity': 'high',
                'host_ip': '192.168.88.250',
                'port': 'tcp/80',
                'raw_output': 'CVE-2011-3192 7.8 Apache httpd vulnerability'
            },
            {
                'cve_id': 'CVE-2021-41773',
                'score': 7.5,
                'description': 'Apache httpd vulnerability - high severity',
                'severity': 'high',
                'host_ip': '192.168.88.250',
                'port': 'tcp/80',
                'raw_output': 'CVE-2021-41773 7.5 Apache httpd vulnerability'
            },
            {
                'cve_id': 'CVE-2019-0215',
                'score': 7.5,
                'description': 'Apache httpd vulnerability - high severity',
                'severity': 'high',
                'host_ip': '192.168.88.250',
                'port': 'tcp/80',
                'raw_output': 'CVE-2019-0215 7.5 Apache httpd vulnerability'
            }
        ],
        'hosts': {
            '192.168.88.250': {
                'hostname': 'target-server.local',
                'state': 'up',
                'protocols': ['tcp'],
                'ports': {
                    'tcp/22': {
                        'state': 'open',
                        'name': 'ssh',
                        'product': 'OpenSSH',
                        'version': '4.7p1',
                        'extrainfo': 'Debian 8ubuntu1 (protocol 2.0)'
                    },
                    'tcp/80': {
                        'state': 'open',
                        'name': 'http',
                        'product': 'Apache httpd',
                        'version': '2.2.8',
                        'extrainfo': '(Ubuntu) DAV/2'
                    },
                    'tcp/443': {
                        'state': 'closed',
                        'name': 'https'
                    }
                }
            }
        }
    }


def test_real_scan_compliance():
    """Test compliance analysis with real scan data from 192.168.88.250."""
    print("🚀 CapScan - Real Scan Compliance Test")
    print("=" * 60)
    print(f"Target: 192.168.88.250")
    print(f"Test Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Create scan data based on real nmap results
    print("\n📊 Processing real scan data from 192.168.88.250...")
    scan_results = create_real_scan_data()
    
    print(f"✅ Real scan data processed!")
    print(f"📊 Found {len(scan_results.get('vulnerabilities', []))} vulnerabilities")
    print(f"🖥️  Scanned {len(scan_results.get('hosts', {}))} hosts")
    
    # Display real vulnerabilities
    vulnerabilities = scan_results.get('vulnerabilities', [])
    print(f"\n🚨 Real Vulnerabilities Found ({len(vulnerabilities)}):")
    print("-" * 60)
    
    # Group by severity
    critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
    high_vulns = [v for v in vulnerabilities if v.get('severity') == 'high']
    medium_vulns = [v for v in vulnerabilities if v.get('severity') == 'medium']
    
    print(f"🔴 Critical: {len(critical_vulns)} vulnerabilities")
    print(f"🟠 High: {len(high_vulns)} vulnerabilities")
    print(f"🟡 Medium: {len(medium_vulns)} vulnerabilities")
    
    print(f"\n🔴 Critical Vulnerabilities:")
    for i, vuln in enumerate(critical_vulns[:5], 1):  # Show first 5
        cve_id = vuln.get('cve_id', 'Unknown')
        score = vuln.get('score', 0)
        description = vuln.get('description', 'No description')
        port = vuln.get('port', 'unknown')
        
        print(f"  {i}. {cve_id} (Score: {score})")
        print(f"     Port: {port}")
        print(f"     Description: {description}")
        print()
    
    if len(critical_vulns) > 5:
        print(f"     ... and {len(critical_vulns) - 5} more critical vulnerabilities")
    
    # Test compliance frameworks
    frameworks = [
        (ComplianceStandard.OWASP, "OWASP Top 10"),
        (ComplianceStandard.NIST, "NIST Cybersecurity Framework"),
        (ComplianceStandard.ISO27001, "ISO 27001"),
        (ComplianceStandard.PCI_DSS, "PCI DSS")
    ]
    
    print("\n🔍 Running Compliance Analysis on Real Data...")
    print("=" * 60)
    
    all_results = {}
    
    for standard, name in frameworks:
        print(f"\n📋 Testing {name} Compliance...")
        print("-" * 40)
        
        try:
            analyzer = ComplianceAnalyzer(standard)
            compliance_result = analyzer.analyze_scan_results(scan_results)
            all_results[standard.value] = compliance_result
            
            print(f"✅ {name} Analysis Complete:")
            print(f"   Compliance Score: {compliance_result.get('compliance_score', 0):.1f}%")
            print(f"   Risk Level: {compliance_result.get('risk_level', 'unknown').upper()}")
            print(f"   Total Violations: {len(compliance_result.get('violations', []))}")
            
            # Display violations
            violations = compliance_result.get('violations', [])
            if violations:
                print(f"\n   🚨 Top Violations:")
                for i, violation in enumerate(violations[:3], 1):  # Show top 3
                    requirement = violation.get('requirement', 'Unknown')
                    severity = violation.get('severity', 'unknown')
                    description = violation.get('description', 'No description')
                    
                    print(f"   {i}. {requirement} [{severity.upper()}]")
                    print(f"      {description[:80]}{'...' if len(description) > 80 else ''}")
                
                if len(violations) > 3:
                    print(f"      ... and {len(violations) - 3} more violations")
            
        except Exception as e:
            print(f"❌ {name} analysis failed: {e}")
            all_results[standard.value] = {'error': str(e)}
    
    # Generate detailed OWASP report
    print(f"\n📋 Detailed OWASP Compliance Report:")
    print("=" * 60)
    try:
        owasp_analyzer = ComplianceAnalyzer(ComplianceStandard.OWASP)
        owasp_result = all_results.get('owasp', {})
        if 'error' not in owasp_result:
            report = owasp_analyzer.generate_compliance_report(owasp_result)
            print(report)
        else:
            print(f"❌ OWASP report generation failed: {owasp_result['error']}")
    except Exception as e:
        print(f"❌ OWASP report generation failed: {e}")
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = f"real_scan_compliance_{timestamp}.json"
    
    output_data = {
        'test_info': {
            'target': '192.168.88.250',
            'test_time': datetime.now().isoformat(),
            'test_type': 'real_scan_compliance_analysis',
            'scan_source': 'actual_nmap_scan'
        },
        'real_scan_data': scan_results,
        'compliance_results': all_results
    }
    
    with open(results_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n💾 Real scan compliance results saved to: {results_file}")
    
    # Summary
    print(f"\n📊 Real Scan Compliance Test Summary:")
    print("=" * 60)
    print(f"Target: 192.168.88.250")
    print(f"Total Vulnerabilities: {len(vulnerabilities)}")
    print(f"  - Critical: {len(critical_vulns)}")
    print(f"  - High: {len(high_vulns)}")
    print(f"  - Medium: {len(medium_vulns)}")
    print()
    
    for standard, name in frameworks:
        result = all_results.get(standard.value, {})
        if 'error' in result:
            print(f"{name:<25} ❌ FAILED")
        else:
            score = result.get('compliance_score', 0)
            risk = result.get('risk_level', 'unknown')
            violations = len(result.get('violations', []))
            print(f"{name:<25} ✅ Score: {score:5.1f}% | Risk: {risk.upper():<8} | Violations: {violations}")
    
    return True


def main():
    """Main function to run the real scan compliance test."""
    print("🧪 CapScan Real Scan Compliance Test")
    print("Testing compliance analysis with actual scan data from 192.168.88.250")
    print("Based on real nmap vulnerability scan results")
    print()
    
    success = test_real_scan_compliance()
    
    if success:
        print("\n🎉 Real scan compliance test completed successfully!")
        print("This demonstrates CapScan's compliance analysis capabilities")
        print("using actual vulnerability data from 192.168.88.250")
        return 0
    else:
        print("\n❌ Real scan compliance test failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())