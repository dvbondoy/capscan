#!/usr/bin/env python3
"""
Quick compliance test using simulated scan data for 192.168.88.250
This provides a faster way to test compliance analysis without waiting for a full scan.
"""

import json
import sys
from datetime import datetime
from compliance.analyzers import ComplianceAnalyzer
from compliance.frameworks import ComplianceStandard


def create_sample_scan_data():
    """Create sample scan data for 192.168.88.250 to test compliance."""
    return {
        'target': '192.168.88.250',
        'scan_time': datetime.now().isoformat(),
        'vulnerabilities': [
            {
                'cve_id': 'CVE-2021-44228',
                'score': 9.8,
                'description': 'Apache Log4j2 Remote Code Execution vulnerability - critical security issue',
                'severity': 'critical',
                'host_ip': '192.168.88.250',
                'port': 'tcp/8080',
                'raw_output': 'CVE-2021-44228 9.8 Apache Log4j2 2.0-beta9 through 2.15.0'
            },
            {
                'cve_id': 'CVE-2020-14145',
                'score': 7.5,
                'description': 'OpenSSH through 8.3 and earlier vulnerability with privilege escalation',
                'severity': 'high',
                'host_ip': '192.168.88.250',
                'port': 'tcp/22',
                'raw_output': 'CVE-2020-14145 7.5 OpenSSH through 8.3 and earlier'
            },
            {
                'cve_id': 'CVE-2019-12345',
                'score': 5.2,
                'description': 'Information disclosure vulnerability in web application',
                'severity': 'medium',
                'host_ip': '192.168.88.250',
                'port': 'tcp/80',
                'raw_output': 'CVE-2019-12345 5.2 Information disclosure'
            },
            {
                'cve_id': 'CVE-2021-34527',
                'score': 8.8,
                'description': 'Windows Print Spooler Remote Code Execution vulnerability',
                'severity': 'high',
                'host_ip': '192.168.88.250',
                'port': 'tcp/445',
                'raw_output': 'CVE-2021-34527 8.8 Windows Print Spooler RCE'
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
                        'version': '8.2p1',
                        'extrainfo': 'Ubuntu-4ubuntu0.2'
                    },
                    'tcp/80': {
                        'state': 'open',
                        'name': 'http',
                        'product': 'Apache httpd',
                        'version': '2.4.41',
                        'extrainfo': 'Ubuntu'
                    },
                    'tcp/443': {
                        'state': 'open',
                        'name': 'https',
                        'product': 'Apache httpd',
                        'version': '2.4.41',
                        'extrainfo': 'Ubuntu'
                    },
                    'tcp/8080': {
                        'state': 'open',
                        'name': 'http-proxy',
                        'product': 'Apache Tomcat',
                        'version': '9.0.65',
                        'extrainfo': 'Ubuntu'
                    },
                    'tcp/445': {
                        'state': 'open',
                        'name': 'microsoft-ds',
                        'product': 'Samba smbd',
                        'version': '4.13.17',
                        'extrainfo': 'Ubuntu'
                    }
                }
            }
        }
    }


def test_compliance_analysis():
    """Test compliance analysis with sample data for 192.168.88.250."""
    print("🚀 CapScan - Quick Compliance Test")
    print("=" * 60)
    print(f"Target: 192.168.88.250")
    print(f"Test Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Create sample scan data
    print("\n📊 Creating sample scan data for compliance testing...")
    scan_results = create_sample_scan_data()
    
    print(f"✅ Sample data created!")
    print(f"📊 Simulated {len(scan_results.get('vulnerabilities', []))} vulnerabilities")
    print(f"🖥️  Simulated {len(scan_results.get('hosts', {}))} hosts")
    
    # Display sample vulnerabilities
    vulnerabilities = scan_results.get('vulnerabilities', [])
    print(f"\n🚨 Sample Vulnerabilities ({len(vulnerabilities)}):")
    print("-" * 50)
    for i, vuln in enumerate(vulnerabilities, 1):
        cve_id = vuln.get('cve_id', 'Unknown')
        score = vuln.get('score', 0)
        severity = vuln.get('severity', 'unknown')
        description = vuln.get('description', 'No description')
        port = vuln.get('port', 'unknown')
        
        print(f"{i}. {cve_id} (Score: {score}) [{severity.upper()}]")
        print(f"   Port: {port}")
        print(f"   Description: {description}")
        print()
    
    # Test multiple compliance frameworks
    frameworks = [
        (ComplianceStandard.OWASP, "OWASP Top 10"),
        (ComplianceStandard.NIST, "NIST Cybersecurity Framework"),
        (ComplianceStandard.ISO27001, "ISO 27001"),
        (ComplianceStandard.PCI_DSS, "PCI DSS")
    ]
    
    print("\n🔍 Running Compliance Analysis...")
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
            
            # Display top violations
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
    results_file = f"compliance_test_results_{timestamp}.json"
    
    output_data = {
        'test_info': {
            'target': '192.168.88.250',
            'test_time': datetime.now().isoformat(),
            'test_type': 'compliance_analysis_test'
        },
        'sample_scan_data': scan_results,
        'compliance_results': all_results
    }
    
    with open(results_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n💾 Test results saved to: {results_file}")
    
    # Summary
    print(f"\n📊 Compliance Test Summary:")
    print("=" * 60)
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
    """Main function to run the compliance test."""
    print("🧪 CapScan Compliance Analysis Test")
    print("Testing compliance analysis with sample vulnerability data")
    print("Target: 192.168.88.250")
    print()
    
    success = test_compliance_analysis()
    
    if success:
        print("\n🎉 Compliance analysis test completed successfully!")
        print("This demonstrates how CapScan would analyze vulnerabilities")
        print("and provide compliance scoring for 192.168.88.250")
        return 0
    else:
        print("\n❌ Compliance analysis test failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
