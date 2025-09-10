#!/usr/bin/env python3
"""
Test compliance system with keyword-based scoring
"""

import json
from datetime import datetime
from engine import Scanner
from compliance.analyzers import ComplianceAnalyzer
from compliance.frameworks import ComplianceStandard

def test_compliance_with_scoring():
    """Test compliance analysis with keyword-based scoring."""
    print("🧪 Testing Compliance with Keyword-Based Scoring...")
    print("=" * 60)
    
    # Create scanner and add sample vulnerabilities with high scores
    scanner = Scanner()
    
    # Sample scan results with high-severity vulnerabilities
    sample_scan = {
        'target': '192.168.1.100',
        'scan_time': datetime.now().isoformat(),
        'vulnerabilities': [
            {
                'cve_id': 'CVE-2021-44228',
                'score': 9.8,  # High score
                'description': 'Apache Log4j2 Remote Code Execution vulnerability - critical security issue',
                'host_ip': '192.168.1.100',
                'port': 'tcp/8080',
                'raw_output': 'CVE-2021-44228 9.8 Apache Log4j2 2.0-beta9 through 2.15.0'
            },
            {
                'cve_id': 'CVE-2020-14145',
                'score': 7.5,  # High score
                'description': 'OpenSSH through 8.3 and earlier vulnerability with privilege escalation',
                'host_ip': '192.168.1.100',
                'port': 'tcp/22',
                'raw_output': 'CVE-2020-14145 7.5 OpenSSH through 8.3 and earlier'
            },
            {
                'cve_id': 'CVE-2019-12345',
                'score': 5.2,  # Medium score
                'description': 'Information disclosure vulnerability in web application',
                'host_ip': '192.168.1.100',
                'port': 'tcp/80',
                'raw_output': 'CVE-2019-12345 5.2 Information disclosure'
            }
        ],
        'hosts': {
            '192.168.1.100': {
                'hostname': 'test-server.local',
                'state': 'up',
                'protocols': ['tcp'],
                'ports': {
                    'tcp/22': {
                        'state': 'open',
                        'name': 'ssh',
                        'product': 'OpenSSH',
                        'version': '8.2p1'
                    },
                    'tcp/80': {
                        'state': 'open',
                        'name': 'http',
                        'product': 'Apache',
                        'version': '2.4.41'
                    },
                    'tcp/8080': {
                        'state': 'open',
                        'name': 'http',
                        'product': 'Apache Tomcat',
                        'version': '9.0.65'
                    }
                }
            }
        }
    }
    
    # Set scan results in scanner
    scanner.scan_results = sample_scan
    scanner.vulnerabilities = sample_scan['vulnerabilities']
    
    # Enhance vulnerabilities with scores and severity
    print("🔍 Enhancing vulnerabilities with keyword-based scoring...")
    enhanced_count = scanner.enhance_vulnerabilities_with_scores()
    print(f"✅ Enhanced {enhanced_count} vulnerabilities")
    
    # Show vulnerability details with severity
    print("\n📊 Vulnerability Details:")
    for i, vuln in enumerate(scanner.vulnerabilities, 1):
        print(f"{i}. {vuln.get('cve_id', 'N/A')} - Score: {vuln.get('score', 'N/A')} - Severity: {vuln.get('severity', 'N/A')}")
        print(f"   Description: {vuln.get('description', 'N/A')}")
        print()
    
    # Test OWASP compliance analysis
    print("🔍 Testing OWASP compliance analysis...")
    owasp_analyzer = ComplianceAnalyzer(ComplianceStandard.OWASP)
    compliance_result = owasp_analyzer.analyze_scan_results(scanner.scan_results)
    
    print("OWASP Compliance Result:")
    print(json.dumps(compliance_result, indent=2))
    
    # Test other compliance standards
    print("\n🔍 Testing other compliance standards...")
    standards = [ComplianceStandard.PCI_DSS, ComplianceStandard.NIST, ComplianceStandard.ISO27001]
    
    for standard in standards:
        analyzer = ComplianceAnalyzer(standard)
        result = analyzer.analyze_scan_results(scanner.scan_results)
        print(f"\n{standard.value} Compliance:")
        print(f"  Score: {result['compliance_score']:.1f}/100")
        print(f"  Status: {result['status']}")
        print(f"  Violations: {len(result['violations'])}")
    
    print("\n✅ Compliance scoring test completed!")
    return True

if __name__ == "__main__":
    test_compliance_with_scoring()
