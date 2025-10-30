#!/usr/bin/env python3
"""
Debug compliance mapping for real vulnerabilities
"""

import json
from datetime import datetime
from compliance.analyzers import ComplianceAnalyzer
from compliance.frameworks import ComplianceStandard

def debug_compliance_mapping():
    """Debug why compliance isn't detecting violations."""
    print("🔍 Debugging Compliance Mapping...")
    print("=" * 60)
    
    # Sample vulnerabilities that should trigger compliance violations
    sample_vulnerabilities = [
        {
            'cve_id': 'CVE-2021-44228',
            'score': 9.8,
            'severity': 'critical',
            'description': 'Apache Log4j2 Remote Code Execution vulnerability',
            'host_ip': '192.168.88.250',
            'port': 'tcp/8080'
        },
        {
            'cve_id': 'CVE-2020-14145',
            'score': 7.5,
            'severity': 'high',
            'description': 'OpenSSH through 8.3 and earlier vulnerability with privilege escalation',
            'host_ip': '192.168.88.250',
            'port': 'tcp/22'
        },
        {
            'cve_id': 'CVE-2019-12345',
            'score': 5.2,
            'severity': 'medium',
            'description': 'Information disclosure vulnerability in web application',
            'host_ip': '192.168.88.250',
            'port': 'tcp/80'
        }
    ]
    
    # Test each compliance standard
    standards = [
        ComplianceStandard.OWASP,
        ComplianceStandard.ISO27001,
        ComplianceStandard.PCI_DSS,
        ComplianceStandard.NIST
    ]
    
    for standard in standards:
        print(f"\n🔍 Testing {standard.value} Compliance...")
        analyzer = ComplianceAnalyzer(standard)
        framework = analyzer.framework
        
        print(f"Available vulnerability types: {list(framework._extract_vulnerability_types(sample_vulnerabilities[0]))}")
        
        # Test each vulnerability
        for i, vuln in enumerate(sample_vulnerabilities, 1):
            print(f"\nVulnerability {i}: {vuln['cve_id']}")
            print(f"  Description: {vuln['description']}")
            print(f"  Severity: {vuln['severity']}")
            
            # Extract vulnerability types
            vuln_types = framework._extract_vulnerability_types(vuln)
            print(f"  Extracted types: {vuln_types}")
            
            # Check if it violates requirements
            violates = framework._vulnerability_violates_requirements(vuln)
            print(f"  Violates requirements: {violates}")
            
            if violates:
                # Find which requirements it violates
                for req_id, req in framework.requirements.items():
                    req_types = req.get('vulnerability_types', [])
                    if any(vuln_type in req_types for vuln_type in vuln_types):
                        print(f"    Violates: {req_id} - {req['title']}")
        
        # Run full compliance analysis
        scan_results = {
            'target': '192.168.88.250',
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': sample_vulnerabilities
        }
        
        result = analyzer.analyze_scan_results(scan_results)
        print(f"\n{standard.value} Result:")
        print(f"  Score: {result['compliance_score']:.1f}/100")
        print(f"  Status: {result['status']}")
        print(f"  Violations: {len(result['violations'])}")
        
        if result['violations']:
            for violation in result['violations']:
                print(f"    - {violation['vulnerability_id']}: {violation['description']}")

if __name__ == "__main__":
    debug_compliance_mapping()
