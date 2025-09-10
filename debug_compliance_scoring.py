#!/usr/bin/env python3
"""
Debug compliance scoring to understand why we get 100% compliance
with critical vulnerabilities present.
"""

import json
from compliance.analyzers import ComplianceAnalyzer
from compliance.frameworks import ComplianceStandard


def debug_compliance_scoring():
    """Debug why compliance scoring shows 100% with critical vulnerabilities."""
    print("🔍 Debugging Compliance Scoring Logic")
    print("=" * 60)
    
    # Create test vulnerability data
    test_vulns = [
        {
            'cve_id': 'CVE-2023-38408',
            'score': 9.8,
            'description': 'OpenSSH vulnerability - critical security issue',
            'severity': 'critical',
            'host_ip': '192.168.88.250',
            'port': 'tcp/22'
        },
        {
            'cve_id': 'CVE-2010-0425',
            'score': 10.0,
            'description': 'Apache httpd vulnerability - critical security issue',
            'severity': 'critical',
            'host_ip': '192.168.88.250',
            'port': 'tcp/80'
        }
    ]
    
    print("📊 Test Vulnerabilities:")
    for i, vuln in enumerate(test_vulns, 1):
        print(f"{i}. {vuln['cve_id']} - {vuln['severity'].upper()}")
        print(f"   Description: {vuln['description']}")
        print()
    
    # Test OWASP compliance
    print("🔍 Testing OWASP Compliance Analysis...")
    print("-" * 40)
    
    analyzer = ComplianceAnalyzer(ComplianceStandard.OWASP)
    
    # Debug vulnerability type extraction
    print("🔍 Debugging Vulnerability Type Extraction:")
    for i, vuln in enumerate(test_vulns, 1):
        print(f"\nVulnerability {i}: {vuln['cve_id']}")
        print(f"Description: {vuln['description']}")
        
        # Extract vulnerability types using the framework method
        vuln_types = analyzer.framework._extract_vulnerability_types(vuln)
        print(f"Extracted types: {vuln_types}")
        
        # Check if it violates requirements
        violates = analyzer.framework._vulnerability_violates_requirements(vuln)
        print(f"Violates requirements: {violates}")
        
        # Show what requirements it should match
        print("Available OWASP requirements:")
        for req_id, req in analyzer.framework.get_all_requirements().items():
            print(f"  {req_id}: {req['title']}")
            print(f"    Types: {req.get('vulnerability_types', [])}")
    
    # Test the full analysis
    print(f"\n🔍 Full OWASP Analysis:")
    print("-" * 40)
    
    scan_results = {
        'target': '192.168.88.250',
        'vulnerabilities': test_vulns,
        'hosts': {}
    }
    
    result = analyzer.analyze_scan_results(scan_results)
    print(f"Compliance Score: {result.get('compliance_score', 0)}%")
    print(f"Status: {result.get('status', 'unknown')}")
    print(f"Violations: {len(result.get('violations', []))}")
    print(f"Total vulnerabilities: {result.get('total_vulnerabilities', 0)}")
    
    print(f"\n📋 Detailed Result:")
    print(json.dumps(result, indent=2))
    
    return result


def test_with_better_descriptions():
    """Test with more descriptive vulnerability descriptions."""
    print("\n\n🔧 Testing with Better Vulnerability Descriptions")
    print("=" * 60)
    
    # Create test data with more descriptive vulnerability descriptions
    test_vulns = [
        {
            'cve_id': 'CVE-2023-38408',
            'score': 9.8,
            'description': 'OpenSSH remote code execution vulnerability with privilege escalation',
            'severity': 'critical',
            'host_ip': '192.168.88.250',
            'port': 'tcp/22'
        },
        {
            'cve_id': 'CVE-2010-0425',
            'score': 10.0,
            'description': 'Apache httpd remote code execution vulnerability with command injection',
            'severity': 'critical',
            'host_ip': '192.168.88.250',
            'port': 'tcp/80'
        },
        {
            'cve_id': 'CVE-2021-42013',
            'score': 9.8,
            'description': 'Apache httpd path traversal vulnerability with directory traversal',
            'severity': 'critical',
            'host_ip': '192.168.88.250',
            'port': 'tcp/80'
        }
    ]
    
    print("📊 Test Vulnerabilities with Better Descriptions:")
    for i, vuln in enumerate(test_vulns, 1):
        print(f"{i}. {vuln['cve_id']} - {vuln['severity'].upper()}")
        print(f"   Description: {vuln['description']}")
        print()
    
    # Test OWASP compliance
    print("🔍 Testing OWASP Compliance Analysis...")
    print("-" * 40)
    
    analyzer = ComplianceAnalyzer(ComplianceStandard.OWASP)
    
    # Debug vulnerability type extraction
    print("🔍 Debugging Vulnerability Type Extraction:")
    for i, vuln in enumerate(test_vulns, 1):
        print(f"\nVulnerability {i}: {vuln['cve_id']}")
        print(f"Description: {vuln['description']}")
        
        # Extract vulnerability types using the framework method
        vuln_types = analyzer.framework._extract_vulnerability_types(vuln)
        print(f"Extracted types: {vuln_types}")
        
        # Check if it violates requirements
        violates = analyzer.framework._vulnerability_violates_requirements(vuln)
        print(f"Violates requirements: {violates}")
    
    # Test the full analysis
    print(f"\n🔍 Full OWASP Analysis:")
    print("-" * 40)
    
    scan_results = {
        'target': '192.168.88.250',
        'vulnerabilities': test_vulns,
        'hosts': {}
    }
    
    result = analyzer.analyze_scan_results(scan_results)
    print(f"Compliance Score: {result.get('compliance_score', 0)}%")
    print(f"Status: {result.get('status', 'unknown')}")
    print(f"Violations: {len(result.get('violations', []))}")
    print(f"Total vulnerabilities: {result.get('total_vulnerabilities', 0)}")
    
    if result.get('violations'):
        print(f"\n🚨 Violations Found:")
        for i, violation in enumerate(result['violations'], 1):
            print(f"{i}. {violation.get('requirement', 'Unknown')} [{violation.get('severity', 'unknown')}]")
            print(f"   {violation.get('description', 'No description')}")
    
    return result


def main():
    """Main function to debug compliance scoring."""
    print("🧪 Compliance Scoring Debug Tool")
    print("Investigating why 100% compliance is reported with critical vulnerabilities")
    print()
    
    # Test with generic descriptions (current issue)
    result1 = debug_compliance_scoring()
    
    # Test with better descriptions
    result2 = test_with_better_descriptions()
    
    print(f"\n📊 Summary:")
    print("=" * 60)
    print(f"Generic descriptions: {result1.get('compliance_score', 0)}% compliance")
    print(f"Better descriptions: {result2.get('compliance_score', 0)}% compliance")
    
    if result1.get('compliance_score', 0) == 100.0 and result2.get('compliance_score', 0) < 100.0:
        print("\n✅ Issue identified: Vulnerability descriptions need to contain")
        print("   specific keywords to be properly categorized for compliance analysis.")
    elif result1.get('compliance_score', 0) == result2.get('compliance_score', 0):
        print("\n⚠️  Issue persists: There may be a deeper problem with the compliance logic.")


if __name__ == "__main__":
    main()
