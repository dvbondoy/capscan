#!/usr/bin/env python3
"""
Basic AI integration test
Tests core functionality without requiring tgpt.
"""

import json
import sys
from datetime import datetime
from compliance.frameworks import ComplianceFramework, ComplianceStandard
from mitigation.engine import MitigationEngine


def test_compliance_framework():
    """Test compliance framework without AI."""
    print("🧪 Testing Compliance Framework...")
    print("=" * 50)
    
    # Test OWASP framework
    owasp_framework = ComplianceFramework(ComplianceStandard.OWASP)
    
    # Test requirements
    requirements = owasp_framework.get_all_requirements()
    print(f"✅ OWASP framework loaded with {len(requirements)} requirements")
    
    # Test specific requirement
    req = owasp_framework.get_requirement_by_id("A01_Broken_Access_Control")
    if req:
        print(f"✅ Found requirement: {req['title']}")
    else:
        print("❌ Failed to find A01 requirement")
        return False
    
    # Test compliance scoring
    sample_vulnerabilities = [
        {
            'cve_id': 'CVE-2021-44228',
            'score': 9.8,
            'description': 'Apache Log4j2 Remote Code Execution',
            'severity': 'critical'
        }
    ]
    
    score = owasp_framework.calculate_compliance_score(sample_vulnerabilities)
    print(f"✅ Compliance score calculated: {score}")
    
    return True


def test_mitigation_engine():
    """Test mitigation engine without AI."""
    print("\n🧪 Testing Mitigation Engine...")
    print("=" * 50)
    
    mitigation_engine = MitigationEngine()
    
    # Test vulnerability type identification
    vuln = {
        'cve_id': 'CVE-2021-44228',
        'description': 'Apache Log4j2 Remote Code Execution vulnerability',
        'severity': 'critical',
        'score': 9.8
    }
    
    vuln_type = mitigation_engine._identify_vulnerability_type(vuln)
    print(f"✅ Identified vulnerability type: {vuln_type}")
    
    # Test mitigation plan generation
    sample_scan = {
        'target': '192.168.1.100',
        'scan_time': datetime.now().isoformat(),
        'vulnerabilities': [vuln],
        'hosts': {
            '192.168.1.100': {
                'hostname': 'test-server.local',
                'state': 'up',
                'protocols': ['tcp'],
                'ports': {
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
    
    mitigation_plan = mitigation_engine.generate_mitigation_plan(sample_scan)
    print(f"✅ Generated mitigation plan with {len(mitigation_plan['mitigation_plan'])} recommendations")
    
    return True


def test_database_schema():
    """Test database schema updates."""
    print("\n🧪 Testing Database Schema...")
    print("=" * 50)
    
    try:
        from database import Database
        
        # Test database connection with new test database
        with Database(db_path="test_capscan.db", password="test_password") as db:
            print("✅ Database connection successful")
            
            # Test AI analysis storage
            sample_analysis = {
                'compliance_score': 75.5,
                'risk_level': 'high',
                'violations': [
                    {
                        'requirement': 'A01_Broken_Access_Control',
                        'severity': 'high',
                        'description': 'Access control issues found'
                    }
                ]
            }
            
            analysis_id = db.save_ai_analysis(
                scan_id="test_scan_123",
                analysis_type="compliance",
                standard="OWASP",
                compliance_score=75.5,
                risk_level="high",
                analysis_data=sample_analysis
            )
            print(f"✅ AI analysis saved with ID: {analysis_id}")
            
            # Test retrieval
            analyses = db.get_ai_analysis("test_scan_123")
            print(f"✅ Retrieved {len(analyses)} AI analyses")
            
            # Test summary
            summary = db.get_ai_summary("test_scan_123")
            print("✅ AI Summary:")
            print(json.dumps(summary, indent=2))
            
        return True
        
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False


def main():
    """Run basic AI integration tests."""
    print("🚀 Starting Basic AI Integration Tests")
    print("=" * 60)
    
    tests = [
        ("Compliance Framework", test_compliance_framework),
        ("Mitigation Engine", test_mitigation_engine),
        ("Database Schema", test_database_schema)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            print(f"\n🧪 Running {test_name} Test...")
            success = test_func()
            results.append((test_name, success))
            if success:
                print(f"✅ {test_name} test passed")
            else:
                print(f"❌ {test_name} test failed")
        except Exception as e:
            print(f"❌ {test_name} test failed with error: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Test Results Summary")
    print("=" * 60)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{test_name:<25} {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All basic tests passed! Core AI integration is working.")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
