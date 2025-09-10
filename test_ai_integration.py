#!/usr/bin/env python3
"""
Test script for AI integration features
Tests the AI service, compliance analysis, and mitigation recommendations.
"""

import json
import sys
from datetime import datetime
from ai_service import AIService
from compliance.analyzers import ComplianceAnalyzer
from compliance.frameworks import ComplianceStandard
from mitigation.engine import MitigationEngine
from database import Database


def test_ai_service():
    """Test AI service functionality."""
    print("🧪 Testing AI Service...")
    print("=" * 50)
    
    ai_service = AIService()
    
    # Test service status
    status = ai_service.get_service_status()
    print("AI Service Status:")
    print(json.dumps(status, indent=2))
    
    # Test with sample scan data
    sample_scan = {
        'target': '192.168.1.100',
        'scan_time': datetime.now().isoformat(),
        'vulnerabilities': [
            {
                'cve_id': 'CVE-2021-44228',
                'score': 9.8,
                'description': 'Apache Log4j2 Remote Code Execution vulnerability',
                'severity': 'critical',
                'host_ip': '192.168.1.100',
                'port': 'tcp/8080',
                'raw_output': 'CVE-2021-44228 9.8 Apache Log4j2 2.0-beta9 through 2.15.0'
            },
            {
                'cve_id': 'CVE-2020-14145',
                'score': 7.5,
                'description': 'OpenSSH through 8.3 and earlier vulnerability',
                'severity': 'high',
                'host_ip': '192.168.1.100',
                'port': 'tcp/22',
                'raw_output': 'CVE-2020-14145 7.5 OpenSSH through 8.3 and earlier'
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
                        'version': '8.2p1',
                        'extrainfo': 'Ubuntu-4ubuntu0.2'
                    },
                    'tcp/8080': {
                        'state': 'open',
                        'name': 'http',
                        'product': 'Apache Tomcat',
                        'version': '9.0.65',
                        'extrainfo': 'Ubuntu'
                    }
                }
            }
        }
    }
    
    print("\n🔍 Testing vulnerability analysis...")
    analysis = ai_service.analyze_vulnerabilities(sample_scan)
    print("Analysis result:")
    print(json.dumps(analysis, indent=2)[:500] + "...")
    
    print("\n📊 Testing compliance checking...")
    compliance = ai_service.check_compliance(sample_scan, "OWASP")
    print("Compliance result:")
    print(json.dumps(compliance, indent=2)[:500] + "...")
    
    print("\n🛠️ Testing mitigation recommendations...")
    mitigation = ai_service.generate_mitigation_recommendations(sample_scan['vulnerabilities'][0])
    print("Mitigation result:")
    print(json.dumps(mitigation, indent=2)[:500] + "...")
    
    return True


def test_compliance_framework():
    """Test compliance framework functionality."""
    print("\n🧪 Testing Compliance Framework...")
    print("=" * 50)
    
    # Test OWASP compliance
    owasp_analyzer = ComplianceAnalyzer(ComplianceStandard.OWASP)
    
    sample_scan = {
        'target': '192.168.1.100',
        'scan_time': datetime.now().isoformat(),
        'vulnerabilities': [
            {
                'cve_id': 'CVE-2021-44228',
                'score': 9.8,
                'description': 'Apache Log4j2 Remote Code Execution vulnerability',
                'severity': 'critical',
                'host_ip': '192.168.1.100',
                'port': 'tcp/8080'
            }
        ],
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
    
    print("🔍 Testing OWASP compliance analysis...")
    compliance_result = owasp_analyzer.analyze_scan_results(sample_scan)
    print("OWASP Compliance Result:")
    print(json.dumps(compliance_result, indent=2))
    
    print("\n📋 Testing compliance report generation...")
    report = owasp_analyzer.generate_compliance_report(compliance_result)
    print("Compliance Report:")
    print(report)
    
    return True


def test_mitigation_engine():
    """Test mitigation engine functionality."""
    print("\n🧪 Testing Mitigation Engine...")
    print("=" * 50)
    
    mitigation_engine = MitigationEngine()
    
    sample_scan = {
        'target': '192.168.1.100',
        'scan_time': datetime.now().isoformat(),
        'vulnerabilities': [
            {
                'cve_id': 'CVE-2021-44228',
                'score': 9.8,
                'description': 'Apache Log4j2 Remote Code Execution vulnerability',
                'severity': 'critical',
                'host_ip': '192.168.1.100',
                'port': 'tcp/8080'
            },
            {
                'cve_id': 'CVE-2020-14145',
                'score': 7.5,
                'description': 'OpenSSH through 8.3 and earlier vulnerability',
                'severity': 'high',
                'host_ip': '192.168.1.100',
                'port': 'tcp/22'
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
    
    print("🔍 Testing mitigation plan generation...")
    mitigation_plan = mitigation_engine.generate_mitigation_plan(sample_scan)
    print("Mitigation Plan:")
    print(json.dumps(mitigation_plan, indent=2))
    
    return True


def test_database_integration():
    """Test database integration with AI features."""
    print("\n🧪 Testing Database Integration...")
    print("=" * 50)
    
    try:
        # Test database connection
        with Database(password="test_password") as db:
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
            
            print("💾 Testing AI analysis storage...")
            analysis_id = db.save_ai_analysis(
                scan_id="test_scan_123",
                analysis_type="compliance",
                standard="OWASP",
                compliance_score=75.5,
                risk_level="high",
                analysis_data=sample_analysis
            )
            print(f"✅ AI analysis saved with ID: {analysis_id}")
            
            # Test mitigation recommendations storage
            sample_recommendations = [
                {
                    'vulnerability_id': 'CVE-2021-44228',
                    'recommendation_type': 'immediate',
                    'priority': 'critical',
                    'title': 'Apply Log4j2 security patch',
                    'description': 'Apply the latest security patch for Apache Log4j2',
                    'steps': ['Download patch', 'Apply patch', 'Test application'],
                    'resources': {'documentation': ['https://logging.apache.org/log4j/2.x/security.html']},
                    'estimated_effort': 'medium',
                    'status': 'pending',
                    'due_date': '2024-01-15T00:00:00'
                }
            ]
            
            print("💾 Testing mitigation recommendations storage...")
            rec_ids = db.save_mitigation_recommendations(
                scan_id="test_scan_123",
                recommendations=sample_recommendations
            )
            print(f"✅ Mitigation recommendations saved with IDs: {rec_ids}")
            
            # Test retrieval
            print("📊 Testing data retrieval...")
            ai_analyses = db.get_ai_analysis("test_scan_123")
            print(f"✅ Retrieved {len(ai_analyses)} AI analyses")
            
            recommendations = db.get_mitigation_recommendations("test_scan_123")
            print(f"✅ Retrieved {len(recommendations)} mitigation recommendations")
            
            # Test summary
            summary = db.get_ai_summary("test_scan_123")
            print("✅ AI Summary:")
            print(json.dumps(summary, indent=2))
            
        return True
        
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False


def main():
    """Run all AI integration tests."""
    print("🚀 Starting AI Integration Tests")
    print("=" * 60)
    
    tests = [
        ("AI Service", test_ai_service),
        ("Compliance Framework", test_compliance_framework),
        ("Mitigation Engine", test_mitigation_engine),
        ("Database Integration", test_database_integration)
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
        print("🎉 All tests passed! AI integration is working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
