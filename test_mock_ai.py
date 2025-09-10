#!/usr/bin/env python3
"""
Test script for Mock AI backend
Tests the AI service with mock responses (no API key required)
"""

import json
from datetime import datetime
from ai_service import AIService

def test_mock_ai():
    """Test AI service with mock backend."""
    print("🧪 Testing Mock AI Service...")
    print("=" * 50)
    
    # Force mock backend
    ai_service = AIService(backend="mock")
    
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
    print(json.dumps(analysis, indent=2)[:1000] + "...")
    
    print("\n📊 Testing compliance checking...")
    compliance = ai_service.check_compliance(sample_scan, "OWASP")
    print("Compliance result:")
    print(json.dumps(compliance, indent=2)[:1000] + "...")
    
    print("\n🛠️ Testing mitigation recommendations...")
    mitigation = ai_service.generate_mitigation_recommendations(sample_scan['vulnerabilities'][0])
    print("Mitigation result:")
    print(json.dumps(mitigation, indent=2)[:1000] + "...")
    
    print("\n✅ Mock AI Service test completed successfully!")
    print("🎉 No API key required - all responses are generated locally!")
    
    return True

if __name__ == "__main__":
    test_mock_ai()
