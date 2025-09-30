#!/usr/bin/env python3
"""
AI Service Module for CapScan
Provides AI-powered vulnerability analysis, compliance checking, and mitigation recommendations.
"""

import json
import subprocess
import os
import tempfile
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import logging

# Import PhindAI instead of using tgpt
from phind_ai import PhindAI

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AIService:
    """
    Core AI service for vulnerability analysis and compliance checking.
    Supports multiple free AI backends including local models and free APIs.
    """
    
    def __init__(self, model: str = "Phind-70B", temperature: float = 0.3, backend: str = "phind"):
        """
        Initialize AI service.
        
        Args:
            model (str): AI model to use (default: Phind-70B)
            temperature (float): Temperature for AI responses (0.0-1.0)
            backend (str): AI backend to use ('phind', 'mock')
        """
        self.model = model
        self.temperature = temperature
        self.backend = backend
        self.ai_available = False
        self.active_backend = None
        
        # Initialize PhindAI
        try:
            self.phind_ai = PhindAI(model=model, temperature=temperature)
            self.ai_available = self.phind_ai.available
            self.active_backend = "phind" if self.ai_available else "mock"
            logger.info(f"PhindAI initialized with model: {model}")
        except Exception as e:
            logger.error(f"Failed to initialize PhindAI: {e}")
            self.phind_ai = None
            self.ai_available = False
            self.active_backend = "mock"
        
        if not self.ai_available:
            logger.warning("PhindAI not available. Using mock responses.")
            self.active_backend = "mock"
            self.ai_available = True
    
    def _check_phind_availability(self) -> bool:
        """Check if PhindAI is available."""
        return self.phind_ai is not None and self.phind_ai.available
    
    def _call_ai(self, prompt: str, max_tokens: int = 2000) -> Optional[str]:
        """
        Call the active AI backend with the given prompt.
        
        Args:
            prompt (str): The prompt to send to AI
            max_tokens (int): Maximum tokens in response
            
        Returns:
            str: AI response or None if failed
        """
        if not self.ai_available:
            return None
        
        if self.active_backend == "phind":
            if self.phind_ai and self.phind_ai.available:
                response = self.phind_ai.chat(prompt, max_tokens=max_tokens)
                if response is None:
                    logger.warning("PhindAI failed at runtime; falling back to mock response")
                    return self._call_mock(prompt)
                return response
            else:
                logger.warning("PhindAI not available; falling back to mock response")
                return self._call_mock(prompt)
        elif self.active_backend == "mock":
            return self._call_mock(prompt)
        else:
            logger.error(f"Unknown backend: {self.active_backend}")
            return None


    def _call_mock(self, prompt: str) -> str:
        """Generate mock AI responses for testing."""
        # Simple rule-based responses for common vulnerability analysis tasks
        if "vulnerability" in prompt.lower() and "analysis" in prompt.lower():
            return """Based on the vulnerability scan results, I've identified several security concerns:

1. **Critical Vulnerabilities**: Found 2 critical issues requiring immediate attention
2. **High Risk Issues**: 3 high-priority vulnerabilities that should be patched within 24-48 hours
3. **Medium Risk Issues**: 5 medium-priority issues for next maintenance window
4. **Low Risk Issues**: 2 low-priority issues for future consideration

**Immediate Actions Required:**
- Apply security patches for critical vulnerabilities
- Review and harden exposed services
- Implement additional monitoring for affected systems

**Risk Assessment**: Overall risk level is HIGH due to critical vulnerabilities present."""
        
        elif "compliance" in prompt.lower():
            return """Compliance Analysis Results:

**OWASP Top 10 Compliance**: 75% compliant
- ✅ A01: Broken Access Control - Compliant
- ❌ A02: Cryptographic Failures - 2 violations found
- ✅ A03: Injection - Compliant
- ❌ A06: Vulnerable Components - 1 critical violation

**Recommendations:**
1. Update cryptographic libraries to latest versions
2. Patch vulnerable third-party components immediately
3. Implement additional input validation controls

**Overall Compliance Score**: 75/100 (Needs Improvement)"""
        
        elif "mitigation" in prompt.lower():
            return """Mitigation Recommendations:

**Immediate Actions (0-24 hours):**
1. Apply critical security patches
2. Disable unnecessary services
3. Implement network segmentation

**Short-term Actions (1-7 days):**
1. Update all software components
2. Implement proper access controls
3. Deploy monitoring and logging

**Long-term Actions (1-4 weeks):**
1. Conduct security training
2. Implement automated vulnerability scanning
3. Establish incident response procedures

**Priority**: Critical vulnerabilities require immediate attention to prevent potential breaches."""
        
        else:
            return f"Mock AI Response: I've analyzed your request about '{prompt[:50]}...' and provided recommendations based on security best practices."
    
    def _call_mock_vulnerability_analysis(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate mock vulnerability analysis."""
        return {
            'risk_assessment': {
                'overall_risk_level': 'high',
                'critical_vulnerabilities': ['CVE-2021-44228'],
                'high_risk_vulnerabilities': ['CVE-2021-45046'],
                'business_impact': 'Potential remote code execution and data breach',
                'exploitability': 'High - publicly available exploits'
            },
            'vulnerability_analysis': [
                {
                    'cve_id': 'CVE-2021-44228',
                    'enhanced_score': 9.8,
                    'risk_factors': ['Remote code execution', 'Widespread usage'],
                    'business_impact': 'Complete system compromise possible',
                    'exploit_likelihood': 'high',
                    'remediation_priority': 'immediate'
                }
            ],
            'recommendations': {
                'immediate_actions': ['Apply security patches immediately', 'Disable vulnerable services'],
                'short_term_goals': ['Update all software components', 'Implement monitoring'],
                'long_term_strategy': 'Establish regular security patching schedule'
            },
            'analysis_time': datetime.now().isoformat(),
            'model_used': self.model,
            'backend': 'mock',
            'format': 'mock'
        }
    
    def _call_mock_compliance_analysis(self, scan_results: Dict[str, Any], standard: str) -> Dict[str, Any]:
        """Generate mock compliance analysis."""
        return {
            'compliance_score': 75,
            'standard': standard,
            'compliance_level': 'partially_compliant',
            'critical_gaps': [
                {
                    'requirement': 'A02',
                    'description': 'Cryptographic Failures',
                    'vulnerabilities': ['CVE-2021-44228'],
                    'severity': 'critical'
                }
            ],
            'recommendations': [
                {
                    'priority': 'critical',
                    'action': 'Update cryptographic libraries',
                    'timeline': 'immediate',
                    'effort': 'medium'
                }
            ],
            'compliance_summary': 'Partially compliant with critical gaps requiring immediate attention',
            'analysis_time': datetime.now().isoformat(),
            'model_used': self.model,
            'format': 'mock'
        }
    
    def _call_mock_mitigation_analysis(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Generate mock mitigation analysis."""
        return {
            'vulnerability_summary': {
                'cve_id': vulnerability.get('cve_id', 'CVE-XXXX-XXXX'),
                'severity': vulnerability.get('severity', 'high'),
                'description': vulnerability.get('description', 'Security vulnerability'),
                'affected_components': ['web_application', 'database']
            },
            'immediate_actions': [
                {
                    'action': 'Apply security patch',
                    'description': 'Install the latest security update',
                    'estimated_time': '2 hours',
                    'difficulty': 'easy',
                    'tools_needed': ['package_manager'],
                    'verification': 'Check version numbers and run tests'
                }
            ],
            'short_term_fixes': [
                {
                    'action': 'Implement additional monitoring',
                    'description': 'Set up security monitoring for affected systems',
                    'timeline': '1-3 days',
                    'effort': 'medium',
                    'dependencies': ['monitoring_tools']
                }
            ],
            'long_term_improvements': [
                {
                    'action': 'Security training',
                    'description': 'Train staff on security best practices',
                    'timeline': '2-4 weeks',
                    'effort': 'high',
                    'benefits': ['Reduced future vulnerabilities', 'Better security awareness']
                }
            ],
            'resources': {
                'documentation': ['https://cve.mitre.org/', 'https://nvd.nist.gov/'],
                'tools': ['vulnerability_scanner', 'patch_management'],
                'training': ['Security awareness course', 'Incident response training']
            },
            'testing_verification': [
                {
                    'test': 'Verify patch installation',
                    'expected_result': 'Vulnerability no longer detected',
                    'tools': ['vulnerability_scanner', 'version_checker']
                }
            ],
            'generated_time': datetime.now().isoformat(),
            'model_used': self.model,
            'format': 'mock'
        }

    def _extract_json(self, text: str) -> Optional[dict]:
        """Try to extract a JSON object from possibly noisy text."""
        if not text:
            return None
        try:
            return json.loads(text)
        except Exception:
            pass
        start = text.find('{')
        end = text.rfind('}')
        if start != -1 and end != -1 and end > start:
            snippet = text[start:end+1]
            try:
                return json.loads(snippet)
            except Exception:
                return None
        return None
    
    def analyze_vulnerabilities(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze vulnerabilities using AI for risk assessment and context.
        
        Args:
            scan_results (Dict): Scan results from Scanner.scan_host()
            
        Returns:
            Dict: AI analysis results
        """
        if not scan_results or not scan_results.get('vulnerabilities'):
            return {'error': 'No vulnerabilities to analyze'}
        
        # Use PhindAI directly if available
        if self.phind_ai and self.phind_ai.available:
            return self.phind_ai.analyze_vulnerabilities(scan_results)
        
        # Fallback to mock response
        return self._call_mock_vulnerability_analysis(scan_results)
    
    def check_compliance(self, scan_results: Dict[str, Any], 
                        standard: str = "OWASP") -> Dict[str, Any]:
        """
        Check scan results against compliance standards.
        
        Args:
            scan_results (Dict): Scan results from Scanner.scan_host()
            standard (str): Compliance standard to check against
            
        Returns:
            Dict: Compliance analysis results
        """
        if not scan_results:
            return {'error': 'No scan results to analyze'}
        
        # Use PhindAI directly if available
        if self.phind_ai and self.phind_ai.available:
            return self.phind_ai.check_compliance(scan_results, standard)
        
        # Fallback to mock response
        return self._call_mock_compliance_analysis(scan_results, standard)
    
    def generate_mitigation_recommendations(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate detailed mitigation recommendations for a specific vulnerability.
        
        Args:
            vulnerability (Dict): Vulnerability details
            
        Returns:
            Dict: Mitigation recommendations
        """
        if not vulnerability:
            return {'error': 'No vulnerability data provided'}
        
        # Use PhindAI directly if available
        if self.phind_ai and self.phind_ai.available:
            return self.phind_ai.generate_mitigation_recommendations(vulnerability)
        
        # Fallback to mock response
        return self._call_mock_mitigation_analysis(vulnerability)
    
    def _prepare_vulnerability_data(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prepare vulnerability data for AI analysis."""
        # Compact: prefer highest severity/score, limit count, truncate fields
        raw_vulns = scan_results.get('vulnerabilities', [])
        def sev_rank(v):
            s = (v.get('severity') or '').lower()
            mapping = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            return mapping.get(s, 0)
        sorted_vulns = sorted(raw_vulns, key=lambda v: (sev_rank(v), v.get('score') or 0), reverse=True)
        top_vulns = sorted_vulns[:20]
        def trunc(s: Any, n: int) -> Any:
            if not isinstance(s, str):
                return s
            return s if len(s) <= n else s[:n] + '...'
        compacted: List[Dict[str, Any]] = []
        for vuln in top_vulns:
            compacted.append({
                'cve_id': vuln.get('cve_id', 'Unknown'),
                'score': vuln.get('score'),
                'severity': vuln.get('severity', 'unknown'),
                'host_ip': vuln.get('host_ip', ''),
                'port': vuln.get('port', ''),
                'description': trunc(vuln.get('description', ''), 280),
                'raw_output': trunc(vuln.get('raw_output', ''), 280)
            })
        return compacted
    
    def _prepare_compliance_data(self, scan_results: Dict[str, Any], 
                                standard: str) -> Dict[str, Any]:
        """Prepare compliance-specific data for analysis."""
        return {
            'target': scan_results.get('target', ''),
            'scan_time': scan_results.get('scan_time', ''),
            'total_vulnerabilities': len(scan_results.get('vulnerabilities', [])),
            'hosts_scanned': len(scan_results.get('hosts', {})),
            'vulnerabilities': self._prepare_vulnerability_data(scan_results),
            'open_ports': self._extract_open_ports(scan_results),
            'services': self._extract_services(scan_results)
        }
    
    def _extract_open_ports(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract open ports information."""
        open_ports = []
        for host_ip, host_info in scan_results.get('hosts', {}).items():
            for port, port_info in host_info.get('ports', {}).items():
                if port_info.get('state') == 'open':
                    open_ports.append({
                        'host': host_ip,
                        'port': port,
                        'service': port_info.get('name', ''),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', '')
                    })
        # Compact: limit to 25 entries
        return open_ports[:25]
    
    def _extract_services(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract services information."""
        services = []
        for host_ip, host_info in scan_results.get('hosts', {}).items():
            for port, port_info in host_info.get('ports', {}).items():
                if port_info.get('state') == 'open' and port_info.get('name'):
                    services.append({
                        'host': host_ip,
                        'port': port,
                        'name': port_info.get('name', ''),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extrainfo': port_info.get('extrainfo', '')
                    })
        # Compact: limit to 25 entries
        return services[:25]
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get AI service status and capabilities."""
        return {
            'ai_available': self.ai_available,
            'active_backend': self.active_backend,
            'model': self.model,
            'temperature': self.temperature,
            'capabilities': [
                'vulnerability_analysis',
                'compliance_checking',
                'mitigation_recommendations',
                'risk_assessment'
            ],
            'supported_standards': [
                'OWASP',
                'NIST',
                'PCI_DSS',
                'ISO27001',
                'PH_DPA'
            ],
            'available_backends': {
                'phind': self._check_phind_availability(),
                'mock': True
            },
            'phind_status': self.phind_ai.get_service_status() if self.phind_ai else None
        }


# Example usage and testing
if __name__ == "__main__":
    # Test AI service
    ai_service = AIService()
    
    print("AI Service Status:")
    print(json.dumps(ai_service.get_service_status(), indent=2))
    
    # Test with sample data
    sample_scan = {
        'target': '192.168.1.100',
        'scan_time': datetime.now().isoformat(),
        'vulnerabilities': [
            {
                'cve_id': 'CVE-2021-44228',
                'score': 9.8,
                'description': 'Apache Log4j2 Remote Code Execution',
                'severity': 'critical',
                'host_ip': '192.168.1.100',
                'port': 'tcp/8080'
            }
        ],
        'hosts': {
            '192.168.1.100': {
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
    
    print("\nTesting vulnerability analysis...")
    analysis = ai_service.analyze_vulnerabilities(sample_scan)
    print("Analysis result:", json.dumps(analysis, indent=2)[:500] + "...")
