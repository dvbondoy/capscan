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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AIService:
    """
    Core AI service for vulnerability analysis and compliance checking.
    Supports multiple free AI backends including local models and free APIs.
    """
    
    def __init__(self, model: str = "gpt-3.5-turbo", temperature: float = 0.3, backend: str = "auto"):
        """
        Initialize AI service.
        
        Args:
            model (str): AI model to use
            temperature (float): Temperature for AI responses (0.0-1.0)
            backend (str): AI backend to use ('auto', 'tgpt', 'ollama', 'huggingface', 'mock')
        """
        self.model = model
        self.temperature = temperature
        self.backend = backend
        self.ai_available = False
        self.active_backend = None
        
        # Check available backends
        self._detect_available_backends()
        
        if not self.ai_available:
            logger.warning("No AI backends available. Using mock responses.")
            self.active_backend = "mock"
            self.ai_available = True
    
    def _detect_available_backends(self):
        """Detect which AI backends are available."""
        available_backends = []
        
        # Check tgpt
        if self._check_tgpt_availability():
            available_backends.append("tgpt")
        
        # Check Ollama
        if self._check_ollama_availability():
            available_backends.append("ollama")
        
        # Check Hugging Face Transformers
        if self._check_huggingface_availability():
            available_backends.append("huggingface")
        
        # Always available
        available_backends.append("mock")
        
        if available_backends:
            self.ai_available = True
            if self.backend == "auto":
                # Prefer local models over API-based ones
                if "ollama" in available_backends:
                    self.active_backend = "ollama"
                elif "huggingface" in available_backends:
                    self.active_backend = "huggingface"
                elif "tgpt" in available_backends:
                    self.active_backend = "tgpt"
                else:
                    self.active_backend = "mock"
            else:
                self.active_backend = self.backend if self.backend in available_backends else "mock"
        
        logger.info(f"Available AI backends: {available_backends}")
        logger.info(f"Using backend: {self.active_backend}")

    def _check_tgpt_availability(self) -> bool:
        """Check if tgpt is available and properly configured."""
        try:
            # Try to run tgpt without arguments to check if it's available
            result = subprocess.run(['tgpt'], 
                                  capture_output=True, text=True, timeout=10)
            # tgpt is available if it returns usage information (even with non-zero exit code)
            return 'usage:' in result.stdout.lower() and 'tgpt' in result.stdout.lower()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _check_ollama_availability(self) -> bool:
        """Check if Ollama is available."""
        try:
            result = subprocess.run(['ollama', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _check_huggingface_availability(self) -> bool:
        """Check if Hugging Face transformers is available."""
        try:
            import transformers
            return True
        except ImportError:
            return False
    
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
        
        if self.active_backend == "tgpt":
            return self._call_tgpt(prompt, max_tokens)
        elif self.active_backend == "ollama":
            return self._call_ollama(prompt, max_tokens)
        elif self.active_backend == "huggingface":
            return self._call_huggingface(prompt, max_tokens)
        elif self.active_backend == "mock":
            return self._call_mock(prompt)
        else:
            logger.error(f"Unknown backend: {self.active_backend}")
            return None

    def _call_tgpt(self, prompt: str, max_tokens: int = 2000) -> Optional[str]:
        """Call tgpt with the given prompt."""
        try:
            # Call tgpt with text query subcommand
            cmd = ['tgpt', 'tx', prompt]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                logger.error(f"tgpt error: {result.stderr}")
                return None
        except Exception as e:
            logger.error(f"Error calling tgpt: {e}")
            return None

    def _call_ollama(self, prompt: str, max_tokens: int = 2000) -> Optional[str]:
        """Call Ollama with the given prompt."""
        try:
            # Use a small, fast model like llama2:7b or codellama:7b
            model = "llama2:7b"  # You can change this to any Ollama model
            cmd = ['ollama', 'run', model, prompt]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                logger.error(f"Ollama error: {result.stderr}")
                return None
        except Exception as e:
            logger.error(f"Error calling Ollama: {e}")
            return None

    def _call_huggingface(self, prompt: str, max_tokens: int = 2000) -> Optional[str]:
        """Call Hugging Face transformers with the given prompt."""
        try:
            from transformers import pipeline
            
            # Use a small, fast model for local inference
            generator = pipeline("text-generation", 
                              model="microsoft/DialoGPT-small", 
                              max_length=max_tokens,
                              do_sample=True,
                              temperature=self.temperature)
            
            result = generator(prompt, max_length=max_tokens, num_return_sequences=1)
            return result[0]['generated_text'].replace(prompt, "").strip()
        except Exception as e:
            logger.error(f"Error calling Hugging Face: {e}")
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
        
        # Prepare vulnerability data for AI analysis
        vuln_data = self._prepare_vulnerability_data(scan_results)
        
        prompt = f"""
Analyze the following vulnerability scan results and provide a comprehensive risk assessment:

SCAN SUMMARY:
- Target: {scan_results.get('target', 'Unknown')}
- Total Vulnerabilities: {len(scan_results.get('vulnerabilities', []))}
- Hosts Scanned: {len(scan_results.get('hosts', {}))}
- Scan Time: {scan_results.get('scan_time', 'Unknown')}

VULNERABILITY DETAILS:
{json.dumps(vuln_data, indent=2)}

Please provide analysis in the following JSON format:
{{
    "risk_assessment": {{
        "overall_risk_level": "critical|high|medium|low",
        "critical_vulnerabilities": [],
        "high_risk_vulnerabilities": [],
        "business_impact": "description",
        "exploitability": "description"
    }},
    "vulnerability_analysis": [
        {{
            "cve_id": "CVE-XXXX-XXXX",
            "enhanced_score": 8.5,
            "risk_factors": ["factor1", "factor2"],
            "business_impact": "description",
            "exploit_likelihood": "high|medium|low",
            "remediation_priority": "immediate|high|medium|low"
        }}
    ],
    "recommendations": {{
        "immediate_actions": ["action1", "action2"],
        "short_term_goals": ["goal1", "goal2"],
        "long_term_strategy": "description"
    }}
}}
"""
        
        response = self._call_ai(prompt)
        if not response:
            return {'error': 'Failed to get AI analysis'}
        
        try:
            # Try to parse JSON response
            analysis = json.loads(response)
            analysis['analysis_time'] = datetime.now().isoformat()
            analysis['model_used'] = self.model
            analysis['backend'] = self.active_backend
            return analysis
        except json.JSONDecodeError:
            # If JSON parsing fails, return raw response with structure
            return {
                'raw_analysis': response,
                'analysis_time': datetime.now().isoformat(),
                'model_used': self.model,
                'backend': self.active_backend,
                'format': 'text'
            }
    
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
        
        # Prepare compliance-specific data
        compliance_data = self._prepare_compliance_data(scan_results, standard)
        
        prompt = f"""
Analyze the following vulnerability scan results for compliance with {standard} standards:

SCAN DATA:
{json.dumps(compliance_data, indent=2)}

Please provide compliance analysis in the following JSON format:
{{
    "compliance_score": 75,
    "standard": "{standard}",
    "compliance_level": "compliant|partially_compliant|non_compliant",
    "critical_gaps": [
        {{
            "requirement": "requirement_id",
            "description": "description",
            "vulnerabilities": ["CVE-XXXX-XXXX"],
            "severity": "critical|high|medium|low"
        }}
    ],
    "recommendations": [
        {{
            "priority": "critical|high|medium|low",
            "action": "specific action",
            "timeline": "immediate|1-7 days|1-4 weeks|1-3 months",
            "effort": "low|medium|high"
        }}
    ],
    "compliance_summary": "overall compliance status and next steps"
}}
"""
        
        response = self._call_ai(prompt)
        if not response:
            return {'error': 'Failed to get compliance analysis'}
        
        try:
            compliance_analysis = json.loads(response)
            compliance_analysis['analysis_time'] = datetime.now().isoformat()
            compliance_analysis['model_used'] = self.model
            return compliance_analysis
        except json.JSONDecodeError:
            return {
                'raw_analysis': response,
                'analysis_time': datetime.now().isoformat(),
                'model_used': self.model,
                'standard': standard,
                'format': 'text'
            }
    
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
        
        prompt = f"""
Based on the following vulnerability, provide detailed mitigation recommendations:

VULNERABILITY DETAILS:
{json.dumps(vulnerability, indent=2)}

Please provide comprehensive mitigation recommendations in the following JSON format:
{{
    "vulnerability_summary": {{
        "cve_id": "CVE-XXXX-XXXX",
        "severity": "critical|high|medium|low",
        "description": "brief description",
        "affected_components": ["component1", "component2"]
    }},
    "immediate_actions": [
        {{
            "action": "specific action",
            "description": "detailed description",
            "estimated_time": "X hours",
            "difficulty": "easy|medium|hard",
            "tools_needed": ["tool1", "tool2"],
            "verification": "how to verify the fix"
        }}
    ],
    "short_term_fixes": [
        {{
            "action": "specific action",
            "description": "detailed description",
            "timeline": "1-7 days",
            "effort": "low|medium|high",
            "dependencies": ["dependency1", "dependency2"]
        }}
    ],
    "long_term_improvements": [
        {{
            "action": "specific action",
            "description": "detailed description",
            "timeline": "1-4 weeks",
            "effort": "low|medium|high",
            "benefits": ["benefit1", "benefit2"]
        }}
    ],
    "resources": {{
        "documentation": ["url1", "url2"],
        "tools": ["tool1", "tool2"],
        "training": ["course1", "course2"]
    }},
    "testing_verification": [
        {{
            "test": "test description",
            "expected_result": "expected outcome",
            "tools": ["tool1", "tool2"]
        }}
    ]
}}
"""
        
        response = self._call_ai(prompt)
        if not response:
            return {'error': 'Failed to get mitigation recommendations'}
        
        try:
            recommendations = json.loads(response)
            recommendations['generated_time'] = datetime.now().isoformat()
            recommendations['model_used'] = self.model
            return recommendations
        except json.JSONDecodeError:
            return {
                'raw_recommendations': response,
                'generated_time': datetime.now().isoformat(),
                'model_used': self.model,
                'format': 'text'
            }
    
    def _prepare_vulnerability_data(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prepare vulnerability data for AI analysis."""
        vulnerabilities = []
        
        for vuln in scan_results.get('vulnerabilities', []):
            vuln_data = {
                'cve_id': vuln.get('cve_id', 'Unknown'),
                'score': vuln.get('score'),
                'description': vuln.get('description', ''),
                'severity': vuln.get('severity', 'unknown'),
                'host_ip': vuln.get('host_ip', ''),
                'port': vuln.get('port', ''),
                'raw_output': vuln.get('raw_output', '')
            }
            vulnerabilities.append(vuln_data)
        
        return vulnerabilities
    
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
        
        return open_ports
    
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
        
        return services
    
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
                'PCI_DSS',
                'NIST',
                'ISO27001',
                'HIPAA'
            ],
            'available_backends': {
                'tgpt': self._check_tgpt_availability(),
                'ollama': self._check_ollama_availability(),
                'huggingface': self._check_huggingface_availability(),
                'mock': True
            }
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
