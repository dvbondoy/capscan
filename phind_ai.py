#!/usr/bin/env python3
"""
PhindAI Wrapper for CapScan
A wrapper around the Phind client to provide a tgpt-like interface for the AI service.
"""

import sys
import os
import logging
from typing import Optional, Dict, Any, List
from phind.phind_client import PhindClient
from phind.phind_chat import PhindChat

# Configure logging
logger = logging.getLogger(__name__)


class PhindAI:
    """
    PhindAI wrapper that provides a tgpt-like interface for CapScan.
    This class wraps the Phind client to match the expected interface.
    """
    
    def __init__(self, model: str = "Phind-70B", temperature: float = 0.3):
        """
        Initialize PhindAI wrapper.
        
        Args:
            model (str): AI model to use (default: Phind-70B)
            temperature (float): Temperature for AI responses (not used by Phind, kept for compatibility)
        """
        self.model = model
        self.temperature = temperature
        self.client = PhindClient()
        self.chat_client = PhindChat(model=model)
        self.available = True
        
        # Skip connection test on startup
        try:
            self._test_connection()
        except Exception as e:
            logger.error(f"Error testing PhindAI connection: {e}")
            self.available = False
    
    def _test_connection(self) -> bool:
        """Test if Phind service is available."""
        try:
            # Try a simple request to test connectivity
            test_response = self.client.chat("test", model=self.model)
            if test_response and len(test_response.strip()) > 0:
                self.available = True
                logger.info("PhindAI connection test successful")
                return True
            else:
                self.available = False
                logger.warning("PhindAI connection test failed - empty response")
                return False
        except Exception as e:
            self.available = False
            logger.error(f"PhindAI connection test failed: {e}")
            return False
    
    def chat(self, prompt: str, model: Optional[str] = None, 
             system_prompt: str = "", max_tokens: int = 2000) -> Optional[str]:
        """
        Chat with Phind AI - main interface method.
        
        Args:
            prompt (str): The prompt to send to AI
            model (str, optional): Model to use (defaults to instance model)
            system_prompt (str): System prompt for context
            max_tokens (int): Maximum tokens (not used by Phind, kept for compatibility)
            
        Returns:
            str: AI response or None if failed
        """
        if not self.available:
            logger.error("PhindAI is not available")
            return None
        
        if not prompt or not prompt.strip():
            logger.warning("Empty prompt provided")
            return None
        
        try:
            # Use provided model or default
            use_model = model or self.model
            
            # Use the chat client for conversation context
            response = self.chat_client.client.chat(
                user_input=prompt,
                model=use_model,
                system_prompt=system_prompt
            )
            
            if response and response.strip():
                return response.strip()
            else:
                logger.warning("Empty response from PhindAI")
                return None
                
        except Exception as e:
            logger.error(f"Error calling PhindAI: {e}")
            return None
    
    def analyze_vulnerabilities(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze vulnerabilities using Phind AI.
        
        Args:
            scan_results (Dict): Scan results from Scanner.scan_host()
            
        Returns:
            Dict: AI analysis results
        """
        if not self.available:
            return {'error': 'PhindAI is not available'}
        
        if not scan_results or not scan_results.get('vulnerabilities'):
            return {'error': 'No vulnerabilities to analyze'}
        
        # Prepare vulnerability data for AI analysis
        vuln_data = self._prepare_vulnerability_data(scan_results)
        
        prompt = f"""
You are a cybersecurity expert. Analyze the following vulnerability scan results and provide a comprehensive risk assessment.

SCAN SUMMARY:
- Target: {scan_results.get('target', 'Unknown')}
- Total Vulnerabilities: {len(scan_results.get('vulnerabilities', []))}
- Hosts Scanned: {len(scan_results.get('hosts', {}))}
- Scan Time: {scan_results.get('scan_time', 'Unknown')}

VULNERABILITY DETAILS:
{self._format_vulnerability_data(vuln_data)}

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
        
        response = self.chat(prompt)
        if not response:
            return {'error': 'Failed to get AI analysis'}
        
        try:
            import json
            # Try to parse JSON response
            parsed = self._extract_json(response)
            if parsed:
                parsed['analysis_time'] = self._get_timestamp()
                parsed['model_used'] = self.model
                parsed['backend'] = 'phind'
                return parsed
            else:
                # Return raw response if JSON parsing fails
                return {
                    'raw_analysis': response,
                    'analysis_time': self._get_timestamp(),
                    'model_used': self.model,
                    'backend': 'phind',
                    'format': 'text'
                }
        except Exception as e:
            logger.error(f"Error parsing AI response: {e}")
            return {
                'raw_analysis': response,
                'analysis_time': self._get_timestamp(),
                'model_used': self.model,
                'backend': 'phind',
                'format': 'text',
                'error': str(e)
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
        if not self.available:
            return {'error': 'PhindAI is not available'}
        
        if not scan_results:
            return {'error': 'No scan results to analyze'}
        
        # Prepare compliance-specific data
        compliance_data = self._prepare_compliance_data(scan_results, standard)
        
        prompt = f"""
You are a compliance expert. Analyze the following vulnerability scan results for compliance with {standard} standards.

SCAN DATA:
{self._format_compliance_data(compliance_data)}

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
        
        response = self.chat(prompt)
        if not response:
            return {'error': 'Failed to get compliance analysis'}
        
        try:
            import json
            parsed = self._extract_json(response)
            if parsed:
                parsed['analysis_time'] = self._get_timestamp()
                parsed['model_used'] = self.model
                return parsed
            else:
                return {
                    'raw_analysis': response,
                    'analysis_time': self._get_timestamp(),
                    'model_used': self.model,
                    'standard': standard,
                    'format': 'text'
                }
        except Exception as e:
            logger.error(f"Error parsing compliance response: {e}")
            return {
                'raw_analysis': response,
                'analysis_time': self._get_timestamp(),
                'model_used': self.model,
                'standard': standard,
                'format': 'text',
                'error': str(e)
            }
    
    def generate_mitigation_recommendations(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate detailed mitigation recommendations for a specific vulnerability.
        
        Args:
            vulnerability (Dict): Vulnerability details
            
        Returns:
            Dict: Mitigation recommendations
        """
        if not self.available:
            return {'error': 'PhindAI is not available'}
        
        if not vulnerability:
            return {'error': 'No vulnerability data provided'}
        
        prompt = f"""
You are a cybersecurity mitigation expert. Based on the following vulnerability, provide detailed mitigation recommendations.

VULNERABILITY DETAILS:
{self._format_vulnerability_details(vulnerability)}

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
        
        response = self.chat(prompt)
        if not response:
            return {'error': 'Failed to get mitigation recommendations'}
        
        try:
            import json
            parsed = self._extract_json(response)
            if parsed:
                parsed['generated_time'] = self._get_timestamp()
                parsed['model_used'] = self.model
                return parsed
            else:
                return {
                    'raw_recommendations': response,
                    'generated_time': self._get_timestamp(),
                    'model_used': self.model,
                    'format': 'text'
                }
        except Exception as e:
            logger.error(f"Error parsing mitigation response: {e}")
            return {
                'raw_recommendations': response,
                'generated_time': self._get_timestamp(),
                'model_used': self.model,
                'format': 'text',
                'error': str(e)
            }
    
    def _prepare_vulnerability_data(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prepare vulnerability data for AI analysis."""
        raw_vulns = scan_results.get('vulnerabilities', [])
        
        # Sort by severity and score
        def sev_rank(v):
            s = (v.get('severity') or '').lower()
            mapping = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            return mapping.get(s, 0)
        
        sorted_vulns = sorted(raw_vulns, key=lambda v: (sev_rank(v), v.get('score') or 0), reverse=True)
        top_vulns = sorted_vulns[:20]  # Limit to top 20
        
        def trunc(s: Any, n: int) -> Any:
            if not isinstance(s, str):
                return s
            return s if len(s) <= n else s[:n] + '...'
        
        compacted = []
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
        return open_ports[:25]  # Limit to 25 entries
    
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
        return services[:25]  # Limit to 25 entries
    
    def _format_vulnerability_data(self, vuln_data: List[Dict[str, Any]]) -> str:
        """Format vulnerability data for AI prompt."""
        import json
        return json.dumps(vuln_data, indent=2)
    
    def _format_compliance_data(self, compliance_data: Dict[str, Any]) -> str:
        """Format compliance data for AI prompt."""
        import json
        return json.dumps(compliance_data, indent=2)
    
    def _format_vulnerability_details(self, vulnerability: Dict[str, Any]) -> str:
        """Format vulnerability details for AI prompt."""
        import json
        return json.dumps(vulnerability, indent=2)
    
    def _extract_json(self, text: str) -> Optional[dict]:
        """Try to extract a JSON object from possibly noisy text."""
        if not text:
            return None
        try:
            import json
            return json.loads(text)
        except Exception:
            pass
        
        # Try to find JSON in the text
        start = text.find('{')
        end = text.rfind('}')
        if start != -1 and end != -1 and end > start:
            snippet = text[start:end+1]
            try:
                import json
                return json.loads(snippet)
            except Exception:
                return None
        return None
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get PhindAI service status and capabilities."""
        return {
            'ai_available': self.available,
            'active_backend': 'phind',
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
            'connection_status': 'connected' if self.available else 'disconnected'
        }


# Example usage and testing
if __name__ == "__main__":
    # Test PhindAI
    phind_ai = PhindAI()
    
    print("PhindAI Service Status:")
    import json
    print(json.dumps(phind_ai.get_service_status(), indent=2))
    
    # Test basic chat
    print("\nTesting basic chat...")
    response = phind_ai.chat("What is cybersecurity?")
    print(f"Response: {response[:100]}..." if response else "No response")
