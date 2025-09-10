#!/usr/bin/env python3
"""
Mitigation Templates Module
Provides AI prompt templates for mitigation recommendations.
"""

from typing import Dict, Any
try:
    from jinja2 import Template
except ImportError:
    # Fallback for when jinja2 is not available
    class Template:
        def __init__(self, template_str):
            self.template_str = template_str
        def render(self, **kwargs):
            return self.template_str.format(**kwargs)


class MitigationTemplates:
    """Templates for AI mitigation recommendation prompts."""
    
    @staticmethod
    def get_mitigation_template(vuln_type: str) -> str:
        """Get mitigation template for vulnerability type."""
        templates = {
            'sql_injection': MitigationTemplates._get_sql_injection_template(),
            'xss': MitigationTemplates._get_xss_template(),
            'rce': MitigationTemplates._get_rce_template(),
            'generic': MitigationTemplates._get_generic_template()
        }
        return templates.get(vuln_type, templates['generic'])
    
    @staticmethod
    def _get_sql_injection_template() -> str:
        """SQL injection mitigation template."""
        return """
You are a cybersecurity expert providing mitigation recommendations for SQL injection vulnerabilities.

VULNERABILITY DETAILS:
CVE: {{ cve_id }}
Description: {{ description }}
Severity: {{ severity }}
Score: {{ score }}
Host: {{ host_ip }}:{{ port }}

Provide detailed mitigation recommendations in JSON format:
{
    "immediate_actions": [
        {
            "action": "Block malicious requests",
            "description": "Implement immediate blocking of SQL injection patterns",
            "estimated_time": "1-2 hours",
            "difficulty": "easy",
            "tools_needed": ["WAF", "Firewall"],
            "verification": "Test with SQL injection payloads"
        }
    ],
    "short_term_fixes": [
        {
            "action": "Implement parameterized queries",
            "description": "Replace dynamic SQL with parameterized queries",
            "estimated_time": "2-3 days",
            "difficulty": "medium",
            "tools_needed": ["IDE", "Database"],
            "verification": "Code review and testing"
        }
    ],
    "long_term_improvements": [
        {
            "action": "Implement secure coding practices",
            "description": "Establish secure coding standards and training",
            "estimated_time": "1-3 months",
            "difficulty": "high",
            "tools_needed": ["Training", "Code Analysis Tools"],
            "verification": "Security code review process"
        }
    ]
}
"""
    
    @staticmethod
    def _get_xss_template() -> str:
        """XSS mitigation template."""
        return """
You are a cybersecurity expert providing mitigation recommendations for XSS vulnerabilities.

VULNERABILITY DETAILS:
CVE: {{ cve_id }}
Description: {{ description }}
Severity: {{ severity }}
Score: {{ score }}
Host: {{ host_ip }}:{{ port }}

Provide detailed mitigation recommendations in JSON format:
{
    "immediate_actions": [
        {
            "action": "Implement Content Security Policy",
            "description": "Add CSP headers to prevent XSS attacks",
            "estimated_time": "1-2 hours",
            "difficulty": "easy",
            "tools_needed": ["Web Server Configuration"],
            "verification": "Test CSP implementation"
        }
    ],
    "short_term_fixes": [
        {
            "action": "Implement output encoding",
            "description": "Encode all user-controlled output",
            "estimated_time": "2-3 days",
            "difficulty": "medium",
            "tools_needed": ["Encoding Libraries"],
            "verification": "XSS testing"
        }
    ],
    "long_term_improvements": [
        {
            "action": "Implement secure development lifecycle",
            "description": "Integrate security into development process",
            "estimated_time": "1-3 months",
            "difficulty": "high",
            "tools_needed": ["SDLC Tools", "Training"],
            "verification": "Security assessment"
        }
    ]
}
"""
    
    @staticmethod
    def _get_rce_template() -> str:
        """Remote Code Execution mitigation template."""
        return """
You are a cybersecurity expert providing mitigation recommendations for RCE vulnerabilities.

VULNERABILITY DETAILS:
CVE: {{ cve_id }}
Description: {{ description }}
Severity: {{ severity }}
Score: {{ score }}
Host: {{ host_ip }}:{{ port }}

Provide detailed mitigation recommendations in JSON format:
{
    "immediate_actions": [
        {
            "action": "Isolate affected systems",
            "description": "Immediately isolate systems with RCE vulnerabilities",
            "estimated_time": "30 minutes",
            "difficulty": "easy",
            "tools_needed": ["Network Controls"],
            "verification": "Network isolation verification"
        }
    ],
    "short_term_fixes": [
        {
            "action": "Apply security patches",
            "description": "Apply available security patches immediately",
            "estimated_time": "1-2 days",
            "difficulty": "medium",
            "tools_needed": ["Patch Management"],
            "verification": "Patch verification testing"
        }
    ],
    "long_term_improvements": [
        {
            "action": "Implement secure architecture",
            "description": "Redesign with security-first architecture",
            "estimated_time": "1-3 months",
            "difficulty": "high",
            "tools_needed": ["Architecture Tools"],
            "verification": "Security architecture review"
        }
    ]
}
"""
    
    @staticmethod
    def _get_generic_template() -> str:
        """Generic mitigation template."""
        return """
You are a cybersecurity expert providing mitigation recommendations for vulnerabilities.

VULNERABILITY DETAILS:
CVE: {{ cve_id }}
Description: {{ description }}
Severity: {{ severity }}
Score: {{ score }}
Host: {{ host_ip }}:{{ port }}

Provide detailed mitigation recommendations in JSON format:
{
    "immediate_actions": [
        {
            "action": "Assess vulnerability impact",
            "description": "Evaluate the potential impact of the vulnerability",
            "estimated_time": "1-2 hours",
            "difficulty": "medium",
            "tools_needed": ["Assessment Tools"],
            "verification": "Impact assessment review"
        }
    ],
    "short_term_fixes": [
        {
            "action": "Apply available patches",
            "description": "Apply security patches if available",
            "estimated_time": "1-3 days",
            "difficulty": "medium",
            "tools_needed": ["Patch Management"],
            "verification": "Patch testing"
        }
    ],
    "long_term_improvements": [
        {
            "action": "Improve security posture",
            "description": "Enhance overall security posture",
            "estimated_time": "1-3 months",
            "difficulty": "high",
            "tools_needed": ["Security Framework"],
            "verification": "Security assessment"
        }
    ]
}
"""
    
    @staticmethod
    def render_template(template_str: str, data: Dict[str, Any]) -> str:
        """Render a template with provided data."""
        template = Template(template_str)
        return template.render(**data)
