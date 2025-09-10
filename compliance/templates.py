#!/usr/bin/env python3
"""
Compliance Templates Module
Provides AI prompt templates for compliance analysis.
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


class ComplianceTemplates:
    """Templates for AI compliance analysis prompts."""
    
    @staticmethod
    def get_compliance_analysis_template(standard: str) -> str:
        """Get compliance analysis template for a specific standard."""
        templates = {
            'OWASP': ComplianceTemplates._get_owasp_template(),
            'PCI_DSS': ComplianceTemplates._get_pci_dss_template(),
            'NIST': ComplianceTemplates._get_nist_template(),
            'ISO27001': ComplianceTemplates._get_iso27001_template(),
            'HIPAA': ComplianceTemplates._get_hipaa_template(),
            'SOX': ComplianceTemplates._get_sox_template()
        }
        return templates.get(standard, ComplianceTemplates._get_generic_template())
    
    @staticmethod
    def _get_owasp_template() -> str:
        """OWASP Top 10 analysis template."""
        return """
You are a cybersecurity expert analyzing vulnerability scan results for OWASP Top 10 2021 compliance.

SCAN DATA:
Target: {{ target }}
Scan Time: {{ scan_time }}
Total Vulnerabilities: {{ total_vulnerabilities }}
Hosts Scanned: {{ hosts_scanned }}

VULNERABILITIES:
{% for vuln in vulnerabilities %}
- CVE: {{ vuln.cve_id }}
- Score: {{ vuln.score }}
- Description: {{ vuln.description }}
- Severity: {{ vuln.severity }}
- Host: {{ vuln.host_ip }}:{{ vuln.port }}
{% endfor %}

OPEN PORTS:
{% for port in open_ports %}
- {{ port.host }}:{{ port.port }} ({{ port.service }}) - {{ port.product }} {{ port.version }}
{% endfor %}

Please analyze these results for OWASP Top 10 2021 compliance and provide:

1. **Compliance Score** (0-100): Overall compliance percentage
2. **Compliance Status**: compliant/partially_compliant/non_compliant
3. **OWASP Category Violations**: Map each vulnerability to OWASP categories
4. **Critical Gaps**: Most critical compliance issues
5. **Recommendations**: Specific remediation steps

Format your response as JSON:
{
    "compliance_score": 75,
    "compliance_status": "partially_compliant",
    "owasp_violations": [
        {
            "category": "A01_Broken_Access_Control",
            "title": "Broken Access Control",
            "vulnerabilities": ["CVE-XXXX-XXXX"],
            "severity": "high",
            "description": "Access control issues found"
        }
    ],
    "critical_gaps": [
        {
            "gap": "Missing input validation",
            "impact": "High risk of injection attacks",
            "affected_systems": ["web_application"]
        }
    ],
    "recommendations": [
        {
            "priority": "critical",
            "action": "Implement input validation",
            "timeline": "1-7 days",
            "effort": "medium"
        }
    ]
}
"""
    
    @staticmethod
    def _get_pci_dss_template() -> str:
        """PCI DSS compliance analysis template."""
        return """
You are a PCI DSS compliance expert analyzing vulnerability scan results for PCI DSS 4.0 compliance.

SCAN DATA:
Target: {{ target }}
Scan Time: {{ scan_time }}
Total Vulnerabilities: {{ total_vulnerabilities }}
Hosts Scanned: {{ hosts_scanned }}

VULNERABILITIES:
{% for vuln in vulnerabilities %}
- CVE: {{ vuln.cve_id }}
- Score: {{ vuln.score }}
- Description: {{ vuln.description }}
- Severity: {{ vuln.severity }}
- Host: {{ vuln.host_ip }}:{{ vuln.port }}
{% endfor %}

SERVICES:
{% for service in services %}
- {{ service.host }}:{{ service.port }} - {{ service.name }} ({{ service.product }} {{ service.version }})
{% endfor %}

Analyze for PCI DSS 4.0 compliance focusing on:
- Requirement 1: Network Security Controls
- Requirement 2: Secure Configurations
- Requirement 3: Protect Stored Cardholder Data
- Requirement 4: Encrypt Transmission of Cardholder Data
- Requirement 6: Develop and Maintain Secure Systems
- Requirement 7: Restrict Access to Cardholder Data
- Requirement 8: Identify and Authenticate Access
- Requirement 10: Log and Monitor Access

Provide JSON response:
{
    "compliance_score": 80,
    "compliance_status": "partially_compliant",
    "pci_requirements": [
        {
            "requirement": "Requirement_3",
            "title": "Protect Stored Cardholder Data",
            "status": "non_compliant",
            "violations": ["CVE-XXXX-XXXX"],
            "description": "Cardholder data not properly encrypted"
        }
    ],
    "critical_findings": [
        {
            "finding": "Unencrypted cardholder data storage",
            "requirement": "Requirement_3",
            "severity": "critical",
            "remediation": "Implement encryption for stored data"
        }
    ],
    "recommendations": [
        {
            "priority": "critical",
            "requirement": "Requirement_3",
            "action": "Encrypt all stored cardholder data",
            "timeline": "immediate",
            "effort": "high"
        }
    ]
}
"""
    
    @staticmethod
    def _get_nist_template() -> str:
        """NIST Cybersecurity Framework analysis template."""
        return """
You are a NIST Cybersecurity Framework expert analyzing vulnerability scan results for NIST CSF compliance.

SCAN DATA:
Target: {{ target }}
Scan Time: {{ scan_time }}
Total Vulnerabilities: {{ total_vulnerabilities }}
Hosts Scanned: {{ hosts_scanned }}

VULNERABILITIES:
{% for vuln in vulnerabilities %}
- CVE: {{ vuln.cve_id }}
- Score: {{ vuln.score }}
- Description: {{ vuln.description }}
- Severity: {{ vuln.severity }}
- Host: {{ vuln.host_ip }}:{{ vuln.port }}
{% endfor %}

Analyze against NIST Cybersecurity Framework functions:
- IDENTIFY (ID): Asset Management, Business Environment, Governance, Risk Assessment
- PROTECT (PR): Access Control, Awareness, Data Security, Maintenance, Technology
- DETECT (DE): Anomalies, Security Monitoring
- RESPOND (RS): Response Planning, Communications, Analysis, Mitigation
- RECOVER (RC): Recovery Planning, Improvements, Communications

Provide JSON response:
{
    "compliance_score": 85,
    "compliance_status": "partially_compliant",
    "nist_functions": [
        {
            "function": "PR.DS",
            "title": "Data Security",
            "status": "partially_compliant",
            "vulnerabilities": ["CVE-XXXX-XXXX"],
            "description": "Data protection controls need improvement"
        }
    ],
    "risk_assessment": {
        "overall_risk": "medium",
        "key_risks": [
            {
                "risk": "Data exposure vulnerabilities",
                "function": "PR.DS",
                "impact": "high",
                "likelihood": "medium"
            }
        ]
    },
    "recommendations": [
        {
            "function": "PR.DS",
            "priority": "high",
            "action": "Implement data encryption controls",
            "timeline": "1-4 weeks",
            "effort": "medium"
        }
    ]
}
"""
    
    @staticmethod
    def _get_iso27001_template() -> str:
        """ISO 27001 compliance analysis template."""
        return """
You are an ISO 27001 compliance expert analyzing vulnerability scan results for ISO 27001 compliance.

SCAN DATA:
Target: {{ target }}
Scan Time: {{ scan_time }}
Total Vulnerabilities: {{ total_vulnerabilities }}
Hosts Scanned: {{ hosts_scanned }}

VULNERABILITIES:
{% for vuln in vulnerabilities %}
- CVE: {{ vuln.cve_id }}
- Score: {{ vuln.score }}
- Description: {{ vuln.description }}
- Severity: {{ vuln.severity }}
- Host: {{ vuln.host_ip }}:{{ vuln.port }}
{% endfor %}

Analyze against ISO 27001 Annex A controls:
- A.5: Information Security Policies
- A.6: Organization of Information Security
- A.8: Asset Management
- A.9: Access Control
- A.10: Cryptography
- A.11: Physical and Environmental Security
- A.12: Operations Security
- A.13: Communications Security
- A.14: System Acquisition, Development and Maintenance
- A.15: Supplier Relationships
- A.16: Information Security Incident Management
- A.17: Information Security Aspects of Business Continuity Management
- A.18: Compliance

Provide JSON response:
{
    "compliance_score": 78,
    "compliance_status": "partially_compliant",
    "iso_controls": [
        {
            "control": "A.9",
            "title": "Access Control",
            "status": "non_compliant",
            "vulnerabilities": ["CVE-XXXX-XXXX"],
            "description": "Access control mechanisms insufficient"
        }
    ],
    "control_gaps": [
        {
            "control": "A.9",
            "gap": "Weak authentication mechanisms",
            "severity": "high",
            "remediation": "Implement strong authentication"
        }
    ],
    "recommendations": [
        {
            "control": "A.9",
            "priority": "high",
            "action": "Strengthen access control mechanisms",
            "timeline": "1-4 weeks",
            "effort": "medium"
        }
    ]
}
"""
    
    @staticmethod
    def _get_hipaa_template() -> str:
        """HIPAA compliance analysis template."""
        return """
You are a HIPAA compliance expert analyzing vulnerability scan results for HIPAA compliance.

SCAN DATA:
Target: {{ target }}
Scan Time: {{ scan_time }}
Total Vulnerabilities: {{ total_vulnerabilities }}
Hosts Scanned: {{ hosts_scanned }}

VULNERABILITIES:
{% for vuln in vulnerabilities %}
- CVE: {{ vuln.cve_id }}
- Score: {{ vuln.score }}
- Description: {{ vuln.description }}
- Severity: {{ vuln.severity }}
- Host: {{ vuln.host_ip }}:{{ vuln.port }}
{% endfor %}

Analyze against HIPAA Security Rule safeguards:
- Administrative Safeguards: Security management process, workforce training, access management
- Physical Safeguards: Facility access controls, workstation use restrictions
- Technical Safeguards: Access control, audit controls, integrity, transmission security

Focus on ePHI (electronic Protected Health Information) protection.

Provide JSON response:
{
    "compliance_score": 82,
    "compliance_status": "partially_compliant",
    "hipaa_safeguards": [
        {
            "safeguard": "Technical_Safeguards",
            "status": "partially_compliant",
            "vulnerabilities": ["CVE-XXXX-XXXX"],
            "description": "Technical controls need strengthening"
        }
    ],
    "ephi_risks": [
        {
            "risk": "Unencrypted ePHI transmission",
            "safeguard": "Technical_Safeguards",
            "severity": "high",
            "remediation": "Implement encryption for ePHI"
        }
    ],
    "recommendations": [
        {
            "safeguard": "Technical_Safeguards",
            "priority": "high",
            "action": "Implement ePHI encryption",
            "timeline": "1-7 days",
            "effort": "medium"
        }
    ]
}
"""
    
    @staticmethod
    def _get_sox_template() -> str:
        """SOX compliance analysis template."""
        return """
You are a SOX compliance expert analyzing vulnerability scan results for SOX compliance.

SCAN DATA:
Target: {{ target }}
Scan Time: {{ scan_time }}
Total Vulnerabilities: {{ total_vulnerabilities }}
Hosts Scanned: {{ hosts_scanned }}

VULNERABILITIES:
{% for vuln in vulnerabilities %}
- CVE: {{ vuln.cve_id }}
- Score: {{ vuln.score }}
- Description: {{ vuln.description }}
- Severity: {{ vuln.severity }}
- Host: {{ vuln.host_ip }}:{{ vuln.port }}
{% endfor %}

Analyze against SOX IT General Controls:
- Access Controls: User access management, segregation of duties
- Change Management: System changes, code deployment
- System Development: Secure development practices
- Operations: System monitoring, backup procedures

Focus on controls affecting financial reporting systems.

Provide JSON response:
{
    "compliance_score": 88,
    "compliance_status": "partially_compliant",
    "sox_controls": [
        {
            "control": "Access_Controls",
            "status": "partially_compliant",
            "vulnerabilities": ["CVE-XXXX-XXXX"],
            "description": "Access controls need improvement"
        }
    ],
    "financial_risks": [
        {
            "risk": "Unauthorized access to financial systems",
            "control": "Access_Controls",
            "severity": "high",
            "remediation": "Strengthen access controls"
        }
    ],
    "recommendations": [
        {
            "control": "Access_Controls",
            "priority": "high",
            "action": "Implement multi-factor authentication",
            "timeline": "1-4 weeks",
            "effort": "medium"
        }
    ]
}
"""
    
    @staticmethod
    def _get_generic_template() -> str:
        """Generic compliance analysis template."""
        return """
You are a cybersecurity compliance expert analyzing vulnerability scan results.

SCAN DATA:
Target: {{ target }}
Scan Time: {{ scan_time }}
Total Vulnerabilities: {{ total_vulnerabilities }}
Hosts Scanned: {{ hosts_scanned }}

VULNERABILITIES:
{% for vuln in vulnerabilities %}
- CVE: {{ vuln.cve_id }}
- Score: {{ vuln.score }}
- Description: {{ vuln.description }}
- Severity: {{ vuln.severity }}
- Host: {{ vuln.host_ip }}:{{ vuln.port }}
{% endfor %}

Provide a comprehensive compliance analysis including:
1. Overall compliance score (0-100)
2. Compliance status
3. Key findings and violations
4. Risk assessment
5. Prioritized recommendations

Format as JSON with detailed analysis.
"""
    
    @staticmethod
    def render_template(template_str: str, data: Dict[str, Any]) -> str:
        """Render a template with provided data."""
        template = Template(template_str)
        return template.render(**data)
