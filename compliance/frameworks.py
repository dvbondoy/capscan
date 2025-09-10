#!/usr/bin/env python3
"""
Compliance Framework Definitions
Defines various compliance standards and their requirements.
"""

from typing import Dict, List, Any, Optional
from data.exploitdb_index import ExploitDBIndex, derive_types_from_exploit_metadata
from enum import Enum


class ComplianceStandard(Enum):
    """Supported compliance standards."""
    OWASP = "OWASP"
    PCI_DSS = "PCI_DSS"
    NIST = "NIST"
    ISO27001 = "ISO27001"
    HIPAA = "HIPAA"
    SOX = "SOX"
    PH_DPA = "PH_DPA"


class ComplianceFramework:
    """
    Base class for compliance frameworks.
    Defines the structure and requirements for different compliance standards.
    """
    
    def __init__(self, standard: ComplianceStandard):
        self.standard = standard
        self.requirements = self._load_requirements()
        self.scoring_weights = self._get_scoring_weights()
    
    def _load_requirements(self) -> Dict[str, Any]:
        """Load compliance requirements for the standard."""
        if self.standard == ComplianceStandard.OWASP:
            return self._get_owasp_requirements()
        elif self.standard == ComplianceStandard.PCI_DSS:
            return self._get_pci_dss_requirements()
        elif self.standard == ComplianceStandard.NIST:
            return self._get_nist_requirements()
        elif self.standard == ComplianceStandard.ISO27001:
            return self._get_iso27001_requirements()
        elif self.standard == ComplianceStandard.HIPAA:
            return self._get_hipaa_requirements()
        elif self.standard == ComplianceStandard.SOX:
            return self._get_sox_requirements()
        elif self.standard == ComplianceStandard.PH_DPA:
            return self._get_ph_dpa_requirements()
        else:
            return {}
    
    def _get_owasp_requirements(self) -> Dict[str, Any]:
        """OWASP Top 10 2021 requirements."""
        return {
            "A01_Broken_Access_Control": {
                "title": "Broken Access Control",
                "description": "Access control enforces policy such that users cannot act outside of their intended permissions",
                "vulnerability_types": [
                    "privilege_escalation",
                    "horizontal_privilege_escalation", 
                    "vertical_privilege_escalation",
                    "idor",
                    "broken_authentication"
                ],
                "severity_weight": 0.9
            },
            "A02_Cryptographic_Failures": {
                "title": "Cryptographic Failures",
                "description": "Sensitive data exposure due to weak or missing cryptographic controls",
                "vulnerability_types": [
                    "weak_encryption",
                    "insecure_transmission",
                    "data_exposure",
                    "weak_crypto_algorithms"
                ],
                "severity_weight": 0.8
            },
            "A03_Injection": {
                "title": "Injection",
                "description": "Untrusted data is sent to an interpreter as part of a command or query",
                "vulnerability_types": [
                    "sql_injection",
                    "no_sql_injection",
                    "ldap_injection",
                    "xpath_injection",
                    "command_injection",
                    "code_injection"
                ],
                "severity_weight": 1.0
            },
            "A04_Insecure_Design": {
                "title": "Insecure Design",
                "description": "Missing or ineffective control design",
                "vulnerability_types": [
                    "design_flaws",
                    "missing_security_controls",
                    "insecure_architecture"
                ],
                "severity_weight": 0.7
            },
            "A05_Security_Misconfiguration": {
                "title": "Security Misconfiguration",
                "description": "Insecure default configurations, incomplete configurations, etc.",
                "vulnerability_types": [
                    "default_credentials",
                    "exposed_debug_info",
                    "insecure_headers",
                    "unnecessary_services"
                ],
                "severity_weight": 0.6
            },
            "A06_Vulnerable_Components": {
                "title": "Vulnerable and Outdated Components",
                "description": "Using components with known vulnerabilities",
                "vulnerability_types": [
                    "outdated_software",
                    "known_cves",
                    "unpatched_systems"
                ],
                "severity_weight": 0.8
            },
            "A07_Authentication_Failures": {
                "title": "Identification and Authentication Failures",
                "description": "Confirmation of the user's identity, authentication, and session management",
                "vulnerability_types": [
                    "weak_passwords",
                    "session_management",
                    "multi_factor_auth",
                    "password_policies"
                ],
                "severity_weight": 0.7
            },
            "A08_Software_Data_Integrity": {
                "title": "Software and Data Integrity Failures",
                "description": "Software and data integrity failures related to code and infrastructure",
                "vulnerability_types": [
                    "code_integrity",
                    "data_integrity",
                    "supply_chain_attacks"
                ],
                "severity_weight": 0.6
            },
            "A09_Logging_Monitoring": {
                "title": "Security Logging and Monitoring Failures",
                "description": "Insufficient logging and monitoring capabilities",
                "vulnerability_types": [
                    "insufficient_logging",
                    "monitoring_gaps",
                    "log_tampering"
                ],
                "severity_weight": 0.5
            },
            "A10_SSRF": {
                "title": "Server-Side Request Forgery",
                "description": "SSRF flaws occur whenever a web application is fetching a remote resource",
                "vulnerability_types": [
                    "ssrf",
                    "server_side_request_forgery"
                ],
                "severity_weight": 0.8
            }
        }
    
    def _get_pci_dss_requirements(self) -> Dict[str, Any]:
        """PCI DSS 4.0 requirements."""
        return {
            "Requirement_1": {
                "title": "Install and Maintain Network Security Controls",
                "description": "Network security controls and network access controls",
                "vulnerability_types": [
                    "firewall_misconfiguration",
                    "network_segmentation",
                    "insecure_network_services"
                ],
                "severity_weight": 0.9
            },
            "Requirement_2": {
                "title": "Apply Secure Configurations to All System Components",
                "description": "Secure configuration of system components and software",
                "vulnerability_types": [
                    "default_credentials",
                    "insecure_configurations",
                    "unnecessary_services"
                ],
                "severity_weight": 0.8
            },
            "Requirement_3": {
                "title": "Protect Stored Cardholder Data",
                "description": "Protection of stored cardholder data",
                "vulnerability_types": [
                    "data_encryption",
                    "key_management",
                    "data_retention"
                ],
                "severity_weight": 1.0
            },
            "Requirement_4": {
                "title": "Protect Cardholder Data with Strong Cryptography During Transmission",
                "description": "Encryption of cardholder data during transmission",
                "vulnerability_types": [
                    "weak_encryption",
                    "insecure_transmission",
                    "ssl_tls_issues"
                ],
                "severity_weight": 1.0
            },
            "Requirement_5": {
                "title": "Protect All Systems and Networks from Malicious Software",
                "description": "Anti-malware protection and regular updates",
                "vulnerability_types": [
                    "malware_protection",
                    "antivirus_issues",
                    "system_updates"
                ],
                "severity_weight": 0.7
            },
            "Requirement_6": {
                "title": "Develop and Maintain Secure Systems and Software",
                "description": "Secure development practices and vulnerability management",
                "vulnerability_types": [
                    "secure_coding",
                    "vulnerability_management",
                    "code_review"
                ],
                "severity_weight": 0.8
            },
            "Requirement_7": {
                "title": "Restrict Access to System Components and Cardholder Data",
                "description": "Access control and data access restrictions",
                "vulnerability_types": [
                    "access_control",
                    "privilege_management",
                    "data_access_controls"
                ],
                "severity_weight": 0.9
            },
            "Requirement_8": {
                "title": "Identify Users and Authenticate Access to System Components",
                "description": "User identification and authentication",
                "vulnerability_types": [
                    "user_authentication",
                    "password_policies",
                    "multi_factor_auth"
                ],
                "severity_weight": 0.8
            },
            "Requirement_9": {
                "title": "Restrict Physical Access to Cardholder Data",
                "description": "Physical security controls",
                "vulnerability_types": [
                    "physical_security",
                    "access_controls"
                ],
                "severity_weight": 0.6
            },
            "Requirement_10": {
                "title": "Log and Monitor All Access to System Components and Cardholder Data",
                "description": "Logging and monitoring of access",
                "vulnerability_types": [
                    "logging_monitoring",
                    "audit_trails",
                    "security_monitoring"
                ],
                "severity_weight": 0.7
            },
            "Requirement_11": {
                "title": "Test Security of Systems and Networks Regularly",
                "description": "Regular security testing and vulnerability assessments",
                "vulnerability_types": [
                    "penetration_testing",
                    "vulnerability_scanning",
                    "security_testing"
                ],
                "severity_weight": 0.6
            },
            "Requirement_12": {
                "title": "Support Information Security with Organizational Policies",
                "description": "Information security policies and procedures",
                "vulnerability_types": [
                    "security_policies",
                    "incident_response",
                    "security_awareness"
                ],
                "severity_weight": 0.5
            }
        }
    
    def _get_nist_requirements(self) -> Dict[str, Any]:
        """NIST Cybersecurity Framework requirements."""
        return {
            "ID.AM": {
                "title": "Asset Management",
                "description": "Data, personnel, devices, systems, and facilities are inventoried and managed",
                "vulnerability_types": [
                    "asset_inventory",
                    "asset_management"
                ],
                "severity_weight": 0.4
            },
            "ID.BE": {
                "title": "Business Environment",
                "description": "Organizational mission, objectives, and activities are understood",
                "vulnerability_types": [
                    "business_impact",
                    "risk_assessment"
                ],
                "severity_weight": 0.3
            },
            "ID.GV": {
                "title": "Governance",
                "description": "Cybersecurity policies, procedures, and oversight are established",
                "vulnerability_types": [
                    "governance",
                    "policies_procedures"
                ],
                "severity_weight": 0.4
            },
            "ID.RA": {
                "title": "Risk Assessment",
                "description": "Cybersecurity risk to organizational operations is understood",
                "vulnerability_types": [
                    "risk_assessment",
                    "vulnerability_management"
                ],
                "severity_weight": 0.7
            },
            "ID.SC": {
                "title": "Supply Chain Risk Management",
                "description": "Cybersecurity risk management processes are established",
                "vulnerability_types": [
                    "supply_chain",
                    "third_party_risk"
                ],
                "severity_weight": 0.5
            },
            "PR.AC": {
                "title": "Identity Management and Access Control",
                "description": "Access to assets and facilities is limited and controlled",
                "vulnerability_types": [
                    "access_control",
                    "identity_management"
                ],
                "severity_weight": 0.8
            },
            "PR.AT": {
                "title": "Awareness and Training",
                "description": "Personnel are provided cybersecurity awareness education",
                "vulnerability_types": [
                    "security_awareness",
                    "training"
                ],
                "severity_weight": 0.3
            },
            "PR.DS": {
                "title": "Data Security",
                "description": "Information and records are managed consistent with risk strategy",
                "vulnerability_types": [
                    "data_protection",
                    "data_encryption",
                    "data_classification"
                ],
                "severity_weight": 0.9
            },
            "PR.IP": {
                "title": "Information Protection Processes and Procedures",
                "description": "Security policies and procedures are maintained",
                "vulnerability_types": [
                    "security_policies",
                    "procedures"
                ],
                "severity_weight": 0.6
            },
            "PR.MA": {
                "title": "Maintenance",
                "description": "Maintenance and repairs of organizational assets are performed",
                "vulnerability_types": [
                    "system_maintenance",
                    "patch_management"
                ],
                "severity_weight": 0.7
            },
            "PR.PT": {
                "title": "Protective Technology",
                "description": "Technical security solutions are managed",
                "vulnerability_types": [
                    "security_controls",
                    "protective_technology"
                ],
                "severity_weight": 0.8
            }
        }
    
    def _get_iso27001_requirements(self) -> Dict[str, Any]:
        """ISO 27001 requirements."""
        return {
            "A.5": {
                "title": "Information Security Policies",
                "description": "Management direction and support for information security",
                "vulnerability_types": [
                    "security_policies",
                    "governance"
                ],
                "severity_weight": 0.5
            },
            "A.6": {
                "title": "Organization of Information Security",
                "description": "Internal organization and mobile devices/teleworking",
                "vulnerability_types": [
                    "organization_security",
                    "mobile_security"
                ],
                "severity_weight": 0.4
            },
            "A.7": {
                "title": "Human Resource Security",
                "description": "Prior to employment, during employment, and termination",
                "vulnerability_types": [
                    "hr_security",
                    "background_checks"
                ],
                "severity_weight": 0.3
            },
            "A.8": {
                "title": "Asset Management",
                "description": "Responsibility for assets and information classification",
                "vulnerability_types": [
                    "asset_management",
                    "data_classification",
                    "information_disclosure",
                    "data_exposure"
                ],
                "severity_weight": 0.6
            },
            "A.9": {
                "title": "Access Control",
                "description": "Business requirements for access control and user access management",
                "vulnerability_types": [
                    "access_control",
                    "user_management",
                    "privilege_escalation",
                    "authentication_bypass",
                    "broken_authentication",
                    "idor"
                ],
                "severity_weight": 0.9
            },
            "A.10": {
                "title": "Cryptography",
                "description": "Cryptographic controls and key management",
                "vulnerability_types": [
                    "cryptography",
                    "key_management"
                ],
                "severity_weight": 0.8
            },
            "A.11": {
                "title": "Physical and Environmental Security",
                "description": "Preventing unauthorized physical access and protecting equipment",
                "vulnerability_types": [
                    "physical_security",
                    "environmental_controls"
                ],
                "severity_weight": 0.6
            },
            "A.12": {
                "title": "Operations Security",
                "description": "Operational procedures and responsibilities",
                "vulnerability_types": [
                    "operational_security",
                    "change_management",
                    "rce",
                    "command_injection",
                    "code_injection",
                    "buffer_overflow"
                ],
                "severity_weight": 0.7
            },
            "A.13": {
                "title": "Communications Security",
                "description": "Network security management and information transfer",
                "vulnerability_types": [
                    "network_security",
                    "secure_communications"
                ],
                "severity_weight": 0.8
            },
            "A.14": {
                "title": "System Acquisition, Development and Maintenance",
                "description": "Security requirements and secure development",
                "vulnerability_types": [
                    "secure_development",
                    "system_security"
                ],
                "severity_weight": 0.8
            },
            "A.15": {
                "title": "Supplier Relationships",
                "description": "Information security in supplier relationships",
                "vulnerability_types": [
                    "supplier_security",
                    "third_party_risk"
                ],
                "severity_weight": 0.5
            },
            "A.16": {
                "title": "Information Security Incident Management",
                "description": "Consistent and effective approach to incident management",
                "vulnerability_types": [
                    "incident_management",
                    "response_procedures"
                ],
                "severity_weight": 0.7
            },
            "A.17": {
                "title": "Information Security Aspects of Business Continuity Management",
                "description": "Redundancies and information security continuity",
                "vulnerability_types": [
                    "business_continuity",
                    "disaster_recovery"
                ],
                "severity_weight": 0.6
            },
            "A.18": {
                "title": "Compliance",
                "description": "Compliance with legal and contractual requirements",
                "vulnerability_types": [
                    "legal_compliance",
                    "regulatory_requirements"
                ],
                "severity_weight": 0.7
            }
        }
    
    def _get_hipaa_requirements(self) -> Dict[str, Any]:
        """HIPAA requirements."""
        return {
            "Administrative_Safeguards": {
                "title": "Administrative Safeguards",
                "description": "Administrative actions, policies, and procedures",
                "vulnerability_types": [
                    "administrative_controls",
                    "policies_procedures"
                ],
                "severity_weight": 0.6
            },
            "Physical_Safeguards": {
                "title": "Physical Safeguards",
                "description": "Physical measures, policies, and procedures",
                "vulnerability_types": [
                    "physical_security",
                    "workstation_use"
                ],
                "severity_weight": 0.5
            },
            "Technical_Safeguards": {
                "title": "Technical Safeguards",
                "description": "Technology and policy for protecting ePHI",
                "vulnerability_types": [
                    "access_control",
                    "audit_controls",
                    "integrity",
                    "transmission_security"
                ],
                "severity_weight": 0.9
            }
        }
    
    def _get_sox_requirements(self) -> Dict[str, Any]:
        """SOX requirements."""
        return {
            "Section_302": {
                "title": "Corporate Responsibility for Financial Reports",
                "description": "Management assessment of internal controls",
                "vulnerability_types": [
                    "internal_controls",
                    "financial_reporting"
                ],
                "severity_weight": 0.7
            },
            "Section_404": {
                "title": "Management Assessment of Internal Controls",
                "description": "Annual assessment of internal control structure",
                "vulnerability_types": [
                    "internal_controls",
                    "control_assessment"
                ],
                "severity_weight": 0.8
            },
            "IT_Controls": {
                "title": "IT General Controls",
                "description": "IT controls over financial reporting systems",
                "vulnerability_types": [
                    "access_controls",
                    "change_management",
                    "system_development",
                    "operations"
                ],
                "severity_weight": 0.9
            }
        }

    def _get_ph_dpa_requirements(self) -> Dict[str, Any]:
        """Philippines Data Privacy Act (RA 10173) requirements and NPC IRR mapping.

        The mapping aligns common technical vulnerability types to DPA principles and obligations,
        with emphasis on Section 20 (Security of Personal Information) and breach management.
        """
        return {
            "SEC20_Security_Measures": {
                "title": "Section 20: Security of Personal Information",
                "description": "Implement organizational, physical, and technical measures to protect personal data.",
                "vulnerability_types": [
                    "security_misconfiguration",
                    "default_credentials",
                    "weak_encryption",
                    "insecure_transmission",
                    "weak_crypto_algorithms",
                    "access_control",
                    "broken_authentication",
                    "authentication_bypass",
                    "session_hijacking",
                    "logging_monitoring",
                    "vulnerability_management",
                    "outdated_software",
                    "unpatched_systems",
                    "rce",
                    "ssrf",
                    "xxe",
                    "buffer_overflow"
                ],
                "severity_weight": 1.0
            },
            "SEC20_Data_At_Rest": {
                "title": "Section 20: Protection of Data at Rest",
                "description": "Protect stored personal data via encryption and access restrictions.",
                "vulnerability_types": [
                    "weak_encryption",
                    "data_exposure",
                    "information_disclosure",
                    "data_classification",
                    "asset_management"
                ],
                "severity_weight": 0.9
            },
            "SEC20_Data_In_Transit": {
                "title": "Section 20: Protection of Data in Transit",
                "description": "Encrypt personal data in transit and use secure protocols.",
                "vulnerability_types": [
                    "insecure_transmission",
                    "weak_crypto_algorithms",
                    "secure_communications"
                ],
                "severity_weight": 0.9
            },
            "IRR_Safeguards_Technical": {
                "title": "IRR: Technical Security Measures",
                "description": "Implement technical measures such as access control, encryption, and secure configurations.",
                "vulnerability_types": [
                    "access_control",
                    "privilege_escalation",
                    "idor",
                    "xss",
                    "sql_injection",
                    "command_injection",
                    "code_injection",
                    "path_traversal"
                ],
                "severity_weight": 0.8
            },
            "IRR_Safeguards_Organizational": {
                "title": "IRR: Organizational Security Measures",
                "description": "Policies, procedures, and accountability for personal data protection.",
                "vulnerability_types": [
                    "security_policies",
                    "incident_management",
                    "logging_monitoring",
                    "change_management"
                ],
                "severity_weight": 0.6
            },
            "NPC_Breach_Notification": {
                "title": "NPC: Personal Data Breach Management",
                "description": "Timely detection, assessment, and notification of personal data breaches.",
                "vulnerability_types": [
                    "data_exposure",
                    "information_disclosure",
                    "logging_monitoring"
                ],
                "severity_weight": 0.7
            },
            "Principles_Security": {
                "title": "DPA Principle: Security",
                "description": "Ensure appropriate security protections for personal data.",
                "vulnerability_types": [
                    "security_misconfiguration",
                    "default_credentials",
                    "weak_encryption",
                    "insecure_transmission",
                    "outdated_software"
                ],
                "severity_weight": 0.8
            },
            "Principles_Transparency_Legitimate_Purpose_Proportionality": {
                "title": "DPA Principles: Transparency, Legitimate Purpose, Proportionality",
                "description": "Limit collection and exposure of personal data to legitimate, proportionate purposes with transparency.",
                "vulnerability_types": [
                    "information_disclosure",
                    "data_exposure",
                    "open_redirect"
                ],
                "severity_weight": 0.5
            }
        }
    
    def _get_scoring_weights(self) -> Dict[str, float]:
        """Get scoring weights for different vulnerability types."""
        return {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4,
            'unknown': 0.2
        }
    
    def get_requirement_by_id(self, requirement_id: str) -> Optional[Dict[str, Any]]:
        """Get specific requirement by ID."""
        return self.requirements.get(requirement_id)
    
    def get_all_requirements(self) -> Dict[str, Any]:
        """Get all requirements for the standard."""
        return self.requirements
    
    def calculate_compliance_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """
        Calculate compliance score based on vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            float: Compliance score (0-100)
        """
        if not vulnerabilities:
            return 100.0
        
        total_weight = 0.0
        violation_weight = 0.0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            weight = self.scoring_weights.get(severity, 0.2)
            total_weight += weight
            
            # Check if vulnerability violates any requirements
            if self._vulnerability_violates_requirements(vuln):
                violation_weight += weight
        
        if total_weight == 0:
            return 100.0
        
        compliance_ratio = 1.0 - (violation_weight / total_weight)
        return max(0.0, min(100.0, compliance_ratio * 100.0))
    
    def _vulnerability_violates_requirements(self, vulnerability: Dict[str, Any]) -> bool:
        """Check if vulnerability violates any compliance requirements."""
        vuln_types = self._extract_vulnerability_types(vulnerability)
        
        for requirement in self.requirements.values():
            requirement_types = requirement.get('vulnerability_types', [])
            if any(vuln_type in requirement_types for vuln_type in vuln_types):
                return True
        
        return False
    
    def _extract_vulnerability_types(self, vulnerability: Dict[str, Any]) -> List[str]:
        """Extract vulnerability types from vulnerability data.

        Order:
        1) ExploitDB lookup by CVE
        2) Keyword heuristics on description/raw_output/CVE
        3) Fallbacks (known_cves, port hints, severity hints)
        """
        types: List[str] = []
        
        # Extract from available fields
        description = (vulnerability.get('description') or '').lower()
        raw_output = (vulnerability.get('raw_output') or '').lower()
        cve_id = (vulnerability.get('cve_id') or '').upper()
        severity = (vulnerability.get('severity') or '').lower()
        port = vulnerability.get('port') or ''
        
        combined_text = f"{description} {raw_output} {cve_id}"

        # 1) ExploitDB enrichment
        if cve_id.startswith('CVE-'):
            edb = ExploitDBIndex.get_instance()
            exploits = edb.get_exploits_for_cve(cve_id)
            if exploits:
                types.extend(derive_types_from_exploit_metadata(exploits))
        
        # Comprehensive vulnerability type keywords
        type_keywords = {
            # Injection vulnerabilities
            'sql_injection': ['sql injection', 'sqli', 'database injection', 'sql-injection'],
            'no_sql_injection': ['nosql injection', 'mongodb injection', 'couchdb injection', 'nosql'],
            'ldap_injection': ['ldap injection', 'ldap'],
            'xpath_injection': ['xpath injection', 'xpath'],
            'command_injection': ['command injection', 'os command injection', 'shell injection', 'cmd injection'],
            'code_injection': ['code injection', 'script injection', 'injection'],
            
            # Cross-site vulnerabilities
            'xss': ['cross-site scripting', 'xss', 'reflected xss', 'stored xss', 'dom xss', 'cross site scripting'],
            'csrf': ['cross-site request forgery', 'csrf', 'xsrf', 'cross site request forgery'],
            
            # Remote execution
            'rce': ['remote code execution', 'rce', 'arbitrary code execution', 'code execution', 'remote execution'],
            'lfi': ['local file inclusion', 'lfi', 'file inclusion'],
            'rfi': ['remote file inclusion', 'rfi', 'remote file inclusion'],
            
            # Access control
            'privilege_escalation': ['privilege escalation', 'escalation', 'vertical escalation', 'horizontal escalation'],
            'horizontal_privilege_escalation': ['horizontal privilege escalation', 'horizontal escalation'],
            'authentication_bypass': ['authentication bypass', 'auth bypass', 'bypass authentication', 'bypass'],
            'idor': ['insecure direct object reference', 'idor', 'direct object reference'],
            'broken_authentication': ['broken authentication', 'weak authentication', 'authentication failure'],
            
            # Cryptographic issues
            'weak_encryption': ['weak encryption', 'weak crypto', 'weak cipher', 'insecure encryption', 'encryption'],
            'insecure_transmission': ['insecure transmission', 'unencrypted transmission', 'plaintext transmission'],
            'data_exposure': ['data exposure', 'sensitive data exposure', 'information disclosure', 'data leak'],
            'weak_crypto_algorithms': ['weak crypto algorithms', 'deprecated crypto', 'outdated encryption'],
            
            # Configuration issues
            'security_misconfiguration': ['security misconfiguration', 'misconfiguration', 'insecure configuration'],
            'default_credentials': ['default credentials', 'default password', 'default login'],
            'insecure_directories': ['insecure directories', 'directory traversal', 'path traversal'],
            'information_disclosure': ['information disclosure', 'information leak', 'data leak'],
            
            # Network security
            'ssrf': ['server-side request forgery', 'ssrf', 'request forgery'],
            'xxe': ['xml external entity', 'xxe', 'xml external entity'],
            'open_redirect': ['open redirect', 'redirect vulnerability'],
            'clickjacking': ['clickjacking', 'ui redressing'],
            
            # Session management
            'session_fixation': ['session fixation', 'session vulnerability'],
            'session_hijacking': ['session hijacking', 'session theft'],
            
            # Input validation
            'buffer_overflow': ['buffer overflow', 'stack overflow', 'heap overflow'],
            'integer_overflow': ['integer overflow', 'integer underflow'],
            'format_string': ['format string', 'format string vulnerability'],
            
            # Denial of service
            'dos': ['denial of service', 'dos', 'ddos', 'resource exhaustion'],
            
            # Business logic
            'business_logic': ['business logic', 'logic flaw', 'workflow bypass'],
            'race_condition': ['race condition', 'timing attack', 'concurrency issue'],
            
            # Physical and environmental
            'physical_security': ['physical security', 'physical access', 'hardware security'],
            'environmental_controls': ['environmental controls', 'environmental security'],
            
            # Operational security
            'operational_security': ['operational security', 'process security', 'procedural security'],
            'change_management': ['change management', 'change control', 'configuration management'],
            
            # Network security
            'network_security': ['network security', 'network vulnerability', 'network attack'],
            'secure_communications': ['secure communications', 'communication security'],
            
            # Development security
            'secure_development': ['secure development', 'development security', 'secure coding'],
            'system_security': ['system security', 'platform security', 'infrastructure security'],
            
            # Third-party and supplier
            'supplier_security': ['supplier security', 'vendor security', 'third-party security'],
            'third_party_risk': ['third-party risk', 'supplier risk', 'vendor risk'],
            
            # Incident management
            'incident_management': ['incident management', 'incident response', 'security incident'],
            'response_procedures': ['response procedures', 'emergency procedures', 'crisis management'],
            
            # Access control (general)
            'access_control': ['access control', 'authorization', 'permissions'],
            'user_management': ['user management', 'account management', 'identity management'],
            
            # Asset management
            'asset_management': ['asset management', 'asset security', 'resource management'],
            'data_classification': ['data classification', 'information classification', 'data handling'],
            
            # HR security
            'hr_security': ['hr security', 'personnel security', 'employee security'],
            'background_checks': ['background checks', 'screening', 'vetting'],
            
            # Organization security
            'organization_security': ['organization security', 'corporate security', 'governance'],
            'mobile_security': ['mobile security', 'mobile device security', 'mobile threat'],
            
            # Risk management
            'risk_management': ['risk management', 'risk assessment', 'threat assessment'],
            'vulnerability_management': ['vulnerability management', 'patch management', 'security updates']
        }
        
        for vuln_type, keywords in type_keywords.items():
            if any(keyword in combined_text for keyword in keywords):
                types.append(vuln_type)
        
        # 3) Fallbacks
        # 3a) Known CVEs → vulnerable components (cross-standard catch-alls)
        if cve_id.startswith('CVE-'):
            if 'known_cves' not in types:
                types.append('known_cves')
            if 'outdated_software' not in types:
                types.append('outdated_software')
            if 'unpatched_systems' not in types:
                types.append('unpatched_systems')
            if 'vulnerability_management' not in types:
                types.append('vulnerability_management')

        # 3b) Port-based enrichment if still empty
        if port and not types:
            port_str = str(port)
            if port_str.endswith('/22') and 'authentication_bypass' not in types:
                types.append('authentication_bypass')
            if port_str.endswith('/445') and 'rce' not in types:
                types.append('rce')
            if port_str.endswith('/80') or port_str.endswith('/443'):
                if 'security_misconfiguration' not in types:
                    types.append('security_misconfiguration')

        # 3c) Severity-based hints
        if severity in ['high', 'critical']:
            if 'rce' not in types and any(keyword in combined_text for keyword in ['remote code execution', 'rce', 'execution', 'execute', 'code']):
                types.append('rce')
            if 'privilege_escalation' not in types and any(keyword in combined_text for keyword in ['privilege', 'escalation', 'elevation']):
                types.append('privilege_escalation')
            if 'access_control' not in types and any(keyword in combined_text for keyword in ['access', 'authorization', 'permission']):
                types.append('access_control')
        
        # De-dup
        seen = set()
        deduped: List[str] = []
        for t in types:
            if t not in seen:
                seen.add(t)
                deduped.append(t)
        return deduped


def get_supported_standards() -> List[ComplianceStandard]:
    """Get list of supported compliance standards."""
    return list(ComplianceStandard)


def get_framework(standard: ComplianceStandard) -> ComplianceFramework:
    """Get compliance framework for a specific standard."""
    return ComplianceFramework(standard)
