#!/usr/bin/env python3
"""
Compliance Analyzer Module
Analyzes scan results against compliance frameworks.
"""

import json
from typing import Dict, List, Any, Optional, Tuple
from data.exploitdb_index import ExploitDBIndex, derive_types_from_exploit_metadata
from datetime import datetime
from .frameworks import ComplianceFramework, ComplianceStandard


class ComplianceAnalyzer:
    """
    Analyzes vulnerability scan results against compliance frameworks.
    """
    
    def __init__(self, standard: ComplianceStandard):
        """
        Initialize compliance analyzer.
        
        Args:
            standard: Compliance standard to analyze against
        """
        self.standard = standard
        self.framework = ComplianceFramework(standard)
    
    def analyze_scan_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze scan results for compliance violations.
        
        Args:
            scan_results: Scan results from Scanner.scan_host()
            
        Returns:
            Dict: Compliance analysis results
        """
        if not scan_results or not scan_results.get('vulnerabilities'):
            return {
                'standard': self.standard.value,
                'compliance_score': 100.0,
                'status': 'compliant',
                'violations': [],
                'recommendations': [],
                'analysis_time': datetime.now().isoformat()
            }
        
        vulnerabilities = scan_results.get('vulnerabilities', [])
        compliance_score = self.framework.calculate_compliance_score(vulnerabilities)
        
        # Analyze violations
        violations = self._analyze_violations(vulnerabilities)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(violations)
        
        # Determine compliance status
        status = self._determine_compliance_status(compliance_score, violations)
        
        return {
            'standard': self.standard.value,
            'compliance_score': round(compliance_score, 2),
            'status': status,
            'total_vulnerabilities': len(vulnerabilities),
            'critical_violations': len([v for v in violations if v['severity'] == 'critical']),
            'high_violations': len([v for v in violations if v['severity'] == 'high']),
            'medium_violations': len([v for v in violations if v['severity'] == 'medium']),
            'low_violations': len([v for v in violations if v['severity'] == 'low']),
            'violations': violations,
            'recommendations': recommendations,
            'analysis_time': datetime.now().isoformat()
        }
    
    def _analyze_violations(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze vulnerabilities for compliance violations."""
        violations = []
        
        for vuln in vulnerabilities:
            violation = self._check_vulnerability_compliance(vuln)
            if violation:
                violations.append(violation)
        
        return violations
    
    def _check_vulnerability_compliance(self, vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if a vulnerability violates compliance requirements."""
        vuln_types = self._extract_vulnerability_types(vulnerability)
        violated_requirements = []
        
        for req_id, requirement in self.framework.get_all_requirements().items():
            requirement_types = requirement.get('vulnerability_types', [])
            if any(vuln_type in requirement_types for vuln_type in vuln_types):
                violated_requirements.append({
                    'requirement_id': req_id,
                    'title': requirement.get('title', ''),
                    'description': requirement.get('description', ''),
                    'severity_weight': requirement.get('severity_weight', 0.5)
                })
        
        if not violated_requirements:
            return None
        
        # Calculate violation severity
        max_weight = max(req['severity_weight'] for req in violated_requirements)
        vuln_score = vulnerability.get('score', 0) or 0
        
        if vuln_score >= 9.0 or max_weight >= 0.9:
            severity = 'critical'
        elif vuln_score >= 7.0 or max_weight >= 0.7:
            severity = 'high'
        elif vuln_score >= 4.0 or max_weight >= 0.5:
            severity = 'medium'
        else:
            severity = 'low'
        
        return {
            'vulnerability_id': vulnerability.get('cve_id', 'Unknown'),
            'description': vulnerability.get('description', ''),
            'score': vuln_score,
            'severity': severity,
            'host_ip': vulnerability.get('host_ip', ''),
            'port': vulnerability.get('port', ''),
            'violated_requirements': violated_requirements,
            'vulnerability_types': vuln_types
        }
    
    def _extract_vulnerability_types(self, vulnerability: Dict[str, Any]) -> List[str]:
        """Extract vulnerability types from vulnerability data.

        Order:
        1) ExploitDB lookup by CVE
        2) Keyword heuristics on description/raw_output/CVE
        3) Severity hints
        """
        types: List[str] = []
        
        description = (vulnerability.get('description') or '').lower()
        raw_output = (vulnerability.get('raw_output') or '').lower()
        cve_id = (vulnerability.get('cve_id') or '').upper()
        severity = (vulnerability.get('severity') or '').lower()
        combined_text = f"{description} {raw_output} {cve_id}"

        # 1) ExploitDB enrichment
        if cve_id.startswith('CVE-'):
            edb = ExploitDBIndex.get_instance()
            exploits = edb.get_exploits_for_cve(cve_id)
            if exploits:
                types.extend(derive_types_from_exploit_metadata(exploits))
        
        # Enhanced vulnerability type detection - comprehensive patterns
        type_patterns = {
            # Injection vulnerabilities
            'sql_injection': ['sql injection', 'sqli', 'sql-injection', 'database injection'],
            'no_sql_injection': ['nosql injection', 'mongodb injection', 'couchdb injection', 'nosql'],
            'ldap_injection': ['ldap injection', 'ldap'],
            'xpath_injection': ['xpath injection', 'xpath'],
            'command_injection': ['command injection', 'cmd injection', 'command', 'os command injection', 'shell injection'],
            'code_injection': ['code injection', 'script injection', 'injection'],
            
            # Cross-site vulnerabilities
            'xss': ['cross-site scripting', 'xss', 'cross site scripting', 'reflected xss', 'stored xss', 'dom xss'],
            'csrf': ['cross-site request forgery', 'csrf', 'request forgery', 'cross site request forgery', 'xsrf'],
            
            # Remote execution
            'rce': ['remote code execution', 'rce', 'code execution', 'remote execution', 'arbitrary code execution'],
            'lfi': ['local file inclusion', 'lfi', 'file inclusion'],
            'rfi': ['remote file inclusion', 'rfi', 'remote file inclusion'],
            
            # Access control
            'privilege_escalation': ['privilege escalation', 'escalation', 'privilege', 'vertical escalation', 'horizontal escalation'],
            'horizontal_privilege_escalation': ['horizontal privilege escalation', 'horizontal escalation'],
            'authentication_bypass': ['authentication bypass', 'auth bypass', 'bypass', 'bypass authentication'],
            'idor': ['insecure direct object reference', 'idor', 'direct object reference'],
            'broken_authentication': ['broken authentication', 'weak authentication', 'authentication failure'],
            
            # Cryptographic issues
            'weak_encryption': ['weak encryption', 'weak crypto', 'encryption', 'weak cipher', 'insecure encryption'],
            'insecure_transmission': ['insecure transmission', 'unencrypted transmission', 'plaintext transmission'],
            'data_exposure': ['data exposure', 'sensitive data exposure', 'information disclosure', 'data leak'],
            'weak_crypto_algorithms': ['weak crypto algorithms', 'deprecated crypto', 'outdated encryption'],
            
            # Configuration issues
            'security_misconfiguration': ['security misconfiguration', 'misconfiguration', 'insecure configuration'],
            'default_credentials': ['default credentials', 'default password', 'default login', 'default'],
            'path_traversal': ['path traversal', 'directory traversal', 'traversal'],
            'information_disclosure': ['information disclosure', 'information leak', 'data leak'],
            
            # Network security
            'ssrf': ['server-side request forgery', 'ssrf', 'request forgery'],
            'xxe': ['xml external entity', 'xxe', 'xml external'],
            'open_redirect': ['open redirect', 'redirect vulnerability'],
            'clickjacking': ['clickjacking', 'ui redressing'],
            
            # Session management
            'session_fixation': ['session fixation', 'session vulnerability'],
            'session_hijacking': ['session hijacking', 'session theft'],
            
            # Input validation
            'buffer_overflow': ['buffer overflow', 'overflow', 'buffer', 'stack overflow', 'heap overflow'],
            'integer_overflow': ['integer overflow', 'integer underflow'],
            'format_string': ['format string', 'format string vulnerability'],
            
            # Denial of service
            'dos': ['denial of service', 'dos', 'ddos', 'resource exhaustion'],
            
            # Business logic
            'business_logic': ['business logic', 'logic flaw', 'workflow bypass'],
            'race_condition': ['race condition', 'timing attack', 'concurrency issue'],
            
            # Deserialization
            'deserialization': ['deserialization', 'unserialize', 'deserialize'],
            'insecure_deserialization': ['insecure deserialization', 'unsafe deserialization'],
            
            # Specific vulnerabilities
            'log4j': ['log4j', 'log4shell', 'apache log4j'],
            'spring4shell': ['spring4shell', 'spring shell', 'spring framework'],
            'zeroday': ['zero day', '0-day', 'zeroday', 'zero-day'],
            
            # General security
            'access_control': ['access control', 'authorization', 'permissions'],
            'user_management': ['user management', 'account management', 'identity management'],
            'vulnerability_management': ['vulnerability management', 'patch management', 'security updates']
        }
        
        for vuln_type, patterns in type_patterns.items():
            if any(pattern in combined_text for pattern in patterns):
                types.append(vuln_type)
        
        # 3) Known CVEs catch-alls for other standards
        if cve_id.startswith('CVE-'):
            if 'known_cves' not in types:
                types.append('known_cves')
            if 'outdated_software' not in types:
                types.append('outdated_software')
            if 'unpatched_systems' not in types:
                types.append('unpatched_systems')
            if 'vulnerability_management' not in types:
                types.append('vulnerability_management')

        # 4) Severity-based types for high/critical vulnerabilities
        if severity in ['high', 'critical']:
            if 'rce' not in types and any(keyword in combined_text for keyword in ['remote code execution', 'rce', 'execution', 'execute', 'code']):
                types.append('rce')
            if 'privilege_escalation' not in types and any(keyword in combined_text for keyword in ['privilege', 'escalation', 'elevation']):
                types.append('privilege_escalation')
            if 'access_control' not in types and any(keyword in combined_text for keyword in ['access', 'authorization', 'permission']):
                types.append('access_control')
        
        # De-duplicate preserving order
        seen = set()
        deduped: List[str] = []
        for t in types:
            if t not in seen:
                seen.add(t)
                deduped.append(t)
        return deduped
    
    def _generate_recommendations(self, violations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate compliance recommendations based on violations."""
        recommendations = []
        
        # Group violations by requirement
        requirement_violations = {}
        for violation in violations:
            for req in violation['violated_requirements']:
                req_id = req['requirement_id']
                if req_id not in requirement_violations:
                    requirement_violations[req_id] = []
                requirement_violations[req_id].append(violation)
        
        # Generate recommendations for each requirement
        for req_id, req_violations in requirement_violations.items():
            requirement = self.framework.get_requirement_by_id(req_id)
            if not requirement:
                continue
            
            # Calculate priority based on violation severity
            max_severity = max(v['severity'] for v in req_violations)
            priority = self._calculate_priority(max_severity, len(req_violations))
            
            recommendation = {
                'requirement_id': req_id,
                'title': requirement['title'],
                'description': requirement['description'],
                'priority': priority,
                'violation_count': len(req_violations),
                'affected_vulnerabilities': [v['vulnerability_id'] for v in req_violations],
                'recommended_actions': self._get_recommended_actions(req_id, req_violations),
                'timeline': self._get_remediation_timeline(priority),
                'effort': self._get_effort_estimate(req_id, req_violations)
            }
            
            recommendations.append(recommendation)
        
        # Sort by priority
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 4))
        
        return recommendations
    
    def _calculate_priority(self, max_severity: str, violation_count: int) -> str:
        """Calculate recommendation priority."""
        if max_severity == 'critical' or violation_count >= 5:
            return 'critical'
        elif max_severity == 'high' or violation_count >= 3:
            return 'high'
        elif max_severity == 'medium' or violation_count >= 2:
            return 'medium'
        else:
            return 'low'
    
    def _get_recommended_actions(self, req_id: str, violations: List[Dict[str, Any]]) -> List[str]:
        """Get recommended actions for a specific requirement."""
        actions = []
        
        # Get requirement-specific actions
        requirement_actions = {
            'A01_Broken_Access_Control': [
                'Implement proper access controls and authentication',
                'Review and test authorization mechanisms',
                'Implement least privilege principle',
                'Add input validation and output encoding'
            ],
            'A02_Cryptographic_Failures': [
                'Implement strong encryption for data at rest',
                'Use secure transmission protocols (TLS 1.2+)',
                'Implement proper key management',
                'Remove or protect sensitive data'
            ],
            'A03_Injection': [
                'Implement parameterized queries',
                'Use input validation and sanitization',
                'Implement output encoding',
                'Use prepared statements'
            ],
            'Requirement_3': [
                'Encrypt stored cardholder data',
                'Implement proper key management',
                'Remove unnecessary cardholder data',
                'Implement data retention policies'
            ],
            'Requirement_4': [
                'Use strong encryption for data transmission',
                'Implement TLS 1.2 or higher',
                'Disable weak encryption protocols',
                'Implement certificate management'
            ]
        }
        
        if req_id in requirement_actions:
            actions.extend(requirement_actions[req_id])
        else:
            # Generic actions based on violation types
            vuln_types = set()
            for violation in violations:
                vuln_types.update(violation.get('vulnerability_types', []))
            
            if 'sql_injection' in vuln_types:
                actions.append('Implement parameterized queries and input validation')
            if 'xss' in vuln_types:
                actions.append('Implement output encoding and Content Security Policy')
            if 'rce' in vuln_types:
                actions.append('Implement input validation and secure coding practices')
            if 'weak_encryption' in vuln_types:
                actions.append('Upgrade to strong encryption algorithms and protocols')
            if 'default_credentials' in vuln_types:
                actions.append('Change default passwords and implement strong authentication')
        
        return actions
    
    def _get_remediation_timeline(self, priority: str) -> str:
        """Get remediation timeline based on priority."""
        timelines = {
            'critical': 'Immediate (0-24 hours)',
            'high': '1-7 days',
            'medium': '1-4 weeks',
            'low': '1-3 months'
        }
        return timelines.get(priority, '1-4 weeks')
    
    def _get_effort_estimate(self, req_id: str, violations: List[Dict[str, Any]]) -> str:
        """Get effort estimate for remediation."""
        # Simple effort estimation based on violation count and types
        vuln_count = len(violations)
        
        if vuln_count >= 10:
            return 'high'
        elif vuln_count >= 5:
            return 'medium'
        else:
            return 'low'
    
    def _determine_compliance_status(self, score: float, violations: List[Dict[str, Any]]) -> str:
        """Determine overall compliance status."""
        critical_violations = len([v for v in violations if v['severity'] == 'critical'])
        high_violations = len([v for v in violations if v['severity'] == 'high'])
        
        if critical_violations > 0 or score < 50:
            return 'non_compliant'
        elif high_violations > 2 or score < 75:
            return 'partially_compliant'
        elif score >= 90:
            return 'compliant'
        else:
            return 'partially_compliant'
    
    def generate_compliance_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate a human-readable compliance report."""
        report = f"""
# Compliance Analysis Report - {analysis_results['standard']}

## Executive Summary
- **Compliance Score**: {analysis_results['compliance_score']}/100
- **Status**: {analysis_results['status'].replace('_', ' ').title()}
- **Total Vulnerabilities**: {analysis_results['total_vulnerabilities']}
- **Analysis Time**: {analysis_results['analysis_time']}

## Violation Summary
- **Critical**: {analysis_results['critical_violations']}
- **High**: {analysis_results['high_violations']}
- **Medium**: {analysis_results['medium_violations']}
- **Low**: {analysis_results['low_violations']}

## Key Recommendations
"""
        
        for i, rec in enumerate(analysis_results['recommendations'][:5], 1):
            report += f"""
### {i}. {rec['title']}
- **Priority**: {rec['priority'].title()}
- **Timeline**: {rec['timeline']}
- **Effort**: {rec['effort'].title()}
- **Violations**: {rec['violation_count']}

**Actions Required**:
"""
            for action in rec['recommended_actions']:
                report += f"- {action}\n"
        
        return report
