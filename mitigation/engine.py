#!/usr/bin/env python3
"""
Mitigation Engine Module
Generates AI-powered mitigation recommendations for vulnerabilities.
"""

import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum


class MitigationPriority(Enum):
    """Mitigation priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MitigationTimeline(Enum):
    """Mitigation timeline categories."""
    IMMEDIATE = "immediate"  # 0-24 hours
    SHORT_TERM = "short_term"  # 1-7 days
    MEDIUM_TERM = "medium_term"  # 1-4 weeks
    LONG_TERM = "long_term"  # 1-3 months


class MitigationEffort(Enum):
    """Mitigation effort levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class MitigationEngine:
    """
    AI-powered mitigation recommendation engine.
    Generates detailed, actionable mitigation steps for vulnerabilities.
    """
    
    def __init__(self, ai_service=None):
        """
        Initialize mitigation engine.
        
        Args:
            ai_service: AI service instance for generating recommendations
        """
        self.ai_service = ai_service
        self.mitigation_templates = self._load_mitigation_templates()
    
    def generate_mitigation_plan(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive mitigation plan for scan results.
        
        Args:
            scan_results: Scan results from Scanner.scan_host()
            
        Returns:
            Dict: Complete mitigation plan
        """
        if not scan_results or not scan_results.get('vulnerabilities'):
            return {
                'mitigation_plan': [],
                'summary': {
                    'total_recommendations': 0,
                    'critical_actions': 0,
                    'estimated_timeline': 'N/A',
                    'overall_effort': 'N/A'
                },
                'generated_time': datetime.now().isoformat()
            }
        
        vulnerabilities = scan_results.get('vulnerabilities', [])
        mitigation_plan = []
        
        # Group vulnerabilities by severity for prioritization
        severity_groups = self._group_vulnerabilities_by_severity(vulnerabilities)
        
        # Generate recommendations for each severity group
        for severity, vulns in severity_groups.items():
            for vuln in vulns:
                recommendation = self._generate_vulnerability_mitigation(vuln)
                if recommendation:
                    mitigation_plan.append(recommendation)
        
        # Sort by priority and timeline
        mitigation_plan = self._prioritize_recommendations(mitigation_plan)
        
        # Generate summary
        summary = self._generate_mitigation_summary(mitigation_plan)
        
        return {
            'mitigation_plan': mitigation_plan,
            'summary': summary,
            'generated_time': datetime.now().isoformat()
        }
    
    def _group_vulnerabilities_by_severity(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group vulnerabilities by severity level."""
        groups = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'unknown': []
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            if severity in groups:
                groups[severity].append(vuln)
            else:
                groups['unknown'].append(vuln)
        
        return groups
    
    def _generate_vulnerability_mitigation(self, vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate mitigation recommendation for a specific vulnerability."""
        cve_id = vulnerability.get('cve_id', 'Unknown')
        severity = vulnerability.get('severity', 'unknown').lower()
        score = vulnerability.get('score', 0) or 0
        
        # Determine priority based on severity and score
        priority = self._determine_priority(severity, score)
        
        # Get mitigation template based on vulnerability type
        vuln_type = self._identify_vulnerability_type(vulnerability)
        template = self._get_mitigation_template(vuln_type)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(vulnerability, template, priority)
        
        if not recommendations:
            return None
        
        return {
            'vulnerability_id': cve_id,
            'title': f"Mitigation for {cve_id}",
            'description': vulnerability.get('description', ''),
            'severity': severity,
            'score': score,
            'vulnerability_type': vuln_type,
            'priority': priority.value,
            'host_ip': vulnerability.get('host_ip', ''),
            'port': vulnerability.get('port', ''),
            'recommendations': recommendations,
            'estimated_timeline': self._estimate_timeline(priority),
            'estimated_effort': self._estimate_effort(vuln_type, severity),
            'verification_steps': self._generate_verification_steps(vuln_type),
            'resources': self._get_resources(vuln_type),
            'created_time': datetime.now().isoformat()
        }
    
    def _determine_priority(self, severity: str, score: float) -> MitigationPriority:
        """Determine mitigation priority based on severity and score."""
        if severity == 'critical' or score >= 9.0:
            return MitigationPriority.CRITICAL
        elif severity == 'high' or score >= 7.0:
            return MitigationPriority.HIGH
        elif severity == 'medium' or score >= 4.0:
            return MitigationPriority.MEDIUM
        else:
            return MitigationPriority.LOW
    
    def _identify_vulnerability_type(self, vulnerability: Dict[str, Any]) -> str:
        """Identify the type of vulnerability for template selection."""
        description = vulnerability.get('description', '').lower()
        cve_id = vulnerability.get('cve_id', '').lower()
        
        # Vulnerability type patterns
        type_patterns = {
            'sql_injection': ['sql injection', 'sqli', 'sql-injection'],
            'xss': ['cross-site scripting', 'xss', 'cross site scripting'],
            'rce': ['remote code execution', 'rce', 'code execution'],
            'privilege_escalation': ['privilege escalation', 'escalation'],
            'authentication_bypass': ['authentication bypass', 'auth bypass'],
            'weak_encryption': ['weak encryption', 'weak crypto', 'encryption'],
            'default_credentials': ['default credentials', 'default password'],
            'ssrf': ['server-side request forgery', 'ssrf'],
            'xxe': ['xml external entity', 'xxe'],
            'csrf': ['cross-site request forgery', 'csrf'],
            'buffer_overflow': ['buffer overflow', 'overflow'],
            'path_traversal': ['path traversal', 'directory traversal'],
            'command_injection': ['command injection', 'cmd injection'],
            'deserialization': ['deserialization', 'unserialize'],
            'log4j': ['log4j', 'log4shell', 'apache log4j'],
            'spring4shell': ['spring4shell', 'spring shell'],
            'ssl_tls': ['ssl', 'tls', 'certificate'],
            'denial_of_service': ['denial of service', 'dos'],
            'information_disclosure': ['information disclosure', 'information leak']
        }
        
        for vuln_type, patterns in type_patterns.items():
            if any(pattern in description or pattern in cve_id for pattern in patterns):
                return vuln_type
        
        return 'generic'
    
    def _get_mitigation_template(self, vuln_type: str) -> Dict[str, Any]:
        """Get mitigation template for vulnerability type."""
        return self.mitigation_templates.get(vuln_type, self.mitigation_templates['generic'])
    
    def _generate_recommendations(self, vulnerability: Dict[str, Any], 
                                 template: Dict[str, Any], 
                                 priority: MitigationPriority) -> List[Dict[str, Any]]:
        """Generate specific recommendations based on template and vulnerability."""
        recommendations = []
        
        # Immediate actions
        immediate_actions = template.get('immediate_actions', [])
        for action in immediate_actions:
            recommendations.append({
                'timeline': MitigationTimeline.IMMEDIATE.value,
                'action': action['action'],
                'description': action['description'],
                'estimated_time': action.get('estimated_time', '1-4 hours'),
                'difficulty': action.get('difficulty', 'medium'),
                'tools_needed': action.get('tools_needed', []),
                'verification': action.get('verification', 'Manual verification required')
            })
        
        # Short-term fixes
        short_term_fixes = template.get('short_term_fixes', [])
        for fix in short_term_fixes:
            recommendations.append({
                'timeline': MitigationTimeline.SHORT_TERM.value,
                'action': fix['action'],
                'description': fix['description'],
                'estimated_time': fix.get('estimated_time', '1-3 days'),
                'difficulty': fix.get('difficulty', 'medium'),
                'tools_needed': fix.get('tools_needed', []),
                'verification': fix.get('verification', 'Testing and validation required')
            })
        
        # Medium-term improvements
        medium_term_improvements = template.get('medium_term_improvements', [])
        for improvement in medium_term_improvements:
            recommendations.append({
                'timeline': MitigationTimeline.MEDIUM_TERM.value,
                'action': improvement['action'],
                'description': improvement['description'],
                'estimated_time': improvement.get('estimated_time', '1-2 weeks'),
                'difficulty': improvement.get('difficulty', 'medium'),
                'tools_needed': improvement.get('tools_needed', []),
                'verification': improvement.get('verification', 'Comprehensive testing required')
            })
        
        # Long-term improvements
        long_term_improvements = template.get('long_term_improvements', [])
        for improvement in long_term_improvements:
            recommendations.append({
                'timeline': MitigationTimeline.LONG_TERM.value,
                'action': improvement['action'],
                'description': improvement['description'],
                'estimated_time': improvement.get('estimated_time', '1-3 months'),
                'difficulty': improvement.get('difficulty', 'high'),
                'tools_needed': improvement.get('tools_needed', []),
                'verification': improvement.get('verification', 'Full security assessment required')
            })
        
        return recommendations
    
    def _estimate_timeline(self, priority: MitigationPriority) -> str:
        """Estimate overall timeline for mitigation."""
        timelines = {
            MitigationPriority.CRITICAL: "0-24 hours",
            MitigationPriority.HIGH: "1-7 days",
            MitigationPriority.MEDIUM: "1-4 weeks",
            MitigationPriority.LOW: "1-3 months"
        }
        return timelines.get(priority, "1-4 weeks")
    
    def _estimate_effort(self, vuln_type: str, severity: str) -> MitigationEffort:
        """Estimate effort required for mitigation."""
        # High effort for complex vulnerabilities
        high_effort_types = ['rce', 'privilege_escalation', 'deserialization', 'log4j', 'spring4shell']
        if vuln_type in high_effort_types or severity == 'critical':
            return MitigationEffort.HIGH
        
        # Medium effort for common vulnerabilities
        medium_effort_types = ['sql_injection', 'xss', 'authentication_bypass', 'ssrf', 'xxe']
        if vuln_type in medium_effort_types or severity in ['high', 'medium']:
            return MitigationEffort.MEDIUM
        
        return MitigationEffort.LOW
    
    def _generate_verification_steps(self, vuln_type: str) -> List[str]:
        """Generate verification steps for vulnerability type."""
        verification_templates = {
            'sql_injection': [
                "Test all input fields with SQL injection payloads",
                "Verify parameterized queries are implemented",
                "Check for proper input validation",
                "Review database access logs"
            ],
            'xss': [
                "Test all input fields with XSS payloads",
                "Verify output encoding is implemented",
                "Check Content Security Policy headers",
                "Test in multiple browsers"
            ],
            'rce': [
                "Verify input validation is implemented",
                "Test with command injection payloads",
                "Check for secure coding practices",
                "Review system logs for suspicious activity"
            ],
            'weak_encryption': [
                "Verify strong encryption algorithms are used",
                "Check certificate validity and strength",
                "Test encryption key management",
                "Review cryptographic implementations"
            ],
            'default_credentials': [
                "Verify all default passwords are changed",
                "Check for hardcoded credentials",
                "Test authentication mechanisms",
                "Review password policies"
            ]
        }
        
        return verification_templates.get(vuln_type, [
            "Verify the vulnerability is patched",
            "Test the affected system/application",
            "Review security controls",
            "Monitor for similar issues"
        ])
    
    def _get_resources(self, vuln_type: str) -> Dict[str, List[str]]:
        """Get helpful resources for vulnerability type."""
        resource_templates = {
            'sql_injection': {
                'documentation': [
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                ],
                'tools': ["SQLMap", "Burp Suite", "OWASP ZAP"],
                'training': ["OWASP Top 10", "Secure Coding Practices"]
            },
            'xss': {
                'documentation': [
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                ],
                'tools': ["XSSer", "Burp Suite", "OWASP ZAP"],
                'training': ["Web Application Security", "Frontend Security"]
            },
            'rce': {
                'documentation': [
                    "https://owasp.org/www-community/attacks/Code_Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html"
                ],
                'tools': ["Metasploit", "Burp Suite", "Custom Scripts"],
                'training': ["Secure Coding", "Input Validation"]
            }
        }
        
        return resource_templates.get(vuln_type, {
            'documentation': ["OWASP Top 10", "CVE Database"],
            'tools': ["Vulnerability Scanners", "Security Testing Tools"],
            'training': ["General Security Awareness", "Vulnerability Management"]
        })
    
    def _prioritize_recommendations(self, recommendations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort recommendations by priority and timeline."""
        priority_order = {
            MitigationPriority.CRITICAL.value: 0,
            MitigationPriority.HIGH.value: 1,
            MitigationPriority.MEDIUM.value: 2,
            MitigationPriority.LOW.value: 3
        }
        
        timeline_order = {
            MitigationTimeline.IMMEDIATE.value: 0,
            MitigationTimeline.SHORT_TERM.value: 1,
            MitigationTimeline.MEDIUM_TERM.value: 2,
            MitigationTimeline.LONG_TERM.value: 3
        }
        
        def sort_key(rec):
            priority_score = priority_order.get(rec['priority'], 4)
            timeline_score = timeline_order.get(rec['recommendations'][0]['timeline'], 4) if rec['recommendations'] else 4
            return (priority_score, timeline_score)
        
        return sorted(recommendations, key=sort_key)
    
    def _generate_mitigation_summary(self, recommendations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of mitigation plan."""
        if not recommendations:
            return {
                'total_recommendations': 0,
                'critical_actions': 0,
                'estimated_timeline': 'N/A',
                'overall_effort': 'N/A'
            }
        
        total_recommendations = len(recommendations)
        critical_actions = len([r for r in recommendations if r['priority'] == MitigationPriority.CRITICAL.value])
        
        # Calculate estimated timeline
        priorities = [r['priority'] for r in recommendations]
        if MitigationPriority.CRITICAL.value in priorities:
            estimated_timeline = "0-24 hours"
        elif MitigationPriority.HIGH.value in priorities:
            estimated_timeline = "1-7 days"
        elif MitigationPriority.MEDIUM.value in priorities:
            estimated_timeline = "1-4 weeks"
        else:
            estimated_timeline = "1-3 months"
        
        # Calculate overall effort
        efforts = [r['estimated_effort'] for r in recommendations]
        if MitigationEffort.HIGH.value in efforts:
            overall_effort = MitigationEffort.HIGH.value
        elif MitigationEffort.MEDIUM.value in efforts:
            overall_effort = MitigationEffort.MEDIUM.value
        else:
            overall_effort = MitigationEffort.LOW.value
        
        return {
            'total_recommendations': total_recommendations,
            'critical_actions': critical_actions,
            'high_actions': len([r for r in recommendations if r['priority'] == MitigationPriority.HIGH.value]),
            'medium_actions': len([r for r in recommendations if r['priority'] == MitigationPriority.MEDIUM.value]),
            'low_actions': len([r for r in recommendations if r['priority'] == MitigationPriority.LOW.value]),
            'estimated_timeline': estimated_timeline,
            'overall_effort': overall_effort
        }
    
    def _load_mitigation_templates(self) -> Dict[str, Any]:
        """Load mitigation templates for different vulnerability types."""
        return {
            'sql_injection': {
                'immediate_actions': [
                    {
                        'action': 'Block malicious SQL injection attempts',
                        'description': 'Implement immediate blocking of known SQL injection patterns',
                        'estimated_time': '1-2 hours',
                        'difficulty': 'easy',
                        'tools_needed': ['WAF', 'Firewall'],
                        'verification': 'Test with SQL injection payloads'
                    }
                ],
                'short_term_fixes': [
                    {
                        'action': 'Implement parameterized queries',
                        'description': 'Replace dynamic SQL with parameterized queries',
                        'estimated_time': '2-3 days',
                        'difficulty': 'medium',
                        'tools_needed': ['IDE', 'Database'],
                        'verification': 'Code review and testing'
                    }
                ],
                'medium_term_improvements': [
                    {
                        'action': 'Implement input validation framework',
                        'description': 'Add comprehensive input validation across the application',
                        'estimated_time': '1-2 weeks',
                        'difficulty': 'medium',
                        'tools_needed': ['Framework', 'Testing Tools'],
                        'verification': 'Penetration testing'
                    }
                ],
                'long_term_improvements': [
                    {
                        'action': 'Implement secure coding practices',
                        'description': 'Establish secure coding standards and training',
                        'estimated_time': '1-3 months',
                        'difficulty': 'high',
                        'tools_needed': ['Training', 'Code Analysis Tools'],
                        'verification': 'Security code review process'
                    }
                ]
            },
            'xss': {
                'immediate_actions': [
                    {
                        'action': 'Implement Content Security Policy (CSP)',
                        'description': 'Add CSP headers to prevent XSS attacks',
                        'estimated_time': '1-2 hours',
                        'difficulty': 'easy',
                        'tools_needed': ['Web Server Configuration'],
                        'verification': 'Test CSP implementation'
                    }
                ],
                'short_term_fixes': [
                    {
                        'action': 'Implement output encoding',
                        'description': 'Encode all user-controlled output',
                        'estimated_time': '2-3 days',
                        'difficulty': 'medium',
                        'tools_needed': ['Encoding Libraries'],
                        'verification': 'XSS testing'
                    }
                ],
                'medium_term_improvements': [
                    {
                        'action': 'Implement input validation',
                        'description': 'Add comprehensive input validation',
                        'estimated_time': '1-2 weeks',
                        'difficulty': 'medium',
                        'tools_needed': ['Validation Framework'],
                        'verification': 'Automated testing'
                    }
                ],
                'long_term_improvements': [
                    {
                        'action': 'Implement secure development lifecycle',
                        'description': 'Integrate security into development process',
                        'estimated_time': '1-3 months',
                        'difficulty': 'high',
                        'tools_needed': ['SDLC Tools', 'Training'],
                        'verification': 'Security assessment'
                    }
                ]
            },
            'rce': {
                'immediate_actions': [
                    {
                        'action': 'Isolate affected systems',
                        'description': 'Immediately isolate systems with RCE vulnerabilities',
                        'estimated_time': '30 minutes',
                        'difficulty': 'easy',
                        'tools_needed': ['Network Controls'],
                        'verification': 'Network isolation verification'
                    }
                ],
                'short_term_fixes': [
                    {
                        'action': 'Apply security patches',
                        'description': 'Apply available security patches immediately',
                        'estimated_time': '1-2 days',
                        'difficulty': 'medium',
                        'tools_needed': ['Patch Management'],
                        'verification': 'Patch verification testing'
                    }
                ],
                'medium_term_improvements': [
                    {
                        'action': 'Implement input validation',
                        'description': 'Add comprehensive input validation',
                        'estimated_time': '1-2 weeks',
                        'difficulty': 'high',
                        'tools_needed': ['Development Tools'],
                        'verification': 'Penetration testing'
                    }
                ],
                'long_term_improvements': [
                    {
                        'action': 'Implement secure architecture',
                        'description': 'Redesign with security-first architecture',
                        'estimated_time': '1-3 months',
                        'difficulty': 'high',
                        'tools_needed': ['Architecture Tools'],
                        'verification': 'Security architecture review'
                    }
                ]
            },
            'generic': {
                'immediate_actions': [
                    {
                        'action': 'Assess vulnerability impact',
                        'description': 'Evaluate the potential impact of the vulnerability',
                        'estimated_time': '1-2 hours',
                        'difficulty': 'medium',
                        'tools_needed': ['Assessment Tools'],
                        'verification': 'Impact assessment review'
                    }
                ],
                'short_term_fixes': [
                    {
                        'action': 'Apply available patches',
                        'description': 'Apply security patches if available',
                        'estimated_time': '1-3 days',
                        'difficulty': 'medium',
                        'tools_needed': ['Patch Management'],
                        'verification': 'Patch testing'
                    }
                ],
                'medium_term_improvements': [
                    {
                        'action': 'Implement compensating controls',
                        'description': 'Add security controls to mitigate the vulnerability',
                        'estimated_time': '1-2 weeks',
                        'difficulty': 'medium',
                        'tools_needed': ['Security Tools'],
                        'verification': 'Control effectiveness testing'
                    }
                ],
                'long_term_improvements': [
                    {
                        'action': 'Improve security posture',
                        'description': 'Enhance overall security posture',
                        'estimated_time': '1-3 months',
                        'difficulty': 'high',
                        'tools_needed': ['Security Framework'],
                        'verification': 'Security assessment'
                    }
                ]
            }
        }
