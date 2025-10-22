#!/usr/bin/env python3
"""
Mitigation Engine Module
Generates AI-powered mitigation recommendations for vulnerabilities.
"""

import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum
import sys
import os

# Add the parent directory to the path to import services
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services.exploitdb_service import ExploitDBService


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
        try:
            self.exploitdb_service = ExploitDBService()
        except Exception as e:
            print(f"Warning: Could not initialize ExploitDB service: {e}")
            self.exploitdb_service = None
    
    def generate_mitigation_plan(self, scan_results: Dict[str, Any], recommendation_type: str = "ai") -> Dict[str, Any]:
        """
        Generate comprehensive mitigation plan for scan results.
        
        Args:
            scan_results: Scan results from Scanner.scan_host()
            recommendation_type: Type of recommendations to generate ("ai" or "template")
            
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
        vulnerability_mitigations = []
        for severity, vulns in severity_groups.items():
            for vuln in vulns:
                recommendation = self._generate_vulnerability_mitigation(vuln, recommendation_type)
                if recommendation:
                    mitigation_plan.append(recommendation)
                
                # Create vulnerability-specific mitigation details
                vuln_mitigation = self._create_vulnerability_mitigation_detail(vuln, recommendation)
                if vuln_mitigation:
                    vulnerability_mitigations.append(vuln_mitigation)
        
        # Sort by priority and timeline
        mitigation_plan = self._prioritize_recommendations(mitigation_plan)
        
        # Generate summary
        summary = self._generate_mitigation_summary(mitigation_plan)
        
        return {
            'mitigation_plan': mitigation_plan,
            'summary': summary,
            'vulnerability_mitigations': vulnerability_mitigations,
            'ai_enhanced': self.ai_service is not None,
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
    
    def _generate_vulnerability_mitigation(self, vulnerability: Dict[str, Any], recommendation_type: str = "ai") -> Optional[Dict[str, Any]]:
        """Generate mitigation recommendation for a specific vulnerability with enhanced context."""
        cve_id = vulnerability.get('cve_id', 'Unknown')
        severity = vulnerability.get('severity', 'unknown').lower()
        score = vulnerability.get('score', 0) or 0
        
        # Determine priority based on severity and score
        priority = self._determine_priority(severity, score)
        
        # Get enhanced vulnerability type using enriched data
        vuln_type = self._identify_enhanced_vulnerability_type(vulnerability)
        template = self._get_mitigation_template(vuln_type)
        
        # Get ExploitDB information for this CVE
        exploit_info = self._get_exploit_information(cve_id)
        
        # Generate recommendations based on selected type
        if recommendation_type == "ai":
            recommendations = self._generate_ai_enhanced_recommendations(vulnerability, template, priority, exploit_info)
        else:  # template
            recommendations = self._generate_enhanced_recommendations(vulnerability, template, priority, exploit_info)
        
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
            'service_name': vulnerability.get('service_name', ''),
            'product': vulnerability.get('product', ''),
            'version': vulnerability.get('version', ''),
            'attack_vector': vulnerability.get('attack_vector', 'Unknown'),
            'complexity': vulnerability.get('complexity', 'Unknown'),
            'privileges_required': vulnerability.get('privileges_required', 'Unknown'),
            'user_interaction': vulnerability.get('user_interaction', 'Unknown'),
            'confidentiality_impact': vulnerability.get('confidentiality_impact', 'Unknown'),
            'integrity_impact': vulnerability.get('integrity_impact', 'Unknown'),
            'availability_impact': vulnerability.get('availability_impact', 'Unknown'),
            'cvss_vector': vulnerability.get('cvss_vector', ''),
            'references': vulnerability.get('references', []),
            'exploit_info': exploit_info,
            'recommendations': recommendations,
            'estimated_timeline': self._estimate_timeline(priority),
            'estimated_effort': self._estimate_effort(vuln_type, severity),
            'verification_steps': self._generate_enhanced_verification_steps(vuln_type, vulnerability, exploit_info),
            'resources': self._get_enhanced_resources(vuln_type, vulnerability, exploit_info),
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
    
    def _generate_ai_enhanced_recommendations(self, vulnerability: Dict[str, Any], 
                                           template: Dict[str, Any], 
                                           priority: MitigationPriority,
                                           exploit_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate AI-enhanced recommendations with fallback to template-based approach."""
        recommendations = []
        
        # Try AI service first if available
        if self.ai_service and hasattr(self.ai_service, 'generate_mitigation_recommendations'):
            try:
                ai_result = self.ai_service.generate_mitigation_recommendations(vulnerability)
                if ai_result and not ai_result.get('error'):
                    # Process AI recommendations
                    ai_recommendations = self._process_ai_recommendations(ai_result, vulnerability, priority, exploit_info)
                    if ai_recommendations:
                        return ai_recommendations
            except Exception as e:
                print(f"AI service error: {e}, falling back to template-based recommendations")
        
        # Fallback to template-based recommendations
        return self._generate_enhanced_recommendations(vulnerability, template, priority, exploit_info)
    
    def _process_ai_recommendations(self, ai_result: Dict[str, Any], vulnerability: Dict[str, Any], 
                                  priority: MitigationPriority, exploit_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process AI-generated recommendations and convert to standard format."""
        recommendations = []
        
        # Extract immediate actions
        immediate_actions = ai_result.get('immediate_actions', [])
        for action in immediate_actions:
            rec = {
                'timeline': MitigationTimeline.IMMEDIATE.value,
                'action': action.get('action', ''),
                'description': action.get('description', ''),
                'estimated_time': action.get('estimated_time', '1-2 hours'),
                'difficulty': action.get('difficulty', 'medium'),
                'tools_needed': action.get('tools_needed', []),
                'verification': action.get('verification', 'Manual verification required'),
                'source': 'ai_generated',
                'ai_context': 'Generated by AI analysis'
            }
            recommendations.append(rec)
        
        # Extract short-term fixes
        short_term_fixes = ai_result.get('short_term_fixes', [])
        for fix in short_term_fixes:
            rec = {
                'timeline': MitigationTimeline.SHORT_TERM.value,
                'action': fix.get('action', ''),
                'description': fix.get('description', ''),
                'estimated_time': fix.get('timeline', '1-3 days'),
                'difficulty': fix.get('effort', 'medium'),
                'tools_needed': fix.get('dependencies', []),
                'verification': 'Testing and validation required',
                'source': 'ai_generated',
                'ai_context': 'Generated by AI analysis'
            }
            recommendations.append(rec)
        
        # Extract long-term improvements
        long_term_improvements = ai_result.get('long_term_improvements', [])
        for improvement in long_term_improvements:
            rec = {
                'timeline': MitigationTimeline.LONG_TERM.value,
                'action': improvement.get('action', ''),
                'description': improvement.get('description', ''),
                'estimated_time': improvement.get('timeline', '1-3 months'),
                'difficulty': improvement.get('effort', 'high'),
                'tools_needed': improvement.get('benefits', []),
                'verification': 'Comprehensive testing required',
                'source': 'ai_generated',
                'ai_context': 'Generated by AI analysis'
            }
            recommendations.append(rec)
        
        # Enhance with exploit context
        for rec in recommendations:
            if exploit_info.get('has_verified_exploits'):
                total_exploits = exploit_info.get('total_exploits', 0)
                rec['exploit_context'] = f"Verified exploits available ({total_exploits} total)"
                rec['urgency'] = 'high' if exploit_info.get('exploit_availability') == 'high' else 'medium'
            else:
                total_exploits = exploit_info.get('total_exploits', 0)
                rec['exploit_context'] = f"No verified exploits found ({total_exploits} total)"
                rec['urgency'] = 'low'
        
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
    
    def _identify_enhanced_vulnerability_type(self, vulnerability: Dict[str, Any]) -> str:
        """Enhanced vulnerability type identification using enriched data."""
        # First try the existing classification
        vuln_type = self._identify_vulnerability_type(vulnerability)
        
        # If we have ExploitDB data, use it to refine the classification
        cve_id = vulnerability.get('cve_id', '')
        if cve_id and self.exploitdb_service:
            try:
                exploits = self.exploitdb_service.get_exploits_for_cve(cve_id)
                if exploits:
                    # Get the most common attack type from exploits
                    attack_types = [exploit.get('attack_type', 'unknown') for exploit in exploits]
                    if attack_types:
                        # Count attack types
                        type_counts = {}
                        for attack_type in attack_types:
                            if attack_type != 'unknown':
                                type_counts[attack_type] = type_counts.get(attack_type, 0) + 1
                        
                        if type_counts:
                            # Get the most common attack type
                            most_common_type = max(type_counts, key=type_counts.get)
                            return most_common_type
            except Exception as e:
                print(f"Error getting exploits for {cve_id}: {e}")
        
        # Use service-specific classification if available
        product = vulnerability.get('product', '').lower()
        service_name = vulnerability.get('service_name', '').lower()
        
        if 'apache' in product or 'httpd' in product:
            if vuln_type in ['buffer_overflow', 'denial_of_service', 'information_disclosure']:
                return f'apache_{vuln_type}'
            else:
                return 'apache_vulnerability'
        elif 'nginx' in product:
            if vuln_type in ['buffer_overflow', 'denial_of_service']:
                return f'nginx_{vuln_type}'
            else:
                return 'nginx_vulnerability'
        elif 'ssh' in service_name or 'openssh' in product:
            if vuln_type in ['authentication_bypass', 'privilege_escalation']:
                return f'ssh_{vuln_type}'
            else:
                return 'ssh_vulnerability'
        elif 'mysql' in product or 'mariadb' in product:
            return 'database_vulnerability'
        elif 'ssl' in vuln_type or 'tls' in vuln_type:
            return 'ssl_tls_vulnerability'
        
        return vuln_type
    
    def _get_exploit_information(self, cve_id: str) -> Dict[str, Any]:
        """Get ExploitDB information for a CVE."""
        if not cve_id or not self.exploitdb_service:
            return {}
        
        try:
            exploits = self.exploitdb_service.get_exploits_for_cve(cve_id)
            if not exploits:
                return {}
        except Exception as e:
            print(f"Error getting exploit information for {cve_id}: {e}")
            return {}
        
        # Analyze exploits
        verified_exploits = [e for e in exploits if e.get('is_verified', False)]
        attack_types = [e.get('attack_type', 'unknown') for e in exploits]
        platforms = [e.get('platform_info', {}).get('os', 'unknown') for e in exploits]
        complexities = [e.get('complexity', 'unknown') for e in exploits]
        
        # Get most common values
        attack_type_counts = {}
        for attack_type in attack_types:
            if attack_type != 'unknown':
                attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
        
        platform_counts = {}
        for platform in platforms:
            if platform != 'unknown':
                platform_counts[platform] = platform_counts.get(platform, 0) + 1
        
        complexity_counts = {}
        for complexity in complexities:
            if complexity != 'unknown':
                complexity_counts[complexity] = complexity_counts.get(complexity, 0) + 1
        
        return {
            'total_exploits': len(exploits),
            'verified_exploits': len(verified_exploits),
            'most_common_attack_type': max(attack_type_counts, key=attack_type_counts.get) if attack_type_counts else 'unknown',
            'most_common_platform': max(platform_counts, key=platform_counts.get) if platform_counts else 'unknown',
            'most_common_complexity': max(complexity_counts, key=complexity_counts.get) if complexity_counts else 'unknown',
            'exploits': exploits[:5],  # Limit to first 5 for display
            'has_verified_exploits': len(verified_exploits) > 0,
            'exploit_availability': 'high' if len(exploits) >= 3 else 'medium' if len(exploits) >= 1 else 'low'
        }
    
    def _generate_enhanced_recommendations(self, vulnerability: Dict[str, Any], 
                                         template: Dict[str, Any], 
                                         priority: MitigationPriority,
                                         exploit_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate enhanced recommendations with exploit context."""
        recommendations = []
        
        # Get base recommendations from template
        base_recommendations = self._generate_recommendations(vulnerability, template, priority)
        
        # Enhance with exploit-specific information
        for rec in base_recommendations:
            enhanced_rec = dict(rec)
            
            # Add exploit-specific context
            if exploit_info.get('has_verified_exploits'):
                total_exploits = exploit_info.get('total_exploits', 0)
                enhanced_rec['exploit_context'] = f"Verified exploits available ({total_exploits} total)"
                enhanced_rec['urgency'] = 'high' if exploit_info.get('exploit_availability') == 'high' else 'medium'
            else:
                total_exploits = exploit_info.get('total_exploits', 0)
                enhanced_rec['exploit_context'] = f"No verified exploits found ({total_exploits} total)"
                enhanced_rec['urgency'] = 'low'
            
            # Add attack vector specific recommendations
            attack_vector = vulnerability.get('attack_vector', 'Unknown')
            if attack_vector == 'Network':
                enhanced_rec['network_considerations'] = [
                    "Implement network segmentation",
                    "Use firewall rules to restrict access",
                    "Consider VPN or private network access"
                ]
            elif attack_vector == 'Local':
                enhanced_rec['local_considerations'] = [
                    "Restrict local access permissions",
                    "Implement privilege separation",
                    "Monitor local user activities"
                ]
            
            # Add complexity-specific recommendations
            complexity = vulnerability.get('complexity', 'Unknown')
            if complexity == 'Low':
                enhanced_rec['implementation_notes'] = "Low complexity - can be implemented quickly"
            elif complexity == 'High':
                enhanced_rec['implementation_notes'] = "High complexity - requires careful planning and testing"
            
            recommendations.append(enhanced_rec)
        
        # Add exploit-specific immediate actions if exploits are available
        if exploit_info.get('has_verified_exploits'):
            total_exploits = exploit_info.get('total_exploits', 0)
            exploit_specific_rec = {
                'timeline': MitigationTimeline.IMMEDIATE.value,
                'action': 'Block known exploit patterns',
                'description': f"Block patterns from {total_exploits} known exploits",
                'estimated_time': '1-2 hours',
                'difficulty': 'easy',
                'tools_needed': ['WAF', 'Firewall', 'IDS/IPS'],
                'verification': 'Test with known exploit patterns',
                'exploit_context': 'Based on verified exploits',
                'urgency': 'high'
            }
            recommendations.insert(0, exploit_specific_rec)
        
        return recommendations
    
    def _generate_enhanced_verification_steps(self, vuln_type: str, vulnerability: Dict[str, Any], exploit_info: Dict[str, Any]) -> List[str]:
        """Generate enhanced verification steps with exploit context."""
        base_steps = self._generate_verification_steps(vuln_type)
        enhanced_steps = list(base_steps)
        
        # Add exploit-specific verification
        if exploit_info.get('has_verified_exploits'):
            total_exploits = exploit_info.get('total_exploits', 0)
            enhanced_steps.append(f"Test with {total_exploits} known exploit patterns")
            enhanced_steps.append("Verify that verified exploits no longer work")
        
        # Add service-specific verification
        product = vulnerability.get('product', '')
        version = vulnerability.get('version', '')
        if product and version:
            enhanced_steps.append(f"Verify {product} {version} is patched or updated")
            enhanced_steps.append(f"Test {product} specific functionality")
        
        # Add CVSS-specific verification
        cvss_vector = vulnerability.get('cvss_vector', '')
        if cvss_vector:
            enhanced_steps.append(f"Verify CVSS vector {cvss_vector} is addressed")
        
        return enhanced_steps
    
    def _get_enhanced_resources(self, vuln_type: str, vulnerability: Dict[str, Any], exploit_info: Dict[str, Any]) -> Dict[str, List[str]]:
        """Get enhanced resources with exploit and service-specific information."""
        base_resources = self._get_resources(vuln_type)
        enhanced_resources = dict(base_resources)
        
        # Add CVE-specific resources
        cve_id = vulnerability.get('cve_id', '')
        if cve_id:
            enhanced_resources['cve_resources'] = [
                f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
                f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                f"https://vulners.com/cve/{cve_id}"
            ]
        
        # Add exploit-specific resources
        if exploit_info.get('has_verified_exploits'):
            enhanced_resources['exploit_resources'] = [
                "https://www.exploit-db.com/",
                "Metasploit Framework",
                "Exploit Database Search"
            ]
        
        # Add service-specific resources
        product = vulnerability.get('product', '')
        if 'apache' in product.lower():
            enhanced_resources['service_resources'] = [
                "https://httpd.apache.org/security/",
                "Apache Security Advisories",
                "Apache Configuration Hardening Guide"
            ]
        elif 'nginx' in product.lower():
            enhanced_resources['service_resources'] = [
                "https://nginx.org/en/security_advisories.html",
                "Nginx Security Advisories",
                "Nginx Configuration Hardening Guide"
            ]
        elif 'ssh' in vulnerability.get('service_name', '').lower():
            enhanced_resources['service_resources'] = [
                "OpenSSH Security Advisories",
                "SSH Configuration Hardening Guide",
                "SSH Key Management Best Practices"
            ]
        
        return enhanced_resources
    
    def _create_vulnerability_mitigation_detail(self, vulnerability: Dict[str, Any], recommendation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create detailed vulnerability-specific mitigation information.
        
        Args:
            vulnerability: Vulnerability data
            recommendation: Generated mitigation recommendation
            
        Returns:
            Dict: Detailed vulnerability mitigation information
        """
        if not vulnerability or not recommendation:
            return None
        
        # Extract key vulnerability information
        cve_id = vulnerability.get('cve_id', 'Unknown')
        severity = vulnerability.get('severity', 'unknown')
        description = vulnerability.get('description', 'No description available')
        host = vulnerability.get('host', 'Unknown')
        port = vulnerability.get('port', 'Unknown')
        service = vulnerability.get('service_name', 'Unknown')
        
        # Extract mitigation steps from recommendation
        mitigation_steps = []
        if 'steps' in recommendation:
            mitigation_steps = recommendation['steps'][:5]  # Limit to first 5 steps
        elif 'description' in recommendation:
            # If no specific steps, use the description as a single step
            mitigation_steps = [recommendation['description']]
        
        # Create detailed mitigation information
        vuln_mitigation = {
            'cve_id': cve_id,
            'severity': severity,
            'description': description,
            'host': host,
            'port': port,
            'service': service,
            'mitigation_steps': mitigation_steps,
            'priority': recommendation.get('priority', 'medium'),
            'effort': recommendation.get('effort', 'medium'),
            'timeline': recommendation.get('timeline', 'N/A'),
            'title': recommendation.get('title', f'Mitigate {cve_id}')
        }
        
        return vuln_mitigation
