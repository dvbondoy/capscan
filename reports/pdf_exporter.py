#!/usr/bin/env python3
"""
PDF Exporter for CapScan
Generates professional PDF reports from scan results.
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import os

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor, black, red, orange, green, blue
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.platypus import Preformatted
    from reportlab.platypus import Image as RLImage
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class PDFExporter:
    """PDF report generator for vulnerability scan results."""
    
    def __init__(self):
        if not REPORTLAB_AVAILABLE:
            raise ImportError("reportlab is required for PDF export. Install with: pip install reportlab")
        
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom styles for the PDF report."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=HexColor('#2c3e50')
        ))
        
        # Heading styles
        self.styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            textColor=HexColor('#34495e')
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=8,
            textColor=HexColor('#7f8c8d')
        ))
        
        # Vulnerability severity styles
        self.styles.add(ParagraphStyle(
            name='CriticalVuln',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=red,
            backColor=HexColor('#ffebee')
        ))
        
        self.styles.add(ParagraphStyle(
            name='HighVuln',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=HexColor('#d32f2f'),
            backColor=HexColor('#fff3e0')
        ))
        
        self.styles.add(ParagraphStyle(
            name='MediumVuln',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=HexColor('#f57c00'),
            backColor=HexColor('#fffde7')
        ))
        
        self.styles.add(ParagraphStyle(
            name='LowVuln',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=HexColor('#388e3c'),
            backColor=HexColor('#e8f5e8')
        ))
        
        # Monospace style for preformatted text exports (avoid redefining if present)
        if 'Code' not in self.styles.byName:
            self.styles.add(ParagraphStyle(
                name='Code',
                parent=self.styles['Normal'],
                fontName='Courier',
                fontSize=9,
                leading=12
            ))
    
    def export_scan_results(self, scan_data: Dict[str, Any], output_path: str, 
                          ai_analysis: Optional[Dict[str, Any]] = None,
                          compliance_results: Optional[Dict[str, Any]] = None,
                          mitigation_plan: Optional[Dict[str, Any]] = None) -> str:
        """
        Export scan results to PDF with optional AI analysis, compliance, and mitigation data.
        
        Args:
            scan_data: Scan results dictionary
            output_path: Path to save PDF file
            ai_analysis: Optional AI analysis results
            compliance_results: Optional compliance analysis results
            mitigation_plan: Optional mitigation plan results
            
        Returns:
            str: Path to saved PDF file
        """
        if not scan_data:
            raise ValueError("No scan data provided")
        
        # Ensure output directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Create PDF document
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        story = []
        
        # Add title page
        story.extend(self._create_title_page(scan_data))
        story.append(PageBreak())
        
        # Add executive summary
        story.extend(self._create_executive_summary(scan_data))
        story.append(PageBreak())
        
        # Add vulnerability details
        story.extend(self._create_vulnerability_details(scan_data))
        story.append(PageBreak())
        
        # Add AI analysis if available
        if ai_analysis:
            story.extend(self._create_ai_analysis_section(ai_analysis))
            story.append(PageBreak())
        
        # Add compliance analysis if available
        if compliance_results:
            story.extend(self._create_compliance_analysis_section(compliance_results))
            story.append(PageBreak())
        
        # Add mitigation plan if available
        if mitigation_plan:
            story.extend(self._create_mitigation_plan_section(mitigation_plan))
            story.append(PageBreak())
        
        # Add host information
        story.extend(self._create_host_details(scan_data))
        
        # Build PDF
        doc.build(story)
        
        return output_path

    def export_preformatted_text(self, title: str, text_content: str, output_path: str) -> str:
        """
        Export a plain preformatted text report to PDF (preserves the on-screen text formatting).
        """
        # Ensure output directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(output_path, pagesize=A4)
        story = []

        # Title
        report_title = Paragraph(title or "Report", self.styles['CustomTitle'])
        story.append(report_title)
        story.append(Spacer(1, 0.2*inch))

        # Timestamp
        ts = Paragraph(datetime.now().strftime("Generated: %Y-%m-%d %H:%M:%S"), self.styles['Normal'])
        story.append(ts)
        story.append(Spacer(1, 0.2*inch))

        # Preformatted body (monospace-like rendering, preserves newlines and spacing)
        body = Preformatted(text_content or "", self.styles['Code'] if 'Code' in self.styles else self.styles['Normal'])
        story.append(body)

        doc.build(story)
        return output_path
    
    def export_ai_analysis_only(self, scan_data: Dict[str, Any], ai_analysis: Dict[str, Any], output_path: str) -> str:
        """
        Export only AI analysis results to PDF (no executive summary or vulnerability details).
        
        Args:
            scan_data: Basic scan data for title page
            ai_analysis: AI analysis results
            output_path: Path to save PDF file
            
        Returns:
            str: Path to saved PDF file
        """
        if not scan_data or not ai_analysis:
            raise ValueError("Scan data and AI analysis required")
        
        # Ensure output directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Create PDF document
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        story = []
        
        # Add title page
        story.extend(self._create_title_page(scan_data))
        story.append(PageBreak())
        
        # Add AI analysis section
        story.extend(self._create_ai_analysis_section(ai_analysis))
        
        # Build PDF
        doc.build(story)
        
        return output_path
    
    def export_compliance_analysis_only(self, scan_data: Dict[str, Any], compliance_results: Dict[str, Any], output_path: str) -> str:
        """
        Export only compliance analysis results to PDF (no executive summary or vulnerability details).
        
        Args:
            scan_data: Basic scan data for title page
            compliance_results: Compliance analysis results
            output_path: Path to save PDF file
            
        Returns:
            str: Path to saved PDF file
        """
        if not scan_data or not compliance_results:
            raise ValueError("Scan data and compliance results required")
        
        # Ensure output directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Create PDF document
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        story = []
        
        # Add title page
        story.extend(self._create_title_page(scan_data))
        story.append(PageBreak())
        
        # Add compliance analysis section
        story.extend(self._create_compliance_analysis_section(compliance_results))
        
        # Build PDF
        doc.build(story)
        
        return output_path
    
    def export_mitigation_plan_only(self, scan_data: Dict[str, Any], mitigation_plan: Dict[str, Any], output_path: str) -> str:
        """
        Export only mitigation plan results to PDF (no executive summary or vulnerability details).
        
        Args:
            scan_data: Basic scan data for title page
            mitigation_plan: Mitigation plan results
            output_path: Path to save PDF file
            
        Returns:
            str: Path to saved PDF file
        """
        if not scan_data or not mitigation_plan:
            raise ValueError("Scan data and mitigation plan required")
        
        # Ensure output directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Create PDF document
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        story = []
        
        # Add title page
        story.extend(self._create_title_page(scan_data))
        story.append(PageBreak())
        
        # Add vulnerability details section
        story.extend(self._create_vulnerability_details(scan_data))
        story.append(PageBreak())
        
        # Add mitigation plan section
        story.extend(self._create_mitigation_plan_section(mitigation_plan))
        
        # Build PDF
        doc.build(story)
        
        return output_path
    
    def _create_title_page(self, scan_data: Dict[str, Any]) -> List:
        """Create title page content."""
        elements = []
        
        # Title
        title = Paragraph("CapScan Vulnerability Assessment Report", self.styles['CustomTitle'])
        elements.append(title)
        elements.append(Spacer(1, 0.5*inch))
        
        # Scan information
        scan_info = [
            ["Target:", scan_data.get('target', 'N/A')],
            ["Scan Time:", scan_data.get('scan_time', 'N/A')],
            ["Scan Arguments:", scan_data.get('scan_args', 'N/A')],
            ["Report Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
        ]
        
        info_table = Table(scan_info, colWidths=[1.5*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(info_table)
        elements.append(Spacer(1, 0.5*inch))
        
        # Disclaimer
        disclaimer = Paragraph(
            "<i>This report contains sensitive security information. "
            "Please handle with appropriate confidentiality measures.</i>",
            self.styles['Normal']
        )
        elements.append(disclaimer)
        
        return elements
    
    def _create_executive_summary(self, scan_data: Dict[str, Any]) -> List:
        """Create executive summary section."""
        elements = []
        
        # Section title
        title = Paragraph("Executive Summary", self.styles['CustomHeading1'])
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        # Get summary statistics
        vulnerabilities = scan_data.get('vulnerabilities', [])
        hosts = scan_data.get('hosts', {})
        
        # Count vulnerabilities by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Unknown': 0}
        for vuln in vulnerabilities:
            score = vuln.get('score', 'N/A')
            if score == 'N/A' or score is None:
                severity_counts['Unknown'] += 1
            elif score >= 9.0:
                severity_counts['Critical'] += 1
            elif score >= 7.0:
                severity_counts['High'] += 1
            elif score >= 4.0:
                severity_counts['Medium'] += 1
            else:
                severity_counts['Low'] += 1
        
        # Summary table
        summary_data = [
            ["Metric", "Count"],
            ["Total Hosts Scanned", len(hosts)],
            ["Total Vulnerabilities", len(vulnerabilities)],
            ["Critical Vulnerabilities", severity_counts['Critical']],
            ["High Vulnerabilities", severity_counts['High']],
            ["Medium Vulnerabilities", severity_counts['Medium']],
            ["Low Vulnerabilities", severity_counts['Low']],
            ["Unknown Severity", severity_counts['Unknown']]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#dee2e6')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        elements.append(summary_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Risk assessment
        risk_text = self._generate_risk_assessment(severity_counts)
        risk_para = Paragraph(risk_text, self.styles['Normal'])
        elements.append(risk_para)
        
        return elements
    
    def _create_vulnerability_details(self, scan_data: Dict[str, Any]) -> List:
        """Create vulnerability details section."""
        elements = []
        
        title = Paragraph("Vulnerability Details", self.styles['CustomHeading1'])
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        if not vulnerabilities:
            no_vulns = Paragraph("No vulnerabilities found during the scan.", self.styles['Normal'])
            elements.append(no_vulns)
            return elements
        
        # Group vulnerabilities by severity
        vuln_groups = {'Critical': [], 'High': [], 'Medium': [], 'Low': [], 'Unknown': []}
        for vuln in vulnerabilities:
            score = vuln.get('score', 'N/A')
            if score == 'N/A' or score is None:
                vuln_groups['Unknown'].append(vuln)
            elif score >= 9.0:
                vuln_groups['Critical'].append(vuln)
            elif score >= 7.0:
                vuln_groups['High'].append(vuln)
            elif score >= 4.0:
                vuln_groups['Medium'].append(vuln)
            else:
                vuln_groups['Low'].append(vuln)
        
        # Process each severity group
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Unknown']:
            vulns = vuln_groups[severity]
            if not vulns:
                continue
            
            # Severity heading
            severity_title = Paragraph(f"{severity} Severity Vulnerabilities ({len(vulns)})", 
                                     self.styles['CustomHeading2'])
            elements.append(severity_title)
            elements.append(Spacer(1, 0.1*inch))
            
            # Vulnerability table
            vuln_data = [["CVE ID", "Score", "Description", "Host", "Port"]]
            
            for vuln in vulns:
                cve_id = vuln.get('cve_id', 'N/A')
                score = vuln.get('score', 'N/A')
                description = vuln.get('description', 'N/A')[:100] + "..." if len(vuln.get('description', '')) > 100 else vuln.get('description', 'N/A')
                host = vuln.get('host', 'N/A')
                port = vuln.get('port', 'N/A')
                
                vuln_data.append([cve_id, str(score), description, host, str(port)])
            
            vuln_table = Table(vuln_data, colWidths=[1*inch, 0.8*inch, 2.5*inch, 0.8*inch, 0.5*inch])
            
            # Style based on severity
            severity_colors = {
                'Critical': (red, HexColor('#ffebee')),
                'High': (HexColor('#d32f2f'), HexColor('#fff3e0')),
                'Medium': (HexColor('#f57c00'), HexColor('#fffde7')),
                'Low': (HexColor('#388e3c'), HexColor('#e8f5e8')),
                'Unknown': (HexColor('#757575'), HexColor('#f5f5f5'))
            }
            
            text_color, bg_color = severity_colors.get(severity, (black, HexColor('#ffffff')))
            
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), bg_color),
                ('TEXTCOLOR', (0, 1), (-1, -1), text_color),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#dee2e6')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [bg_color, HexColor('#ffffff')]),
            ]))
            
            elements.append(vuln_table)
            elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _create_host_details(self, scan_data: Dict[str, Any]) -> List:
        """Create host details section."""
        elements = []
        
        title = Paragraph("Host Information", self.styles['CustomHeading1'])
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        hosts = scan_data.get('hosts', {})
        if not hosts:
            no_hosts = Paragraph("No host information available.", self.styles['Normal'])
            elements.append(no_hosts)
            return elements
        
        for host_ip, host_info in hosts.items():
            # Host header
            host_title = Paragraph(f"Host: {host_ip}", self.styles['CustomHeading2'])
            elements.append(host_title)
            
            # Host details
            host_data = [
                ["Property", "Value"],
                ["Status", host_info.get('status', 'N/A')],
                ["Hostname", host_info.get('hostname', 'N/A')],
                ["OS", host_info.get('os', 'N/A')],
                ["Open Ports", str(len(host_info.get('ports', {})))],
            ]
            
            host_table = Table(host_data, colWidths=[1.5*inch, 4*inch])
            host_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8f9fa')),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#dee2e6')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            elements.append(host_table)
            elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _create_ai_analysis_section(self, ai_analysis: Dict[str, Any]) -> List:
        """Create AI analysis section."""
        elements = []
        
        title = Paragraph("AI Analysis", self.styles['CustomHeading1'])
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        if 'error' in ai_analysis:
            error_text = Paragraph(f"Analysis Error: {ai_analysis['error']}", self.styles['Normal'])
            elements.append(error_text)
            return elements
        
        # Analysis summary
        if 'summary' in ai_analysis:
            summary_text = Paragraph(f"<b>Analysis Summary:</b><br/>{ai_analysis['summary']}", self.styles['Normal'])
            elements.append(summary_text)
            elements.append(Spacer(1, 0.1*inch))
        
        # Risk assessment
        if 'risk_assessment' in ai_analysis:
            risk = ai_analysis['risk_assessment']
            
            # Format risk assessment properly
            risk_text = "<b>Risk Assessment:</b><br/>"
            
            if isinstance(risk, dict):
                # Handle structured risk assessment
                risk_text += f"Overall Risk Level: {risk.get('overall_risk_level', 'Unknown')}<br/>"
                risk_text += f"Business Impact: {risk.get('business_impact', 'N/A')}<br/>"
                risk_text += f"Exploitability: {risk.get('exploitability', 'N/A')}<br/><br/>"
                
                if 'critical_vulnerabilities' in risk and risk['critical_vulnerabilities']:
                    risk_text += "<b>Critical Vulnerabilities:</b><br/>"
                    for vuln in risk['critical_vulnerabilities'][:10]:  # Limit to first 10
                        risk_text += f"• {vuln}<br/>"
                    risk_text += "<br/>"
                
                if 'high_risk_vulnerabilities' in risk and risk['high_risk_vulnerabilities']:
                    risk_text += "<b>High Risk Vulnerabilities:</b><br/>"
                    for vuln in risk['high_risk_vulnerabilities'][:10]:  # Limit to first 10
                        risk_text += f"• {vuln}<br/>"
                    risk_text += "<br/>"
            else:
                # Handle string risk assessment
                risk_text += f"{risk}<br/>"
            
            risk_para = Paragraph(risk_text, self.styles['Normal'])
            elements.append(risk_para)
            elements.append(Spacer(1, 0.1*inch))
        
        # Recommendations
        if 'recommendations' in ai_analysis and ai_analysis['recommendations']:
            recommendations = ai_analysis['recommendations']
            # Safely handle recommendations - ensure it's a list
            if not isinstance(recommendations, list):
                recommendations = []
            
            if recommendations:
                rec_title = Paragraph("<b>AI Recommendations:</b>", self.styles['CustomHeading2'])
                elements.append(rec_title)
                
                for i, rec in enumerate(recommendations[:5], 1):
                    rec_text = f"{i}. {rec}"
                    rec_para = Paragraph(rec_text, self.styles['Normal'])
                    elements.append(rec_para)
                    elements.append(Spacer(1, 0.05*inch))
        
        return elements
    
    def _create_compliance_analysis_section(self, compliance_results: Dict[str, Any]) -> List:
        """Create compliance analysis section."""
        elements = []
        
        title = Paragraph("Compliance Analysis", self.styles['CustomHeading1'])
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        # Compliance summary table
        compliance_data = [
            ["Metric", "Value"],
            ["Compliance Score", f"{compliance_results.get('compliance_score', 'N/A')}/100"],
            ["Status", compliance_results.get('status', 'N/A').replace('_', ' ').title()],
            ["Total Vulnerabilities", str(compliance_results.get('total_vulnerabilities', 0))],
            ["Critical Violations", str(compliance_results.get('critical_violations', 0))],
            ["High Violations", str(compliance_results.get('high_violations', 0))],
            ["Medium Violations", str(compliance_results.get('medium_violations', 0))],
            ["Low Violations", str(compliance_results.get('low_violations', 0))]
        ]
        
        compliance_table = Table(compliance_data, colWidths=[2*inch, 2.5*inch])
        compliance_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#dee2e6')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        elements.append(compliance_table)
        elements.append(Spacer(1, 0.2*inch))
        
        # Recommendations
        if 'recommendations' in compliance_results and compliance_results['recommendations']:
            recommendations = compliance_results['recommendations']
            # Safely handle recommendations - ensure it's a list
            if not isinstance(recommendations, list):
                recommendations = []
            
            if recommendations:
                rec_title = Paragraph("<b>Compliance Recommendations:</b>", self.styles['CustomHeading2'])
                elements.append(rec_title)
                
                for i, rec in enumerate(recommendations[:5], 1):
                    title = rec.get('title', 'N/A')
                    priority = rec.get('priority', 'N/A')
                    timeline = rec.get('timeline', 'N/A')
                    
                    rec_text = f"{i}. {title}<br/>Priority: {priority} | Timeline: {timeline}"
                    rec_para = Paragraph(rec_text, self.styles['Normal'])
                    elements.append(rec_para)
                    elements.append(Spacer(1, 0.05*inch))
        
        return elements
    
    def _create_mitigation_plan_section(self, mitigation_plan: Dict[str, Any]) -> List:
        """Create mitigation plan section."""
        elements = []
        
        title = Paragraph("Mitigation Plan", self.styles['CustomHeading1'])
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        # Summary
        summary = mitigation_plan.get('summary', {})
        if summary:
            summary_data = [
                ["Metric", "Value"],
                ["Critical Actions", str(summary.get('critical_actions', 0))],
                ["High Actions", str(summary.get('high_actions', 0))],
                ["Medium Actions", str(summary.get('medium_actions', 0))],
                ["Low Actions", str(summary.get('low_actions', 0))],
                ["Estimated Timeline", summary.get('estimated_timeline', 'N/A')],
                ["Overall Effort", summary.get('overall_effort', 'N/A')]
            ]
            
            summary_table = Table(summary_data, colWidths=[2*inch, 2.5*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8f9fa')),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#dee2e6')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            elements.append(summary_table)
            elements.append(Spacer(1, 0.2*inch))
        
        # Mitigation recommendations
        if 'mitigation_plan' in mitigation_plan and mitigation_plan['mitigation_plan']:
            mitigation_recs = mitigation_plan['mitigation_plan']
            # Safely handle mitigation recommendations - ensure it's a list
            if not isinstance(mitigation_recs, list):
                mitigation_recs = []
            
            if mitigation_recs:
                rec_title = Paragraph("<b>Mitigation Recommendations:</b>", self.styles['CustomHeading2'])
                elements.append(rec_title)
                
                for i, rec in enumerate(mitigation_recs[:10], 1):
                    title = rec.get('title', 'N/A')
                    priority = rec.get('priority', 'N/A')
                    effort = rec.get('effort', 'N/A')
                    timeline = rec.get('timeline', 'N/A')
                    
                    rec_text = f"{i}. {title}<br/>Priority: {priority} | Effort: {effort} | Timeline: {timeline}"
                    rec_para = Paragraph(rec_text, self.styles['Normal'])
                    elements.append(rec_para)
                    elements.append(Spacer(1, 0.05*inch))
        
        # Add vulnerability-specific mitigation details if available
        if 'vulnerability_mitigations' in mitigation_plan and mitigation_plan['vulnerability_mitigations']:
            vuln_mitigations = mitigation_plan['vulnerability_mitigations']
            if isinstance(vuln_mitigations, list) and vuln_mitigations:
                vuln_title = Paragraph("<b>Vulnerability-Specific Mitigation Details:</b>", self.styles['CustomHeading2'])
                elements.append(vuln_title)
                elements.append(Spacer(1, 0.1*inch))
                
                for vuln_mit in vuln_mitigations[:5]:  # Limit to first 5 for space
                    cve_id = vuln_mit.get('cve_id', 'N/A')
                    severity = vuln_mit.get('severity', 'N/A')
                    description = vuln_mit.get('description', 'N/A')[:100] + "..." if len(vuln_mit.get('description', '')) > 100 else vuln_mit.get('description', 'N/A')
                    mitigation_steps = vuln_mit.get('mitigation_steps', [])
                    
                    vuln_text = f"<b>{cve_id}</b> ({severity})<br/>{description}<br/>"
                    if mitigation_steps:
                        vuln_text += "<b>Mitigation Steps:</b><br/>"
                        for step in mitigation_steps[:3]:  # Limit to first 3 steps
                            vuln_text += f"• {step}<br/>"
                    
                    vuln_para = Paragraph(vuln_text, self.styles['Normal'])
                    elements.append(vuln_para)
                    elements.append(Spacer(1, 0.1*inch))
        
        return elements
    
    def _generate_risk_assessment(self, severity_counts: Dict[str, int]) -> str:
        """Generate risk assessment text based on vulnerability counts."""
        total_vulns = sum(severity_counts.values())
        
        if total_vulns == 0:
            return "✅ <b>Low Risk:</b> No vulnerabilities were detected during the scan. The target appears to be secure."
        
        critical = severity_counts['Critical']
        high = severity_counts['High']
        medium = severity_counts['Medium']
        low = severity_counts['Low']
        
        if critical > 0:
            return f"🔴 <b>Critical Risk:</b> {critical} critical vulnerabilities detected. Immediate remediation required."
        elif high > 5:
            return f"🟠 <b>High Risk:</b> {high} high-severity vulnerabilities detected. Priority remediation recommended."
        elif high > 0 or medium > 10:
            return f"🟡 <b>Medium Risk:</b> {high} high and {medium} medium-severity vulnerabilities detected. Remediation recommended."
        else:
            return f"🟢 <b>Low Risk:</b> {low} low-severity vulnerabilities detected. Consider remediation for security hardening."
