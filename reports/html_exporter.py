#!/usr/bin/env python3
"""
HTML Exporter for CapScan
Generates interactive HTML reports from scan results.
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import json
import os

try:
    from jinja2 import Environment, FileSystemLoader, Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.utils import PlotlyJSONEncoder
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False


class HTMLExporter:
    """HTML report generator for vulnerability scan results."""
    
    def __init__(self):
        if not JINJA2_AVAILABLE:
            raise ImportError("jinja2 is required for HTML export. Install with: pip install jinja2")
        
        # Setup Jinja2 environment
        self.env = Environment(
            loader=FileSystemLoader(Path(__file__).parent / 'templates'),
            autoescape=True
        )
        
        # Create templates directory if it doesn't exist
        templates_dir = Path(__file__).parent / 'templates'
        templates_dir.mkdir(exist_ok=True)
        
        # Create default template if it doesn't exist
        self._create_default_template()
    
    def _create_default_template(self):
        """Create default HTML template if it doesn't exist."""
        template_path = Path(__file__).parent / 'templates' / 'scan_report.html'
        
        if not template_path.exists():
            template_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CapScan Vulnerability Report</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .content {
            padding: 30px;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #3498db;
        }
        .summary-card.critical { border-left-color: #e74c3c; }
        .summary-card.high { border-left-color: #f39c12; }
        .summary-card.medium { border-left-color: #f1c40f; }
        .summary-card.low { border-left-color: #27ae60; }
        .summary-card h3 {
            margin: 0 0 10px 0;
            font-size: 2em;
            color: #2c3e50;
        }
        .summary-card p {
            margin: 0;
            color: #7f8c8d;
            font-weight: 500;
        }
        .vulnerability-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .vulnerability-table th,
        .vulnerability-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .vulnerability-table th {
            background-color: #34495e;
            color: white;
            font-weight: 600;
        }
        .vulnerability-table tr:hover {
            background-color: #f5f5f5;
        }
        .severity-critical { color: #e74c3c; font-weight: bold; }
        .severity-high { color: #f39c12; font-weight: bold; }
        .severity-medium { color: #f1c40f; font-weight: bold; }
        .severity-low { color: #27ae60; font-weight: bold; }
        .severity-unknown { color: #95a5a6; font-weight: bold; }
        .chart-container {
            margin: 20px 0;
        }
        .host-info {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .host-info h3 {
            margin-top: 0;
            color: #2c3e50;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        .info-item {
            background: white;
            padding: 15px;
            border-radius: 5px;
            border-left: 3px solid #3498db;
        }
        .info-item strong {
            color: #2c3e50;
        }
        .footer {
            background: #34495e;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }
        .risk-assessment {
            background: #e8f5e8;
            border: 1px solid #27ae60;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        .risk-assessment.high {
            background: #ffeaa7;
            border-color: #f39c12;
        }
        .risk-assessment.critical {
            background: #fab1a0;
            border-color: #e74c3c;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CapScan Vulnerability Assessment Report</h1>
            <p>Generated on {{ report_date }}</p>
        </div>
        
        <div class="content">
            <!-- Executive Summary -->
            <div class="section">
                <h2>Executive Summary</h2>
                
                <div class="summary-grid">
                    <div class="summary-card">
                        <h3>{{ total_hosts }}</h3>
                        <p>Hosts Scanned</p>
                    </div>
                    <div class="summary-card">
                        <h3>{{ total_vulnerabilities }}</h3>
                        <p>Total Vulnerabilities</p>
                    </div>
                    <div class="summary-card critical">
                        <h3>{{ severity_counts.Critical }}</h3>
                        <p>Critical</p>
                    </div>
                    <div class="summary-card high">
                        <h3>{{ severity_counts.High }}</h3>
                        <p>High</p>
                    </div>
                    <div class="summary-card medium">
                        <h3>{{ severity_counts.Medium }}</h3>
                        <p>Medium</p>
                    </div>
                    <div class="summary-card low">
                        <h3>{{ severity_counts.Low }}</h3>
                        <p>Low</p>
                    </div>
                </div>
                
                <div class="risk-assessment {{ risk_level }}">
                    <h3>Risk Assessment</h3>
                    <p>{{ risk_assessment }}</p>
                </div>
                
                {% if charts.severity_chart %}
                <div class="chart-container">
                    <div id="severityChart"></div>
                </div>
                {% endif %}
            </div>
            
            <!-- Vulnerability Details -->
            <div class="section">
                <h2>Vulnerability Details</h2>
                
                {% if vulnerabilities %}
                <table class="vulnerability-table">
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>Severity</th>
                            <th>Score</th>
                            <th>Description</th>
                            <th>Host</th>
                            <th>Port</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for vuln in vulnerabilities %}
                        <tr>
                            <td><strong>{{ vuln.cve_id }}</strong></td>
                            <td><span class="severity-{{ vuln.severity.lower() }}">{{ vuln.severity }}</span></td>
                            <td>{{ vuln.score }}</td>
                            <td>{{ vuln.description[:100] }}{% if vuln.description|length > 100 %}...{% endif %}</td>
                            <td>{{ vuln.host }}</td>
                            <td>{{ vuln.port }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p>No vulnerabilities found during the scan.</p>
                {% endif %}
            </div>
            
            <!-- Host Information -->
            <div class="section">
                <h2>Host Information</h2>
                {% for host_ip, host_info in hosts.items() %}
                <div class="host-info">
                    <h3>{{ host_ip }}</h3>
                    <div class="info-grid">
                        <div class="info-item">
                            <strong>Status:</strong> {{ host_info.status }}
                        </div>
                        <div class="info-item">
                            <strong>Hostname:</strong> {{ host_info.hostname or 'N/A' }}
                        </div>
                        <div class="info-item">
                            <strong>OS:</strong> {{ host_info.os or 'N/A' }}
                        </div>
                        <div class="info-item">
                            <strong>Open Ports:</strong> {{ host_info.ports|length }}
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
        
        <div class="footer">
            <p>Report generated by CapScan Vulnerability Scanner | {{ report_date }}</p>
        </div>
    </div>
    
    {% if charts.severity_chart %}
    <script>
        var severityData = {{ charts.severity_chart|safe }};
        Plotly.newPlot('severityChart', severityData.data, severityData.layout);
    </script>
    {% endif %}
</body>
</html>'''
            
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write(template_content)
    
    def export_scan_results(self, scan_data: Dict[str, Any], output_path: str,
                          ai_analysis: Optional[Dict[str, Any]] = None,
                          compliance_results: Optional[Dict[str, Any]] = None,
                          mitigation_plan: Optional[Dict[str, Any]] = None) -> str:
        """
        Export scan results to HTML with optional AI analysis, compliance, and mitigation data.
        
        Args:
            scan_data: Scan results dictionary
            output_path: Path to save HTML file
            ai_analysis: Optional AI analysis results
            compliance_results: Optional compliance analysis results
            mitigation_plan: Optional mitigation plan results
            
        Returns:
            str: Path to saved HTML file
        """
        if not scan_data:
            raise ValueError("No scan data provided")
        
        # Ensure output directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # Process scan data for template
            template_data = self._process_scan_data(scan_data, ai_analysis, compliance_results, mitigation_plan)
            
            # Load template
            template = self.env.get_template('scan_report.html')
            
            # Render HTML
            html_content = template.render(**template_data)
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return output_path
            
        except Exception as e:
            # Provide more detailed error information
            error_msg = f"HTML export failed: {str(e)}"
            if hasattr(e, '__traceback__'):
                import traceback
                error_msg += f"\nTraceback: {traceback.format_exc()}"
            raise Exception(error_msg)

    def export_preformatted_text(self, title: str, text_content: str, output_path: str) -> str:
        """Export preformatted text (exact GUI text) to a simple HTML file."""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        safe_title = (title or "Report")
        safe_body = (text_content or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        html = f"""
<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{safe_title}</title>
  <style>
    body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }}
    h1 {{ color: #2c3e50; }}
    pre {{ background: #f8f9fa; padding: 16px; border: 1px solid #e1e5ea; border-radius: 6px; white-space: pre-wrap; word-wrap: break-word; }}
  </style>
  </head>
<body>
  <h1>{safe_title}</h1>
  <div>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
  <pre>{safe_body}</pre>
</body>
</html>
"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        return output_path
    
    def _process_scan_data(self, scan_data: Dict[str, Any], 
                          ai_analysis: Optional[Dict[str, Any]] = None,
                          compliance_results: Optional[Dict[str, Any]] = None,
                          mitigation_plan: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Process scan data for template rendering."""
        vulnerabilities = scan_data.get('vulnerabilities', [])
        hosts = scan_data.get('hosts', {})
        
        # Count vulnerabilities by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Unknown': 0}
        
        processed_vulns = []
        for vuln in vulnerabilities:
            score = vuln.get('score', 'N/A')
            if score == 'N/A' or score is None:
                severity = 'Unknown'
            elif score >= 9.0:
                severity = 'Critical'
            elif score >= 7.0:
                severity = 'High'
            elif score >= 4.0:
                severity = 'Medium'
            else:
                severity = 'Low'
            
            severity_counts[severity] += 1
            
            processed_vulns.append({
                'cve_id': vuln.get('cve_id', 'N/A'),
                'score': score,
                'description': vuln.get('description', 'N/A'),
                'host': vuln.get('host', 'N/A'),
                'port': vuln.get('port', 'N/A'),
                'severity': severity
            })
        
        # Generate risk assessment
        risk_assessment, risk_level = self._generate_risk_assessment(severity_counts)
        
        # Generate charts if plotly is available
        charts = {}
        if PLOTLY_AVAILABLE:
            charts['severity_chart'] = self._create_severity_chart(severity_counts)
        
        # Process additional data
        processed_ai_analysis = self._process_ai_analysis(ai_analysis) if ai_analysis else None
        processed_compliance = self._process_compliance_results(compliance_results) if compliance_results else None
        processed_mitigation = self._process_mitigation_plan(mitigation_plan) if mitigation_plan else None
        
        return {
            'report_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'target': scan_data.get('target', 'N/A'),
            'scan_time': scan_data.get('scan_time', 'N/A'),
            'total_hosts': len(hosts),
            'total_vulnerabilities': len(vulnerabilities),
            'severity_counts': severity_counts,
            'vulnerabilities': processed_vulns,
            'hosts': hosts,
            'risk_assessment': risk_assessment,
            'risk_level': risk_level,
            'charts': charts,
            'ai_analysis': processed_ai_analysis,
            'compliance_results': processed_compliance,
            'mitigation_plan': processed_mitigation
        }
    
    def _generate_risk_assessment(self, severity_counts: Dict[str, int]) -> tuple:
        """Generate risk assessment text and level."""
        total_vulns = sum(severity_counts.values())
        
        if total_vulns == 0:
            return ("✅ Low Risk: No vulnerabilities were detected during the scan. The target appears to be secure.", "low")
        
        critical = severity_counts['Critical']
        high = severity_counts['High']
        medium = severity_counts['Medium']
        low = severity_counts['Low']
        
        if critical > 0:
            return (f"🔴 Critical Risk: {critical} critical vulnerabilities detected. Immediate remediation required.", "critical")
        elif high > 5:
            return (f"🟠 High Risk: {high} high-severity vulnerabilities detected. Priority remediation recommended.", "high")
        elif high > 0 or medium > 10:
            return (f"🟡 Medium Risk: {high} high and {medium} medium-severity vulnerabilities detected. Remediation recommended.", "medium")
        else:
            return (f"🟢 Low Risk: {low} low-severity vulnerabilities detected. Consider remediation for security hardening.", "low")
    
    def _create_severity_chart(self, severity_counts: Dict[str, int]) -> str:
        """Create severity distribution chart using Plotly."""
        if not PLOTLY_AVAILABLE:
            return None
        
        # Filter out zero counts
        filtered_counts = {k: v for k, v in severity_counts.items() if v > 0}
        
        if not filtered_counts:
            return None
        
        # Create pie chart
        fig = go.Figure(data=[go.Pie(
            labels=list(filtered_counts.keys()),
            values=list(filtered_counts.values()),
            hole=0.3,
            marker_colors=['#e74c3c', '#f39c12', '#f1c40f', '#27ae60', '#95a5a6']
        )])
        
        fig.update_layout(
            title="Vulnerability Severity Distribution",
            font=dict(size=12),
            height=400
        )
        
        return json.dumps(fig, cls=PlotlyJSONEncoder)
    
    def _process_ai_analysis(self, ai_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Process AI analysis data for template rendering."""
        if 'error' in ai_analysis:
            return {'error': ai_analysis['error']}
        
        # Safely handle recommendations
        recommendations = ai_analysis.get('recommendations', [])
        if not isinstance(recommendations, list):
            recommendations = []
        
        return {
            'summary': ai_analysis.get('summary', ''),
            'risk_assessment': ai_analysis.get('risk_assessment', ''),
            'recommendations': recommendations[:5] if recommendations else []  # Limit to top 5
        }
    
    def _process_compliance_results(self, compliance_results: Dict[str, Any]) -> Dict[str, Any]:
        """Process compliance results for template rendering."""
        # Safely handle recommendations
        recommendations = compliance_results.get('recommendations', [])
        if not isinstance(recommendations, list):
            recommendations = []
        
        return {
            'compliance_score': compliance_results.get('compliance_score', 0),
            'status': compliance_results.get('status', 'unknown').replace('_', ' ').title(),
            'total_vulnerabilities': compliance_results.get('total_vulnerabilities', 0),
            'critical_violations': compliance_results.get('critical_violations', 0),
            'high_violations': compliance_results.get('high_violations', 0),
            'medium_violations': compliance_results.get('medium_violations', 0),
            'low_violations': compliance_results.get('low_violations', 0),
            'recommendations': recommendations[:5] if recommendations else []  # Limit to top 5
        }
    
    def _process_mitigation_plan(self, mitigation_plan: Dict[str, Any]) -> Dict[str, Any]:
        """Process mitigation plan for template rendering."""
        summary = mitigation_plan.get('summary', {})
        
        # Safely handle mitigation recommendations
        mitigation_recommendations = mitigation_plan.get('mitigation_plan', [])
        if not isinstance(mitigation_recommendations, list):
            mitigation_recommendations = []
        
        # Safely handle vulnerability mitigations
        vulnerability_mitigations = mitigation_plan.get('vulnerability_mitigations', [])
        if not isinstance(vulnerability_mitigations, list):
            vulnerability_mitigations = []
        
        return {
            'summary': {
                'critical_actions': summary.get('critical_actions', 0),
                'high_actions': summary.get('high_actions', 0),
                'medium_actions': summary.get('medium_actions', 0),
                'low_actions': summary.get('low_actions', 0),
                'estimated_timeline': summary.get('estimated_timeline', 'N/A'),
                'overall_effort': summary.get('overall_effort', 'N/A')
            },
            'recommendations': mitigation_recommendations[:10] if mitigation_recommendations else [],  # Limit to top 10
            'vulnerability_mitigations': vulnerability_mitigations[:10] if vulnerability_mitigations else []  # Limit to top 10
        }
