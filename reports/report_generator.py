#!/usr/bin/env python3
"""
Report Generator for CapScan
Main interface for generating PDF and HTML reports from scan results.
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import os

from .pdf_exporter import PDFExporter
from .html_exporter import HTMLExporter


class ReportGenerator:
    """Main report generator that coordinates PDF and HTML export."""
    
    def __init__(self):
        self.pdf_exporter = None
        self.html_exporter = None
        
        # Initialize exporters
        try:
            self.pdf_exporter = PDFExporter()
        except ImportError as e:
            print(f"Warning: PDF export not available: {e}")
        
        try:
            self.html_exporter = HTMLExporter()
        except ImportError as e:
            print(f"Warning: HTML export not available: {e}")
    
    def export_to_pdf(self, scan_data: Dict[str, Any], output_path: Optional[str] = None,
                     ai_analysis: Optional[Dict[str, Any]] = None,
                     compliance_results: Optional[Dict[str, Any]] = None,
                     mitigation_plan: Optional[Dict[str, Any]] = None) -> str:
        """
        Export scan results to PDF with optional AI analysis, compliance, and mitigation data.
        
        Args:
            scan_data: Scan results dictionary
            output_path: Optional path to save PDF file. If None, auto-generates filename.
            ai_analysis: Optional AI analysis results
            compliance_results: Optional compliance analysis results
            mitigation_plan: Optional mitigation plan results
            
        Returns:
            str: Path to saved PDF file
            
        Raises:
            ImportError: If reportlab is not available
            ValueError: If no scan data provided
        """
        if not self.pdf_exporter:
            raise ImportError("PDF export not available. Install reportlab: pip install reportlab")
        
        if not scan_data:
            raise ValueError("No scan data provided")
        
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = scan_data.get('target', 'unknown').replace('.', '_').replace('/', '_')
            output_path = f"output/capscan_report_{target}_{timestamp}.pdf"
        
        # Ensure output directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        return self.pdf_exporter.export_scan_results(scan_data, output_path, ai_analysis, compliance_results, mitigation_plan)
    
    def export_ai_analysis_to_pdf(self, scan_data: Dict[str, Any], ai_analysis: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """
        Export only AI analysis results to PDF.
        
        Args:
            scan_data: Basic scan data for title page
            ai_analysis: AI analysis results
            output_path: Optional path to save PDF file. If None, auto-generates filename.
            
        Returns:
            str: Path to saved PDF file
            
        Raises:
            ImportError: If reportlab is not available
            ValueError: If required data is missing
        """
        if not self.pdf_exporter:
            raise ImportError("PDF export not available. Install reportlab: pip install reportlab")
        
        if not scan_data or not ai_analysis:
            raise ValueError("Scan data and AI analysis required")
        
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = scan_data.get('target', 'unknown').replace('.', '_').replace('/', '_')
            output_path = f"capscan_ai_analysis_{target}_{timestamp}.pdf"
        
        return self.pdf_exporter.export_ai_analysis_only(scan_data, ai_analysis, output_path)
    
    def export_compliance_analysis_to_pdf(self, scan_data: Dict[str, Any], compliance_results: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """
        Export only compliance analysis results to PDF.
        
        Args:
            scan_data: Basic scan data for title page
            compliance_results: Compliance analysis results
            output_path: Optional path to save PDF file. If None, auto-generates filename.
            
        Returns:
            str: Path to saved PDF file
            
        Raises:
            ImportError: If reportlab is not available
            ValueError: If required data is missing
        """
        if not self.pdf_exporter:
            raise ImportError("PDF export not available. Install reportlab: pip install reportlab")
        
        if not scan_data or not compliance_results:
            raise ValueError("Scan data and compliance results required")
        
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = scan_data.get('target', 'unknown').replace('.', '_').replace('/', '_')
            output_path = f"capscan_compliance_{target}_{timestamp}.pdf"
        
        return self.pdf_exporter.export_compliance_analysis_only(scan_data, compliance_results, output_path)
    
    def export_mitigation_plan_to_pdf(self, scan_data: Dict[str, Any], mitigation_plan: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """
        Export only mitigation plan results to PDF.
        
        Args:
            scan_data: Basic scan data for title page
            mitigation_plan: Mitigation plan results
            output_path: Optional path to save PDF file. If None, auto-generates filename.
            
        Returns:
            str: Path to saved PDF file
            
        Raises:
            ImportError: If reportlab is not available
            ValueError: If required data is missing
        """
        if not self.pdf_exporter:
            raise ImportError("PDF export not available. Install reportlab: pip install reportlab")
        
        if not scan_data or not mitigation_plan:
            raise ValueError("Scan data and mitigation plan required")
        
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = scan_data.get('target', 'unknown').replace('.', '_').replace('/', '_')
            output_path = f"capscan_mitigation_{target}_{timestamp}.pdf"
        
        return self.pdf_exporter.export_mitigation_plan_only(scan_data, mitigation_plan, output_path)
    
    def export_to_html(self, scan_data: Dict[str, Any], output_path: Optional[str] = None,
                      ai_analysis: Optional[Dict[str, Any]] = None,
                      compliance_results: Optional[Dict[str, Any]] = None,
                      mitigation_plan: Optional[Dict[str, Any]] = None) -> str:
        """
        Export scan results to HTML with optional AI analysis, compliance, and mitigation data.
        
        Args:
            scan_data: Scan results dictionary
            output_path: Optional path to save HTML file. If None, auto-generates filename.
            ai_analysis: Optional AI analysis results
            compliance_results: Optional compliance analysis results
            mitigation_plan: Optional mitigation plan results
            
        Returns:
            str: Path to saved HTML file
            
        Raises:
            ImportError: If jinja2 is not available
            ValueError: If no scan data provided
        """
        if not self.html_exporter:
            raise ImportError("HTML export not available. Install jinja2: pip install jinja2")
        
        if not scan_data:
            raise ValueError("No scan data provided")
        
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = scan_data.get('target', 'unknown').replace('.', '_').replace('/', '_')
            output_path = f"output/capscan_report_{target}_{timestamp}.html"
        
        # Ensure output directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        return self.html_exporter.export_scan_results(scan_data, output_path, ai_analysis, compliance_results, mitigation_plan)
    
    def export_both_formats(self, scan_data: Dict[str, Any], base_path: Optional[str] = None) -> Dict[str, str]:
        """
        Export scan results to both PDF and HTML formats.
        
        Args:
            scan_data: Scan results dictionary
            base_path: Optional base path for files. If None, auto-generates filename.
            
        Returns:
            Dict[str, str]: Dictionary with 'pdf' and 'html' keys containing file paths
            
        Raises:
            ValueError: If no scan data provided
        """
        if not scan_data:
            raise ValueError("No scan data provided")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = scan_data.get('target', 'unknown').replace('.', '_').replace('/', '_')
        
        if base_path is None:
            base_path = f"output/capscan_report_{target}_{timestamp}"
        
        results = {}
        
        # Export PDF if available
        if self.pdf_exporter:
            try:
                pdf_path = f"{base_path}.pdf"
                results['pdf'] = self.export_to_pdf(scan_data, pdf_path)
            except Exception as e:
                print(f"PDF export failed: {e}")
                results['pdf'] = None
        
        # Export HTML if available
        if self.html_exporter:
            try:
                html_path = f"{base_path}.html"
                results['html'] = self.export_to_html(scan_data, html_path)
            except Exception as e:
                print(f"HTML export failed: {e}")
                results['html'] = None
        
        return results
    
    def is_pdf_available(self) -> bool:
        """Check if PDF export is available."""
        return self.pdf_exporter is not None

    def export_text_to_pdf(self, title: str, text_content: str, output_path: str) -> str:
        """Export preformatted text to PDF."""
        if not self.pdf_exporter:
            raise ImportError("PDF export not available. Install reportlab: pip install reportlab")
        return self.pdf_exporter.export_preformatted_text(title, text_content, output_path)

    def export_text_to_html(self, title: str, text_content: str, output_path: str) -> str:
        """Export preformatted text to HTML."""
        if not self.html_exporter:
            raise ImportError("HTML export not available. Install jinja2: pip install jinja2")
        return self.html_exporter.export_preformatted_text(title, text_content, output_path)
    
    def is_html_available(self) -> bool:
        """Check if HTML export is available."""
        return self.html_exporter is not None
    
    def get_available_formats(self) -> List[str]:
        """Get list of available export formats."""
        formats = []
        if self.is_pdf_available():
            formats.append('pdf')
        if self.is_html_available():
            formats.append('html')
        return formats
