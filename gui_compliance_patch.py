
# Add this to the CapScanGUI class __init__ method after line 47:
        # Vulnerability enhancer for better compliance analysis
        self.vuln_enhancer = VulnerabilityEnhancer()
        self.compliance_helper = ComplianceAnalysisHelper()

# Add this method to the CapScanGUI class:
    def enhance_vulnerabilities_for_compliance(self):
        """Enhance vulnerability descriptions for better compliance analysis."""
        if not self.scanner.scan_results or not self.scanner.scan_results.get('vulnerabilities'):
            self.show_error("No vulnerabilities to enhance. Please run a scan first.")
            return
        
        try:
            # Get current vulnerabilities
            vulnerabilities = self.scanner.scan_results.get('vulnerabilities', [])
            
            # Enhance descriptions
            enhanced_vulns = self.vuln_enhancer.enhance_vulnerabilities(vulnerabilities)
            
            # Update scan results
            self.scanner.scan_results['vulnerabilities'] = enhanced_vulns
            
            # Update display
            self.update_vulnerabilities()
            
            # Show success message
            enhanced_count = len([v for v in enhanced_vulns if v.get('description') != vulnerabilities[enhanced_vulns.index(v)].get('description')])
            self.show_info(f"Enhanced {enhanced_count} vulnerability descriptions for better compliance analysis.")
            
        except Exception as e:
            self.show_error(f"Error enhancing vulnerabilities: {str(e)}")

# Add this method to the CapScanGUI class:
    def explain_compliance_score(self):
        """Show explanation of compliance score."""
        if not self.compliance_results:
            self.show_error("No compliance analysis results available. Please run compliance analysis first.")
            return
        
        standard = self.compliance_standard_var.get()
        if standard not in self.compliance_results:
            self.show_error(f"No {standard} compliance results available.")
            return
        
        results = self.compliance_results[standard]
        score = results.get('compliance_score', 0)
        violations = results.get('violations', [])
        
        explanation = self.compliance_helper.explain_compliance_score(score, violations)
        
        # Show explanation in a new window
        explanation_window = tk.Toplevel(self.root)
        explanation_window.title("Compliance Score Explanation")
        explanation_window.geometry("600x400")
        
        text_widget = tk.Text(explanation_window, wrap=tk.WORD, padx=10, pady=10)
        text_widget.pack(fill=tk.BOTH, expand=True)
        text_widget.insert(1.0, explanation)
        text_widget.config(state=tk.DISABLED)

# Add this method to the CapScanGUI class:
    def show_vulnerability_analysis_tips(self):
        """Show tips for better vulnerability analysis."""
        tips = self.compliance_helper.get_vulnerability_analysis_tips()
        
        # Show tips in a new window
        tips_window = tk.Toplevel(self.root)
        tips_window.title("Vulnerability Analysis Tips")
        tips_window.geometry("700x500")
        
        text_widget = tk.Text(tips_window, wrap=tk.WORD, padx=10, pady=10)
        text_widget.pack(fill=tk.BOTH, expand=True)
        text_widget.insert(1.0, tips)
        text_widget.config(state=tk.DISABLED)

# Update the create_compliance_analysis_tab method to add new buttons:
        # Add enhancement and explanation buttons
        self.compliance_enhance_btn = ttk.Button(
            self.compliance_controls_frame, 
            text="Enhance Descriptions", 
            command=self.enhance_vulnerabilities_for_compliance,
            bootstyle=INFO
        )
        
        self.compliance_explain_btn = ttk.Button(
            self.compliance_controls_frame, 
            text="Explain Score", 
            command=self.explain_compliance_score,
            bootstyle=SECONDARY
        )
        
        self.compliance_tips_btn = ttk.Button(
            self.compliance_controls_frame, 
            text="Analysis Tips", 
            command=self.show_vulnerability_analysis_tips,
            bootstyle=SECONDARY
        )
        
        # Add buttons to layout (after the existing compliance_analyze_btn)
        self.compliance_enhance_btn.pack(side=LEFT, padx=(10, 5))
        self.compliance_explain_btn.pack(side=LEFT, padx=(0, 5))
        self.compliance_tips_btn.pack(side=LEFT, padx=(0, 5))

# Update the display_compliance_results method to show better information:
    def display_compliance_results(self, results, standard):
        """Display compliance analysis results with enhanced information."""
        self.compliance_results_text.delete(1.0, tk.END)
        
        result_text = f"{standard} Compliance Analysis Results
"
        result_text += "=" * 50 + "

"
        
        score = results.get('compliance_score', 'N/A')
        result_text += f"Compliance Score: {score}/100
"
        
        # Add score interpretation
        if isinstance(score, (int, float)):
            if score >= 90:
                result_text += "Status: ✅ Excellent Compliance
"
            elif score >= 70:
                result_text += "Status: ⚠️ Good Compliance
"
            elif score >= 50:
                result_text += "Status: ⚠️ Moderate Compliance
"
            elif score >= 25:
                result_text += "Status: ❌ Poor Compliance
"
            else:
                result_text += "Status: ❌ Critical Compliance
"
        else:
            result_text += f"Status: {results.get('status', 'N/A').replace('_', ' ').title()}
"
        
        result_text += f"Total Vulnerabilities: {results.get('total_vulnerabilities', 0)}

"
        
        result_text += "Violation Summary:
"
        result_text += f"  Critical: {results.get('critical_violations', 0)}
"
        result_text += f"  High: {results.get('high_violations', 0)}
"
        result_text += f"  Medium: {results.get('medium_violations', 0)}
"
        result_text += f"  Low: {results.get('low_violations', 0)}

"
        
        # Add explanation if score seems incorrect
        if isinstance(score, (int, float)) and score == 100.0 and results.get('total_vulnerabilities', 0) > 0:
            result_text += "⚠️ Note: 100% compliance with vulnerabilities present may indicate
"
            result_text += "   that vulnerability descriptions need enhancement for proper categorization.
"
            result_text += "   Try using 'Enhance Descriptions' button for better analysis.

"
        
        if 'violations' in results and results['violations']:
            result_text += "Key Violations:
"
            for i, violation in enumerate(results['violations'][:10], 1):
                requirement = violation.get('requirement', 'Unknown')
                severity = violation.get('severity', 'unknown')
                description = violation.get('description', 'No description')
                result_text += f"{i}. {requirement} [{severity.upper()}]
"
                result_text += f"   {description}

"
            
            if len(results['violations']) > 10:
                result_text += f"... and {len(results['violations']) - 10} more violations

"
        else:
            result_text += "No specific compliance violations detected.

"
        
        if 'recommendations' in results and results['recommendations']:
            result_text += "Compliance Recommendations:
"
            for i, rec in enumerate(results['recommendations'][:5], 1):
                result_text += f"{i}. {rec}
"
            result_text += "
"
        
        result_text += f"Analysis Time: {results.get('analysis_time', 'N/A')}
"
        
        self.compliance_results_text.insert(1.0, result_text)
