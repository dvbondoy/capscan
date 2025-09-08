import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import threading
import json
import os
from datetime import datetime
from engine import Scanner
from database import Database

class CapScanGUI:
    def __init__(self):
        # Initialize ttkbootstrap with flatly theme
        self.root = ttk.Window(themename="flatly")
        self.root.title("CapScan - Vulnerability Scanner")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Initialize scanner
        self.scanner = Scanner()
        self.scan_thread = None
        self.is_scanning = False
        
        # Database variables
        self.db_password = None
        self.scan_id = None
        self.db_connected = False
        
        # Create GUI elements
        self.create_widgets()
        self.setup_layout()
        
    def create_widgets(self):
        """Create all GUI widgets"""
        
        # Main container
        self.main_frame = ttk.Frame(self.root, padding="10")
        
        # Title
        self.title_label = ttk.Label(
            self.main_frame, 
            text="CapScan Vulnerability Scanner", 
            font=("Arial", 16, "bold"),
            bootstyle=PRIMARY
        )
        
        # Input section
        self.input_frame = ttk.LabelFrame(self.main_frame, text="Scan Configuration", padding="10")
        
        # Target input
        self.target_label = ttk.Label(self.input_frame, text="Target Host/IP:")
        self.target_entry = ttk.Entry(self.input_frame, width=30, font=("Arial", 10))
        self.target_entry.insert(0, "192.168.1.1")
        
        # Port range input
        self.ports_label = ttk.Label(self.input_frame, text="Port Range:")
        self.ports_entry = ttk.Entry(self.input_frame, width=30, font=("Arial", 10))
        self.ports_entry.insert(0, "22,80,443,8080")
        
        # Port range options
        self.port_options_frame = ttk.Frame(self.input_frame)
        self.port_preset_label = ttk.Label(self.port_options_frame, text="Port Presets:")
        self.port_preset_var = tk.StringVar(value="Custom")
        self.port_preset_combo = ttk.Combobox(
            self.port_options_frame,
            textvariable=self.port_preset_var,
            values=["Custom", "Quick Scan", "Common Ports", "All Ports"],
            state="readonly",
            width=15
        )
        self.port_preset_combo.bind("<<ComboboxSelected>>", self.on_port_preset_change)
        
        # Scan options
        self.options_frame = ttk.Frame(self.input_frame)
        self.max_reports_label = ttk.Label(self.options_frame, text="Max Reports per Port:")
        self.max_reports_var = tk.StringVar(value="10")
        self.max_reports_spinbox = ttk.Spinbox(
            self.options_frame, 
            from_=1, 
            to=100, 
            textvariable=self.max_reports_var,
            width=10
        )
        
        self.enhance_scores_var = tk.BooleanVar(value=True)
        self.enhance_scores_check = ttk.Checkbutton(
            self.options_frame, 
            text="Enable Keyword-based Scoring", 
            variable=self.enhance_scores_var
        )
        
        # Database options
        self.db_options_frame = ttk.Frame(self.input_frame)
        self.save_to_db_var = tk.BooleanVar(value=True)
        self.save_to_db_check = ttk.Checkbutton(
            self.db_options_frame, 
            text="Save to Database", 
            variable=self.save_to_db_var
        )
        
        self.db_password_label = ttk.Label(self.db_options_frame, text="DB Password:")
        self.db_password_entry = ttk.Entry(
            self.db_options_frame, 
            width=20, 
            font=("Arial", 10),
            show="*"
        )
        
        self.db_info_btn = ttk.Button(
            self.db_options_frame, 
            text="DB Info", 
            command=self.show_db_info,
            bootstyle=INFO,
            width=10
        )
        
        # Scan buttons
        self.scan_buttons_frame = ttk.Frame(self.input_frame)
        self.scan_toggle_btn = ttk.Button(
            self.scan_buttons_frame, 
            text="Start Scan", 
            command=self.toggle_scan,
            bootstyle=SUCCESS,
            width=15
        )
        self.save_results_btn = ttk.Button(
            self.scan_buttons_frame, 
            text="Save Results", 
            command=self.save_results,
            bootstyle=INFO,
            width=15,
            state=DISABLED
        )
        
        # Progress section
        self.progress_frame = ttk.LabelFrame(self.main_frame, text="Scan Progress", padding="10")
        self.progress_bar = ttk.Progressbar(
            self.progress_frame, 
            mode='indeterminate',
            bootstyle=SUCCESS
        )
        self.status_label = ttk.Label(self.progress_frame, text="Ready to scan...")
        
        # Results section
        self.results_frame = ttk.LabelFrame(self.main_frame, text="Scan Results", padding="10")
        
        # Create notebook for different result views
        self.results_notebook = ttk.Notebook(self.results_frame)
        
        # Summary tab
        self.summary_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.summary_frame, text="Summary")
        
        self.summary_text = tk.Text(
            self.summary_frame, 
            height=8, 
            width=80, 
            font=("Consolas", 9),
            wrap=tk.WORD
        )
        self.summary_scrollbar = ttk.Scrollbar(self.summary_frame, orient=VERTICAL, command=self.summary_text.yview)
        self.summary_text.configure(yscrollcommand=self.summary_scrollbar.set)
        
        # Vulnerabilities tab
        self.vulns_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.vulns_frame, text="Vulnerabilities")
        
        # Treeview for vulnerabilities
        self.vulns_tree_frame = ttk.Frame(self.vulns_frame)
        self.vulns_tree = ttk.Treeview(
            self.vulns_tree_frame,
            columns=("CVE ID", "Score", "Severity", "Description"),
            show="headings",
            height=15
        )
        
        # Configure treeview columns
        self.vulns_tree.heading("CVE ID", text="CVE ID")
        self.vulns_tree.heading("Score", text="Score")
        self.vulns_tree.heading("Severity", text="Severity")
        self.vulns_tree.heading("Description", text="Description")
        
        self.vulns_tree.column("CVE ID", width=120)
        self.vulns_tree.column("Score", width=80)
        self.vulns_tree.column("Severity", width=100)
        self.vulns_tree.column("Description", width=400)
        
        self.vulns_tree_scrollbar = ttk.Scrollbar(self.vulns_tree_frame, orient=VERTICAL, command=self.vulns_tree.yview)
        self.vulns_tree.configure(yscrollcommand=self.vulns_tree_scrollbar.set)
        
        # Vulnerability details
        self.vuln_details_frame = ttk.LabelFrame(self.vulns_frame, text="Vulnerability Details", padding="5")
        self.vuln_details_text = tk.Text(
            self.vuln_details_frame, 
            height=6, 
            width=80, 
            font=("Consolas", 9),
            wrap=tk.WORD
        )
        self.vuln_details_scrollbar = ttk.Scrollbar(self.vuln_details_frame, orient=VERTICAL, command=self.vuln_details_text.yview)
        self.vuln_details_text.configure(yscrollcommand=self.vuln_details_scrollbar.set)
        
        # Statistics tab
        self.stats_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.stats_frame, text="Statistics")
        
        self.stats_text = tk.Text(
            self.stats_frame, 
            height=15, 
            width=80, 
            font=("Consolas", 10),
            wrap=tk.WORD
        )
        self.stats_scrollbar = ttk.Scrollbar(self.stats_frame, orient=VERTICAL, command=self.stats_text.yview)
        self.stats_text.configure(yscrollcommand=self.stats_scrollbar.set)
        
        # Database tab
        self.db_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.db_frame, text="Database")
        
        # Database controls
        self.db_controls_frame = ttk.LabelFrame(self.db_frame, text="Database Controls", padding="10")
        
        self.db_status_label = ttk.Label(self.db_controls_frame, text="Status: Not connected")
        self.db_connect_btn = ttk.Button(
            self.db_controls_frame, 
            text="Connect to DB", 
            command=self.toggle_db_connection,
            bootstyle=SUCCESS,
            width=15
        )
        self.db_refresh_btn = ttk.Button(
            self.db_controls_frame, 
            text="Refresh", 
            command=self.refresh_db_info,
            bootstyle=INFO,
            width=15,
            state=DISABLED
        )
        
        # Database info display
        self.db_info_frame = ttk.LabelFrame(self.db_frame, text="Database Information", padding="10")
        self.db_info_text = tk.Text(
            self.db_info_frame, 
            height=12, 
            width=80, 
            font=("Consolas", 9),
            wrap=tk.WORD
        )
        self.db_info_scrollbar = ttk.Scrollbar(self.db_info_frame, orient=VERTICAL, command=self.db_info_text.yview)
        self.db_info_text.configure(yscrollcommand=self.db_info_scrollbar.set)
        
        # Recent scans list
        self.recent_scans_frame = ttk.LabelFrame(self.db_frame, text="Recent Scans", padding="10")
        self.recent_scans_tree = ttk.Treeview(
            self.recent_scans_frame,
            columns=("Target", "Time", "Vulns", "Status"),
            show="headings",
            height=8
        )
        
        # Configure recent scans treeview
        self.recent_scans_tree.heading("Target", text="Target")
        self.recent_scans_tree.heading("Time", text="Scan Time")
        self.recent_scans_tree.heading("Vulns", text="Vulnerabilities")
        self.recent_scans_tree.heading("Status", text="Status")
        
        self.recent_scans_tree.column("Target", width=150)
        self.recent_scans_tree.column("Time", width=150)
        self.recent_scans_tree.column("Vulns", width=100)
        self.recent_scans_tree.column("Status", width=100)
        
        self.recent_scans_scrollbar = ttk.Scrollbar(self.recent_scans_frame, orient=VERTICAL, command=self.recent_scans_tree.yview)
        self.recent_scans_tree.configure(yscrollcommand=self.recent_scans_scrollbar.set)
        
        # Bind events
        self.vulns_tree.bind("<<TreeviewSelect>>", self.on_vuln_select)
        self.ports_entry.bind("<KeyRelease>", self.on_port_entry_change)
        
        # Initialize database info display
        self.db_info_text.insert(1.0, "Database disconnected. Click 'Connect to DB' to connect.")
        
    def setup_layout(self):
        """Setup the layout of all widgets"""
        
        # Main frame
        self.main_frame.pack(fill=BOTH, expand=True)
        
        # Title
        self.title_label.pack(pady=(0, 20))
        
        # Input section
        self.input_frame.pack(fill=X, pady=(0, 10))
        
        # Target input
        self.target_label.grid(row=0, column=0, sticky=W, padx=(0, 10), pady=5)
        self.target_entry.grid(row=0, column=1, sticky=W, padx=(0, 20), pady=5)
        
        # Port range input
        self.ports_label.grid(row=1, column=0, sticky=W, padx=(0, 10), pady=5)
        self.ports_entry.grid(row=1, column=1, sticky=W, padx=(0, 20), pady=5)
        
        # Port options
        self.port_options_frame.grid(row=1, column=2, sticky=W, padx=(10, 0), pady=5)
        self.port_preset_label.pack(side=LEFT, padx=(0, 5))
        self.port_preset_combo.pack(side=LEFT)
        
        # Scan options
        self.options_frame.grid(row=2, column=0, columnspan=3, sticky=W, pady=10)
        self.max_reports_label.pack(side=LEFT, padx=(0, 5))
        self.max_reports_spinbox.pack(side=LEFT, padx=(0, 20))
        self.enhance_scores_check.pack(side=LEFT)
        
        # Database options
        self.db_options_frame.grid(row=3, column=0, columnspan=3, sticky=W, pady=5)
        self.save_to_db_check.pack(side=LEFT, padx=(0, 20))
        self.db_password_label.pack(side=LEFT, padx=(0, 5))
        self.db_password_entry.pack(side=LEFT, padx=(0, 10))
        self.db_info_btn.pack(side=LEFT)
        
        # Scan buttons
        self.scan_buttons_frame.grid(row=4, column=0, columnspan=3, pady=10)
        self.scan_toggle_btn.pack(side=LEFT, padx=(0, 10))
        self.save_results_btn.pack(side=LEFT)
        
        # Progress section
        self.progress_frame.pack(fill=X, pady=(0, 10))
        self.progress_bar.pack(fill=X, pady=(0, 5))
        self.status_label.pack(anchor=W)
        
        # Results section
        self.results_frame.pack(fill=BOTH, expand=True)
        self.results_notebook.pack(fill=BOTH, expand=True)
        
        # Summary tab
        self.summary_text.pack(side=LEFT, fill=BOTH, expand=True)
        self.summary_scrollbar.pack(side=RIGHT, fill=Y)
        
        # Vulnerabilities tab
        self.vulns_tree_frame.pack(fill=BOTH, expand=True, pady=(0, 10))
        self.vulns_tree.pack(side=LEFT, fill=BOTH, expand=True)
        self.vulns_tree_scrollbar.pack(side=RIGHT, fill=Y)
        
        self.vuln_details_frame.pack(fill=X)
        self.vuln_details_text.pack(side=LEFT, fill=BOTH, expand=True)
        self.vuln_details_scrollbar.pack(side=RIGHT, fill=Y)
        
        # Statistics tab
        self.stats_text.pack(side=LEFT, fill=BOTH, expand=True)
        self.stats_scrollbar.pack(side=RIGHT, fill=Y)
        
        # Database tab
        self.db_controls_frame.pack(fill=X, pady=(0, 10))
        self.db_status_label.pack(side=LEFT, padx=(0, 10))
        self.db_connect_btn.pack(side=LEFT, padx=(0, 5))
        self.db_refresh_btn.pack(side=LEFT)
        
        self.db_info_frame.pack(fill=BOTH, expand=True, pady=(0, 10))
        self.db_info_text.pack(side=LEFT, fill=BOTH, expand=True)
        self.db_info_scrollbar.pack(side=RIGHT, fill=Y)
        
        self.recent_scans_frame.pack(fill=BOTH, expand=True)
        self.recent_scans_tree.pack(side=LEFT, fill=BOTH, expand=True)
        self.recent_scans_scrollbar.pack(side=RIGHT, fill=Y)
        
    def on_port_preset_change(self, event):
        """Handle port preset dropdown selection"""
        preset = self.port_preset_var.get()
        
        if preset == "Quick Scan":
            self.ports_entry.delete(0, tk.END)
            self.ports_entry.insert(0, "22,80,443")
        elif preset == "Common Ports":
            self.ports_entry.delete(0, tk.END)
            self.ports_entry.insert(0, "22,23,25,53,80,110,143,443,993,995,3389,5432,5900,8080")
        elif preset == "All Ports":
            self.ports_entry.delete(0, tk.END)
            self.ports_entry.insert(0, "1-65535")
        elif preset == "Custom":
            # Don't change the current port entry, just keep it as is
            pass
    
    def on_port_entry_change(self, event):
        """Handle manual changes to port entry field"""
        current_ports = self.ports_entry.get().strip()
        
        # Check if current entry matches any preset
        if current_ports == "22,80,443":
            self.port_preset_var.set("Quick Scan")
        elif current_ports == "22,23,25,53,80,110,143,443,993,995,3389,5432,5900,8080":
            self.port_preset_var.set("Common Ports")
        elif current_ports == "1-65535":
            self.port_preset_var.set("All Ports")
        else:
            self.port_preset_var.set("Custom")
        
    def toggle_scan(self):
        """Toggle scan state (start/stop)"""
        if self.is_scanning:
            self.stop_scan()
        else:
            self.start_scan()
    
    def start_scan(self):
        """Start vulnerability scan in a separate thread"""
        if self.is_scanning:
            return
            
        target = self.target_entry.get().strip()
        ports = self.ports_entry.get().strip()
        
        if not target:
            self.show_error("Please enter a target host/IP")
            return
            
        if not ports:
            self.show_error("Please enter port range")
            return
            
        # Update UI
        self.is_scanning = True
        self.scan_toggle_btn.config(text="Stop Scan", bootstyle=DANGER)
        self.progress_bar.start()
        self.status_label.config(text=f"Scanning {target} on ports {ports}...")
        
        # Clear previous results
        self.clear_results()
        
        # Start scan in thread
        self.scan_thread = threading.Thread(target=self.run_scan, args=(target, ports))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
    def run_scan(self, target, ports):
        """Run the actual scan"""
        try:
            # Perform scan
            max_reports = int(self.max_reports_var.get())
            vulners_args = f"--script-args vulners.maxreports={max_reports}"
            
            results = self.scanner.scan_host(target, ports, vulners_args)
            
            if 'error' in results:
                self.root.after(0, lambda: self.scan_error(results['error']))
                return
                
            # Enhance with scores if enabled
            if self.enhance_scores_var.get():
                self.root.after(0, lambda: self.status_label.config(text="Enhancing vulnerabilities with scores..."))
                enhanced_count = self.scanner.enhance_vulnerabilities_with_scores()
                self.root.after(0, lambda: self.status_label.config(text=f"Enhanced {enhanced_count} vulnerabilities with scores"))
            
            # Update UI with results
            self.root.after(0, self.scan_complete)
            
        except Exception as e:
            self.root.after(0, lambda: self.scan_error(str(e)))
            
    def scan_complete(self):
        """Handle scan completion"""
        self.is_scanning = False
        self.scan_toggle_btn.config(text="Start Scan", bootstyle=SUCCESS)
        self.progress_bar.stop()
        self.status_label.config(text="Scan completed successfully!")
        self.save_results_btn.config(state=NORMAL)
        
        # Save to database if enabled
        if self.save_to_db_var.get():
            self.save_to_database()
        
        # Update results display
        self.update_summary()
        self.update_vulnerabilities()
        self.update_statistics()
        
    def scan_error(self, error_msg):
        """Handle scan error"""
        self.is_scanning = False
        self.scan_toggle_btn.config(text="Start Scan", bootstyle=SUCCESS)
        self.progress_bar.stop()
        self.status_label.config(text=f"Scan failed: {error_msg}")
        self.show_error(f"Scan failed: {error_msg}")
        
    def stop_scan(self):
        """Stop the current scan"""
        if self.is_scanning:
            self.is_scanning = False
            self.scan_toggle_btn.config(text="Start Scan", bootstyle=SUCCESS)
            self.progress_bar.stop()
            self.status_label.config(text="Scan stopped by user")
            
    def clear_results(self):
        """Clear all result displays"""
        self.summary_text.delete(1.0, tk.END)
        self.vuln_details_text.delete(1.0, tk.END)
        self.stats_text.delete(1.0, tk.END)
        
        # Clear treeview
        for item in self.vulns_tree.get_children():
            self.vulns_tree.delete(item)
            
    def update_summary(self):
        """Update summary display"""
        summary = self.scanner.get_scan_summary()
        
        summary_text = f"""
VULNERABILITY SCAN SUMMARY
{'='*50}
Target: {summary.get('target', 'N/A')}
Scan Time: {summary.get('scan_time', 'N/A')}
Hosts Scanned: {summary.get('hosts_scanned', 0)}
Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}

Severity Breakdown:
  High: {summary.get('severity_breakdown', {}).get('high', 0)}
  Medium: {summary.get('severity_breakdown', {}).get('medium', 0)}
  Low: {summary.get('severity_breakdown', {}).get('low', 0)}
  Unknown: {summary.get('severity_breakdown', {}).get('unknown', 0)}

XML Output: {summary.get('xml_output_path', 'N/A')}
"""
        
        self.summary_text.insert(1.0, summary_text)
        
    def update_vulnerabilities(self):
        """Update vulnerabilities display"""
        vulnerabilities = self.scanner.get_vulnerabilities()
        
        for vuln in vulnerabilities:
            cve_id = vuln.get('cve_id', 'N/A')
            score = vuln.get('score', 'N/A')
            description = vuln.get('description', 'N/A')
            
            # Determine severity
            if score == 'N/A' or score is None:
                severity = "Unknown"
            elif score >= 7.0:
                severity = "High"
            elif score >= 4.0:
                severity = "Medium"
            else:
                severity = "Low"
                
            # Truncate description for display
            display_desc = description[:80] + "..." if len(description) > 80 else description
            
            self.vulns_tree.insert("", "end", values=(cve_id, score, severity, display_desc))
            
    def update_statistics(self):
        """Update statistics display"""
        stats = self.scanner.get_scoring_statistics()
        
        stats_text = f"""
SCANNING STATISTICS
{'='*50}
Total Vulnerabilities: {stats.get('total_vulnerabilities', 0)}
Scored Vulnerabilities: {stats.get('scored_vulnerabilities', 0)}
Unscored Vulnerabilities: {stats.get('unscored_vulnerabilities', 0)}

Severity Distribution:
  High Severity: {stats.get('high_severity', 0)}
  Medium Severity: {stats.get('medium_severity', 0)}
  Low Severity: {stats.get('low_severity', 0)}

Scoring Information:
  Keyword Scored: {stats.get('keyword_scored', 0)}
  Scoring Coverage: {stats.get('scoring_coverage', 0):.1f}%

VULNERABILITY DETAILS
{'='*50}
"""
        
        # Add detailed vulnerability information
        vulnerabilities = self.scanner.get_vulnerabilities()
        for i, vuln in enumerate(vulnerabilities, 1):
            stats_text += f"""
{i}. CVE ID: {vuln.get('cve_id', 'N/A')}
   Score: {vuln.get('score', 'N/A')}
   Source: {vuln.get('score_source', 'N/A')}
   Description: {vuln.get('description', 'N/A')}
   Raw Output: {vuln.get('raw_output', 'N/A')}
   {'-'*40}
"""
        
        self.stats_text.insert(1.0, stats_text)
        
    def on_vuln_select(self, event):
        """Handle vulnerability selection"""
        selection = self.vulns_tree.selection()
        if not selection:
            return
            
        item = self.vulns_tree.item(selection[0])
        cve_id = item['values'][0]
        
        # Find the vulnerability details
        vulnerabilities = self.scanner.get_vulnerabilities()
        vuln_details = None
        for vuln in vulnerabilities:
            if vuln.get('cve_id') == cve_id:
                vuln_details = vuln
                break
                
        if vuln_details:
            details_text = f"""
CVE ID: {vuln_details.get('cve_id', 'N/A')}
Score: {vuln_details.get('score', 'N/A')}
Score Source: {vuln_details.get('score_source', 'N/A')}
Description: {vuln_details.get('description', 'N/A')}
Raw Output: {vuln_details.get('raw_output', 'N/A')}

Additional Information:
- Keyword Score: {vuln_details.get('keyword_score', 'N/A')}
- Year Score: {vuln_details.get('year_score', 'N/A')}
"""
            self.vuln_details_text.delete(1.0, tk.END)
            self.vuln_details_text.insert(1.0, details_text)
            
    def save_results(self):
        """Save scan results to files"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Save vulnerabilities
            vulnerabilities = self.scanner.get_vulnerabilities()
            vuln_file = f"output/vulnerabilities_{timestamp}.json"
            with open(vuln_file, 'w') as f:
                json.dump(vulnerabilities, f, indent=2)
                
            # Save summary
            summary = self.scanner.get_scan_summary()
            summary_file = f"output/summary_{timestamp}.json"
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)
                
            # Save XML
            xml_file = self.scanner.save_as_xml(f"output/vuln_scan_{timestamp}.xml")
            
            self.show_info(f"Results saved:\n- {vuln_file}\n- {summary_file}\n- {xml_file}")
            
        except Exception as e:
            self.show_error(f"Error saving results: {str(e)}")
            
    def show_error(self, message):
        """Show error message"""
        ttk.dialogs.Messagebox.show_error(message, title="Error")
        
    def show_info(self, message):
        """Show info message"""
        ttk.dialogs.Messagebox.show_info(message, title="Information")
    
    def save_to_database(self):
        """Save scan results to database"""
        try:
            # Check if connected to database
            if not self.db_connected:
                self.show_error("Please connect to database first")
                return
            
            # Get password from entry or use stored password
            password = self.db_password_entry.get().strip()
            if not password and not self.db_password:
                self.show_error("Please enter database password or connect to database first")
                return
            
            if password:
                self.db_password = password
            
            # Get scan results
            results = self.scanner.scan_results
            if not results:
                self.show_error("No scan results to save")
                return
            
            # Save to database
            with Database(password=self.db_password) as db:
                self.scan_id = db.save_scan_results(results)
                self.status_label.config(text=f"Scan completed and saved to database (ID: {self.scan_id})")
                self.show_info(f"Scan results saved to database with ID: {self.scan_id}")
                
                # Refresh database info
                self.refresh_db_info()
                
        except Exception as e:
            self.show_error(f"Error saving to database: {str(e)}")
    
    def toggle_db_connection(self):
        """Toggle database connection (connect/disconnect)"""
        if self.db_connected:
            self.disconnect_from_db()
        else:
            self.connect_to_db()
    
    def connect_to_db(self):
        """Connect to database and test connection"""
        try:
            password = self.db_password_entry.get().strip()
            if not password:
                self.show_error("Please enter database password")
                return
            
            # Test connection
            with Database(password=password) as db:
                self.db_password = password
                self.db_connected = True
                self.db_status_label.config(text="Status: Connected")
                self.db_connect_btn.config(text="Disconnect from DB", bootstyle=DANGER)
                self.db_refresh_btn.config(state=NORMAL)
                self.show_info("Successfully connected to database")
                
                # Refresh database info
                self.refresh_db_info()
                
        except Exception as e:
            self.show_error(f"Error connecting to database: {str(e)}")
            self.db_status_label.config(text="Status: Connection failed")
    
    def disconnect_from_db(self):
        """Disconnect from database"""
        self.db_connected = False
        self.db_password = None
        self.db_status_label.config(text="Status: Disconnected")
        self.db_connect_btn.config(text="Connect to DB", bootstyle=SUCCESS)
        self.db_refresh_btn.config(state=DISABLED)
        
        # Clear database info display
        self.db_info_text.delete(1.0, tk.END)
        self.db_info_text.insert(1.0, "Database disconnected. Click 'Connect to DB' to reconnect.")
        
        # Clear recent scans
        for item in self.recent_scans_tree.get_children():
            self.recent_scans_tree.delete(item)
        
        self.show_info("Disconnected from database")
    
    def refresh_db_info(self):
        """Refresh database information display"""
        if not self.db_connected or not self.db_password:
            self.db_info_text.delete(1.0, tk.END)
            self.db_info_text.insert(1.0, "Please connect to database first")
            return
        
        try:
            with Database(password=self.db_password) as db:
                # Get database summary
                summary = db.get_scan_summary()
                
                info_text = f"""
DATABASE SUMMARY
{'='*50}
Total Scans: {summary.get('total_scans', 0)}
Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}

Severity Breakdown:
  High Severity: {summary.get('high_severity', 0)}
  Medium Severity: {summary.get('medium_severity', 0)}
  Low Severity: {summary.get('low_severity', 0)}
  Unknown Severity: {summary.get('unknown_severity', 0)}

Database Status: Connected
Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
                
                self.db_info_text.delete(1.0, tk.END)
                self.db_info_text.insert(1.0, info_text)
                
                # Update recent scans
                self.update_recent_scans(db)
                
        except Exception as e:
            self.db_info_text.delete(1.0, tk.END)
            self.db_info_text.insert(1.0, f"Error accessing database: {str(e)}")
    
    def update_recent_scans(self, db):
        """Update recent scans list"""
        try:
            # Clear existing items
            for item in self.recent_scans_tree.get_children():
                self.recent_scans_tree.delete(item)
            
            # Get recent scans
            all_scans = db.get_all_scan_results()
            
            # Add scans to treeview (limit to 20 most recent)
            for scan in all_scans[:20]:
                target = scan.get('target', 'Unknown')
                scan_time = scan.get('scan_time', 'Unknown')
                vulns = scan.get('total_vulnerabilities', 0)
                status = scan.get('scan_status', 'Unknown')
                
                # Format time for display
                try:
                    if scan_time != 'Unknown':
                        dt = datetime.fromisoformat(scan_time.replace('Z', '+00:00'))
                        display_time = dt.strftime('%Y-%m-%d %H:%M')
                    else:
                        display_time = 'Unknown'
                except:
                    display_time = scan_time
                
                self.recent_scans_tree.insert("", "end", values=(target, display_time, vulns, status))
                
        except Exception as e:
            print(f"Error updating recent scans: {e}")
    
    def show_db_info(self):
        """Show database information dialog"""
        if not self.db_connected or not self.db_password:
            self.show_error("Please connect to database first")
            return
        
        try:
            with Database(password=self.db_password) as db:
                summary = db.get_scan_summary()
                
                info_text = f"""
CapScan Database Information
{'='*40}

Total Scans: {summary.get('total_scans', 0)}
Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}

Severity Distribution:
  High: {summary.get('high_severity', 0)}
  Medium: {summary.get('medium_severity', 0)}
  Low: {summary.get('low_severity', 0)}
  Unknown: {summary.get('unknown_severity', 0)}

Database File: capscan.db
Encryption: SQLCipher3 (AES-256)
Status: Connected
"""
                
                self.show_info(info_text)
                
        except Exception as e:
            self.show_error(f"Error accessing database: {str(e)}")
        
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()

# Main execution
# if __name__ == "__main__":
#     app = CapScanGUI()
#     app.run()