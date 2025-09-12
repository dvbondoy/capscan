import tkinter as tk
from tkinter import simpledialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import threading
import json
import os
from datetime import datetime
from engine import Scanner
from database import Database
from ai_service import AIService
from compliance.analyzers import ComplianceAnalyzer
from compliance.frameworks import ComplianceStandard
from mitigation.engine import MitigationEngine

class CapScanGUI:
    def __init__(self, db_password=None):
        # Initialize ttkbootstrap with flatly theme
        self.root = ttk.Window(themename="flatly")
        self.root.title("CapScan - Vulnerability Scanner")
        # Prefer maximizing the window on start; keep a sensible minimum size
        self.root.minsize(1000, 700)
        try:
            self.root.state('zoomed')  # Works on Windows and some Linux WMs
        except Exception:
            # Fallback for environments that don't support 'zoomed'
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()
            self.root.geometry(f"{screen_width}x{screen_height}+0+0")
        
        # Initialize scanner
        self.scanner = Scanner()
        self.scan_thread = None
        self.is_scanning = False
        
        # Initialize AI services using tgpt CLI backend
        self.ai_service = AIService(backend="tgpt")
        self.compliance_analyzers = {
            'PH_DPA': ComplianceAnalyzer(ComplianceStandard.PH_DPA)
        }
        self.mitigation_engine = MitigationEngine()
        
        # Database variables
        self.db_password = db_password
        self.scan_id = None
        self.db_connected = bool(db_password)
        
        # AI analysis results
        self.ai_analysis_results = {}
        self.compliance_results = {}
        self.mitigation_plan = {}
        
        # Create GUI elements
        self.create_widgets()
        self.setup_layout()
        self.update_db_status_ui()
        
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
        
        # AI Analysis options
        self.ai_analysis_var = tk.BooleanVar(value=True)
        self.ai_analysis_check = ttk.Checkbutton(
            self.options_frame, 
            text="Enable AI Analysis", 
            variable=self.ai_analysis_var
        )
        
        self.compliance_analysis_var = tk.BooleanVar(value=True)
        self.compliance_analysis_check = ttk.Checkbutton(
            self.options_frame, 
            text="Enable Compliance Analysis", 
            variable=self.compliance_analysis_var
        )
        
        self.mitigation_recommendations_var = tk.BooleanVar(value=True)
        self.mitigation_recommendations_check = ttk.Checkbutton(
            self.options_frame, 
            text="Enable Mitigation Recommendations", 
            variable=self.mitigation_recommendations_var
        )
        
        # Database options
        self.db_options_frame = ttk.Frame(self.input_frame)
        self.save_to_db_var = tk.BooleanVar(value=True)
        self.save_to_db_check = ttk.Checkbutton(
            self.db_options_frame, 
            text="Save to Database", 
            variable=self.save_to_db_var
        )
        
        # DB Info button moved to Database Controls in Database tab
        
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
        
        # AI Analysis tab
        self.ai_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.ai_frame, text="AI Analysis")
        
        # Compliance Analysis tab
        self.compliance_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.compliance_frame, text="Compliance")
        
        # Mitigation Recommendations tab
        self.mitigation_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.mitigation_frame, text="Mitigation")
        
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
        self.db_info_btn = ttk.Button(
            self.db_controls_frame, 
            text="DB Info", 
            command=self.show_db_info,
            bootstyle=INFO,
            width=12
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
        
        # AI Analysis tab components
        self.create_ai_analysis_tab()
        
        # Compliance Analysis tab components
        self.create_compliance_analysis_tab()
        
        # Mitigation Recommendations tab components
        self.create_mitigation_tab()
        
        # Bind events
        self.vulns_tree.bind("<<TreeviewSelect>>", self.on_vuln_select)
        self.ports_entry.bind("<KeyRelease>", self.on_port_entry_change)
        
        # Check AI service status after all tabs are created
        self.check_ai_service_status()
        
        # Initialize database info display handled by update_db_status_ui()
    
    def create_ai_analysis_tab(self):
        """Create AI Analysis tab components"""
        # AI Analysis controls
        self.ai_controls_frame = ttk.LabelFrame(self.ai_frame, text="AI Analysis Controls", padding="10")
        
        self.ai_status_label = ttk.Label(self.ai_controls_frame, text="AI Service: Checking...")
        self.ai_analyze_btn = ttk.Button(
            self.ai_controls_frame, 
            text="Run AI Analysis", 
            command=self.run_ai_analysis,
            bootstyle=SUCCESS,
            width=15,
            state=DISABLED
        )
        
        # AI Analysis results
        self.ai_results_frame = ttk.LabelFrame(self.ai_frame, text="AI Analysis Results", padding="10")
        self.ai_results_text = tk.Text(
            self.ai_results_frame, 
            height=15, 
            width=80, 
            font=("Consolas", 9),
            wrap=tk.WORD
        )
        self.ai_results_scrollbar = ttk.Scrollbar(self.ai_results_frame, orient=VERTICAL, command=self.ai_results_text.yview)
        self.ai_results_text.configure(yscrollcommand=self.ai_results_scrollbar.set)
        
        # Layout AI Analysis tab
        self.ai_controls_frame.pack(fill=X, pady=(0, 10))
        self.ai_status_label.pack(side=LEFT, padx=(0, 10))
        self.ai_analyze_btn.pack(side=LEFT)
        
        self.ai_results_frame.pack(fill=BOTH, expand=True)
        self.ai_results_text.pack(side=LEFT, fill=BOTH, expand=True)
        self.ai_results_scrollbar.pack(side=RIGHT, fill=Y)
    
    def create_compliance_analysis_tab(self):
        """Create Compliance Analysis tab components"""
        # Compliance controls
        self.compliance_controls_frame = ttk.LabelFrame(self.compliance_frame, text="Compliance Analysis Controls", padding="10")
        
        self.compliance_standard_label = ttk.Label(self.compliance_controls_frame, text="Standard:")
        self.compliance_standard_var = tk.StringVar(value="PH_DPA")
        self.compliance_standard_combo = ttk.Combobox(
            self.compliance_controls_frame,
            textvariable=self.compliance_standard_var,
            values=["PH_DPA"],
            state="readonly",
            width=15
        )
        
        self.compliance_analyze_btn = ttk.Button(
            self.compliance_controls_frame, 
            text="Run Compliance Analysis", 
            command=self.run_compliance_analysis,
            bootstyle=SUCCESS,
            width=20,
            state=DISABLED
        )
        
        # Compliance results
        self.compliance_results_frame = ttk.LabelFrame(self.compliance_frame, text="Compliance Analysis Results", padding="10")
        self.compliance_results_text = tk.Text(
            self.compliance_results_frame, 
            height=15, 
            width=80, 
            font=("Consolas", 9),
            wrap=tk.WORD
        )
        self.compliance_results_scrollbar = ttk.Scrollbar(self.compliance_results_frame, orient=VERTICAL, command=self.compliance_results_text.yview)
        self.compliance_results_text.configure(yscrollcommand=self.compliance_results_scrollbar.set)
        
        # Layout Compliance Analysis tab
        self.compliance_controls_frame.pack(fill=X, pady=(0, 10))
        self.compliance_standard_label.pack(side=LEFT, padx=(0, 5))
        self.compliance_standard_combo.pack(side=LEFT, padx=(0, 10))
        self.compliance_analyze_btn.pack(side=LEFT)
        
        self.compliance_results_frame.pack(fill=BOTH, expand=True)
        self.compliance_results_text.pack(side=LEFT, fill=BOTH, expand=True)
        self.compliance_results_scrollbar.pack(side=RIGHT, fill=Y)
    
    def create_mitigation_tab(self):
        """Create Mitigation Recommendations tab components"""
        # Mitigation controls
        self.mitigation_controls_frame = ttk.LabelFrame(self.mitigation_frame, text="Mitigation Controls", padding="10")
        
        self.mitigation_generate_btn = ttk.Button(
            self.mitigation_controls_frame, 
            text="Generate Mitigation Plan", 
            command=self.generate_mitigation_plan,
            bootstyle=SUCCESS,
            width=20,
            state=DISABLED
        )
        
        # Mitigation recommendations tree
        self.mitigation_tree_frame = ttk.Frame(self.mitigation_frame)
        self.mitigation_tree = ttk.Treeview(
            self.mitigation_tree_frame,
            columns=("Priority", "Title", "Timeline", "Effort", "Status"),
            show="headings",
            height=10
        )
        
        # Configure mitigation tree columns
        self.mitigation_tree.heading("Priority", text="Priority")
        self.mitigation_tree.heading("Title", text="Title")
        self.mitigation_tree.heading("Timeline", text="Timeline")
        self.mitigation_tree.heading("Effort", text="Effort")
        self.mitigation_tree.heading("Status", text="Status")
        
        self.mitigation_tree.column("Priority", width=80)
        self.mitigation_tree.column("Title", width=300)
        self.mitigation_tree.column("Timeline", width=100)
        self.mitigation_tree.column("Effort", width=80)
        self.mitigation_tree.column("Status", width=100)
        
        self.mitigation_tree_scrollbar = ttk.Scrollbar(self.mitigation_tree_frame, orient=VERTICAL, command=self.mitigation_tree.yview)
        self.mitigation_tree.configure(yscrollcommand=self.mitigation_tree_scrollbar.set)
        
        # Mitigation details
        self.mitigation_details_frame = ttk.LabelFrame(self.mitigation_frame, text="Mitigation Details", padding="5")
        self.mitigation_details_text = tk.Text(
            self.mitigation_details_frame, 
            height=8, 
            width=80, 
            font=("Consolas", 9),
            wrap=tk.WORD
        )
        self.mitigation_details_scrollbar = ttk.Scrollbar(self.mitigation_details_frame, orient=VERTICAL, command=self.mitigation_details_text.yview)
        self.mitigation_details_text.configure(yscrollcommand=self.mitigation_details_scrollbar.set)
        
        # Layout Mitigation tab
        self.mitigation_controls_frame.pack(fill=X, pady=(0, 10))
        self.mitigation_generate_btn.pack(side=LEFT)
        
        self.mitigation_tree_frame.pack(fill=BOTH, expand=True, pady=(0, 10))
        self.mitigation_tree.pack(side=LEFT, fill=BOTH, expand=True)
        self.mitigation_tree_scrollbar.pack(side=RIGHT, fill=Y)
        
        self.mitigation_details_frame.pack(fill=X)
        self.mitigation_details_text.pack(side=LEFT, fill=BOTH, expand=True)
        self.mitigation_details_scrollbar.pack(side=RIGHT, fill=Y)
        
        # Bind mitigation tree selection
        self.mitigation_tree.bind("<<TreeviewSelect>>", self.on_mitigation_select)
        
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
        
        # AI options (second row)
        self.ai_options_frame = ttk.Frame(self.input_frame)
        self.ai_options_frame.grid(row=3, column=0, columnspan=3, sticky=W, pady=5)
        self.ai_analysis_check.pack(side=LEFT, padx=(0, 20))
        self.compliance_analysis_check.pack(side=LEFT, padx=(0, 20))
        self.mitigation_recommendations_check.pack(side=LEFT)
        
        # Database options
        self.db_options_frame.grid(row=4, column=0, columnspan=3, sticky=W, pady=5)
        self.save_to_db_check.pack(side=LEFT, padx=(0, 20))
        
        # Scan buttons
        self.scan_buttons_frame.grid(row=5, column=0, columnspan=3, pady=10)
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
        self.db_refresh_btn.pack(side=LEFT, padx=(5, 5))
        self.db_info_btn.pack(side=LEFT)
        
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
        
        # Enable AI features if scan results are available
        if self.scanner.scan_results:
            self.ai_analyze_btn.config(state=NORMAL)
            self.compliance_analyze_btn.config(state=NORMAL)
            self.mitigation_generate_btn.config(state=NORMAL)
        
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
            if not self.db_connected or not self.db_password:
                self.show_error("Please connect to database first")
                return
            
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
            # If no password stored (shouldn't happen after gated startup), prompt
            if not self.db_password:
                pwd = simpledialog.askstring(title="Database Authentication", prompt="Enter database password:", show="*", parent=self.root)
                if not pwd:
                    self.show_error("Please enter database password")
                    return
                self.db_password = pwd
            
            # Test connection
            with Database(password=self.db_password) as db:
                self.db_connected = True
                self.db_status_label.config(text="Status: Connected")
                self.db_connect_btn.config(text="Disconnect from DB", bootstyle=DANGER)
                self.db_refresh_btn.config(state=NORMAL)
                self.show_info("Successfully connected to database")
                
                # Refresh database info
                self.refresh_db_info()
                self.update_db_status_ui()
                
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
        self.update_db_status_ui()
        
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
    
    def update_db_status_ui(self):
        """Update the Database tab UI to reflect current connection status."""
        if self.db_connected and self.db_password:
            self.db_status_label.config(text="Status: Connected")
            self.db_connect_btn.config(text="Disconnect from DB", bootstyle=DANGER)
            self.db_refresh_btn.config(state=NORMAL)
            # Populate info if empty
            if not self.db_info_text.get("1.0", tk.END).strip() or "disconnected" in self.db_info_text.get("1.0", tk.END).lower():
                self.refresh_db_info()
        else:
            self.db_status_label.config(text="Status: Disconnected")
            self.db_connect_btn.config(text="Connect to DB", bootstyle=SUCCESS)
            self.db_refresh_btn.config(state=DISABLED)
            if not self.db_info_text.get("1.0", tk.END).strip():
                self.db_info_text.insert(1.0, "Database disconnected. Click 'Connect to DB' to connect.")

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
    
    # AI-related methods
    def check_ai_service_status(self):
        """Check AI service status and update UI"""
        try:
            status = self.ai_service.get_service_status()
            if status['ai_available']:
                backend = status['active_backend']
                if backend == 'mock':
                    self.ai_status_label.config(text=f"AI Service: Available ({backend} - No API key needed)", bootstyle=SUCCESS)
                else:
                    self.ai_status_label.config(text=f"AI Service: Available ({backend})", bootstyle=SUCCESS)
                self.ai_analyze_btn.config(state=NORMAL)
                self.compliance_analyze_btn.config(state=NORMAL)
                self.mitigation_generate_btn.config(state=NORMAL)
            else:
                self.ai_status_label.config(text="AI Service: Unavailable", bootstyle=WARNING)
                self.ai_analyze_btn.config(state=DISABLED)
                self.compliance_analyze_btn.config(state=DISABLED)
                self.mitigation_generate_btn.config(state=DISABLED)
        except Exception as e:
            self.ai_status_label.config(text=f"AI Service: Error - {str(e)}", bootstyle=DANGER)
            self.ai_analyze_btn.config(state=DISABLED)
            self.compliance_analyze_btn.config(state=DISABLED)
            self.mitigation_generate_btn.config(state=DISABLED)
    
    def run_ai_analysis(self):
        """Run AI analysis on scan results"""
        if not self.scanner.scan_results:
            self.show_error("No scan results available. Please run a scan first.")
            return
        
        try:
            self.ai_analyze_btn.config(state=DISABLED, text="Analyzing...")
            self.ai_results_text.delete(1.0, tk.END)
            self.ai_results_text.insert(1.0, "Running AI analysis... Please wait.\n")
            self.root.update()
            
            # Run AI analysis
            analysis = self.ai_service.analyze_vulnerabilities(self.scanner.scan_results)
            self.ai_analysis_results = analysis
            
            # Display results
            self.display_ai_analysis_results(analysis)
            
            # Save to database if connected
            if self.db_connected and self.scan_id:
                self.save_ai_analysis_to_db(analysis)
            
        except Exception as e:
            self.show_error(f"AI analysis failed: {str(e)}")
        finally:
            self.ai_analyze_btn.config(state=NORMAL, text="Run AI Analysis")
    
    def display_ai_analysis_results(self, analysis):
        """Display AI analysis results in the text widget"""
        self.ai_results_text.delete(1.0, tk.END)
        
        if 'error' in analysis:
            self.ai_results_text.insert(1.0, f"Error: {analysis['error']}\n")
            return
        
        # Format analysis results
        result_text = "AI Vulnerability Analysis Results\n"
        result_text += "=" * 50 + "\n\n"
        
        if 'risk_assessment' in analysis:
            risk = analysis['risk_assessment']
            result_text += f"Overall Risk Level: {risk.get('overall_risk_level', 'Unknown')}\n"
            result_text += f"Business Impact: {risk.get('business_impact', 'N/A')}\n"
            result_text += f"Exploitability: {risk.get('exploitability', 'N/A')}\n\n"
            
            if 'critical_vulnerabilities' in risk:
                result_text += "Critical Vulnerabilities:\n"
                for vuln in risk['critical_vulnerabilities']:
                    result_text += f"  - {vuln}\n"
                result_text += "\n"
            
            if 'high_risk_vulnerabilities' in risk:
                result_text += "High Risk Vulnerabilities:\n"
                for vuln in risk['high_risk_vulnerabilities']:
                    result_text += f"  - {vuln}\n"
                result_text += "\n"
        
        if 'vulnerability_analysis' in analysis:
            result_text += "Enhanced Vulnerability Analysis:\n"
            result_text += "-" * 30 + "\n"
            for vuln in analysis['vulnerability_analysis'][:5]:  # Show first 5
                result_text += f"CVE: {vuln.get('cve_id', 'N/A')}\n"
                result_text += f"  Enhanced Score: {vuln.get('enhanced_score', 'N/A')}\n"
                result_text += f"  Risk Factors: {', '.join(vuln.get('risk_factors', []))}\n"
                result_text += f"  Business Impact: {vuln.get('business_impact', 'N/A')}\n"
                result_text += f"  Exploit Likelihood: {vuln.get('exploit_likelihood', 'N/A')}\n"
                result_text += f"  Remediation Priority: {vuln.get('remediation_priority', 'N/A')}\n\n"
        
        if 'recommendations' in analysis:
            rec = analysis['recommendations']
            result_text += "AI Recommendations:\n"
            result_text += "-" * 20 + "\n"
            
            if 'immediate_actions' in rec:
                result_text += "Immediate Actions:\n"
                for action in rec['immediate_actions']:
                    result_text += f"  - {action}\n"
                result_text += "\n"
            
            if 'short_term_goals' in rec:
                result_text += "Short-term Goals:\n"
                for goal in rec['short_term_goals']:
                    result_text += f"  - {goal}\n"
                result_text += "\n"
            
            if 'long_term_strategy' in rec:
                result_text += f"Long-term Strategy: {rec['long_term_strategy']}\n"
        
        if 'raw_analysis' in analysis:
            result_text += "\nRaw AI Analysis:\n"
            result_text += "-" * 20 + "\n"
            result_text += analysis['raw_analysis']
        
        self.ai_results_text.insert(1.0, result_text)
    
    def run_compliance_analysis(self):
        """Run compliance analysis on scan results"""
        if not self.scanner.scan_results:
            self.show_error("No scan results available. Please run a scan first.")
            return
        
        try:
            standard = self.compliance_standard_var.get()
            self.compliance_analyze_btn.config(state=DISABLED, text="Analyzing...")
            self.compliance_results_text.delete(1.0, tk.END)
            self.compliance_results_text.insert(1.0, f"Running {standard} compliance analysis... Please wait.\n")
            self.root.update()
            
            # Run compliance analysis
            analyzer = self.compliance_analyzers[standard]
            results = analyzer.analyze_scan_results(self.scanner.scan_results)
            self.compliance_results[standard] = results
            
            # Display results
            self.display_compliance_results(results, standard)
            
            # Save to database if connected
            if self.db_connected and self.scan_id:
                self.save_compliance_analysis_to_db(results, standard)
            
        except Exception as e:
            self.show_error(f"Compliance analysis failed: {str(e)}")
        finally:
            self.compliance_analyze_btn.config(state=NORMAL, text="Run Compliance Analysis")
    
    def display_compliance_results(self, results, standard):
        """Display compliance analysis results"""
        self.compliance_results_text.delete(1.0, tk.END)
        
        # Build a plain-language summary first
        friendly_text = self._format_compliance_results_plain_language(results, standard)
        
        # Optional short technical appendix for users who want details
        technical_text = "\n\nTechnical details (for IT teams)\n" + ("-" * 34) + "\n"
        technical_text += f"Score: {results.get('compliance_score', 'N/A')}/100 | Status: {results.get('status', 'N/A').replace('_', ' ').title()}\n"
        technical_text += f"Total Vulnerabilities: {results.get('total_vulnerabilities', 0)}\n\n"
        technical_text += "Violation counts by severity:\n"
        technical_text += f"  Critical: {results.get('critical_violations', 0)}\n"
        technical_text += f"  High: {results.get('high_violations', 0)}\n"
        technical_text += f"  Medium: {results.get('medium_violations', 0)}\n"
        technical_text += f"  Low: {results.get('low_violations', 0)}\n\n"
        
        if 'violations' in results and results['violations']:
            technical_text += "Top violations:\n"
            for i, violation in enumerate(results['violations'][:5], 1):
                technical_text += f"{i}. {violation.get('vulnerability_id', 'N/A')} | Severity: {violation.get('severity', 'N/A')}\n"
                desc = violation.get('description', 'N/A')
                if isinstance(desc, str):
                    desc_display = desc[:160] + ("..." if len(desc) > 160 else "")
                else:
                    desc_display = 'N/A'
                technical_text += f"   {desc_display}\n"
                technical_text += f"   Violated requirements: {len(violation.get('violated_requirements', []))}\n"
            technical_text += "\n"
        
        if 'recommendations' in results and results['recommendations']:
            technical_text += "Top recommendations:\n"
            for i, rec in enumerate(results['recommendations'][:5], 1):
                technical_text += f"{i}. {rec.get('title', 'N/A')} | Priority: {rec.get('priority', 'N/A')} | Timeline: {rec.get('timeline', 'N/A')} | Effort: {rec.get('effort', 'N/A')}\n"
        
        final_text = friendly_text + technical_text
        self.compliance_results_text.insert(1.0, final_text)

    def _format_compliance_results_plain_language(self, results, standard):
        """Return a plain-language summary of compliance results for non-technical users."""
        # Map status to readable explanations
        status_raw = results.get('status', 'unknown') or 'unknown'
        status_clean = str(status_raw).replace('_', ' ').title()
        status_explainer_map = {
            'Compliant': 'You meet the important requirements for this standard.',
            'Partially Compliant': 'You meet some requirements, but a few areas need attention.',
            'Non Compliant': 'Important requirements are not met. Action is needed to reduce risk.',
            'Unknown': 'We could not determine overall compliance from this scan.'
        }
        status_explainer = status_explainer_map.get(status_clean, 'Current compliance needs review.')
        
        score = results.get('compliance_score')
        if isinstance(score, (int, float)):
            score_str = f"{score}/100"
            if score >= 85:
                score_msg = "Strong overall posture. Keep maintaining controls."
            elif score >= 70:
                score_msg = "Moderate posture. Address the highlighted items to improve."
            elif score >= 50:
                score_msg = "Needs improvement. Prioritize the recommended actions."
            else:
                score_msg = "High risk exposure. Immediate action is recommended."
        else:
            score_str = "N/A"
            score_msg = "Score not available from this scan."
        
        crit = results.get('critical_violations', 0)
        high = results.get('high_violations', 0)
        med = results.get('medium_violations', 0)
        low = results.get('low_violations', 0)
        total_issues = sum(v for v in [crit, high, med, low] if isinstance(v, int))
        
        # Headline
        text = f"{standard} Compliance Overview\n" + ("=" * 50) + "\n\n"
        text += f"Overall status: {status_clean}\n"
        text += f"What this means: {status_explainer}\n\n"
        text += f"Compliance score: {score_str}\n"
        text += f"Quick take: {score_msg}\n\n"
        
        # Simple issue summary
        text += "Issue summary (the higher the severity, the more urgent):\n"
        text += f"- Critical issues: {crit}\n"
        text += f"- High issues: {high}\n"
        text += f"- Medium issues: {med}\n"
        text += f"- Low issues: {low}\n"
        text += f"Total areas to review: {total_issues}\n\n"
        
        # Top 3 practical actions
        text += "Top recommended actions (start here):\n"
        actions_added = 0
        if 'recommendations' in results and isinstance(results['recommendations'], list) and results['recommendations']:
            for rec in results['recommendations']:
                if actions_added >= 3:
                    break
                title = rec.get('title', 'Recommended improvement')
                timeline = rec.get('timeline', 'As soon as practical')
                priority = rec.get('priority', 'Medium')
                text += f"- {title} (Priority: {priority}, Timeline: {timeline})\n"
                actions_added += 1
        if actions_added == 0:
            text += "- No specific actions generated. Re-run analysis or consult your IT team.\n"
        
        text += "\n"
        
        # Plain description of a few notable violations
        if 'violations' in results and isinstance(results['violations'], list) and results['violations']:
            text += "A few notable findings in everyday terms:\n"
            for v in results['violations'][:3]:
                sev = v.get('severity', 'Unknown')
                desc = v.get('description', 'No description available')
                if isinstance(desc, str):
                    desc_simple = desc.split('\n')[0]
                    if len(desc_simple) > 140:
                        desc_simple = desc_simple[:140] + '...'
                else:
                    desc_simple = 'No description available'
                text += f"- {sev} issue: {desc_simple}\n"
            text += "\n"
        
        text += "Note: This view avoids technical jargon and focuses on business impact and next steps.\n"
        return text
    
    def generate_mitigation_plan(self):
        """Generate mitigation plan for scan results"""
        if not self.scanner.scan_results:
            self.show_error("No scan results available. Please run a scan first.")
            return
        
        try:
            self.mitigation_generate_btn.config(state=DISABLED, text="Generating...")
            self.mitigation_tree.delete(*self.mitigation_tree.get_children())
            self.mitigation_details_text.delete(1.0, tk.END)
            self.mitigation_details_text.insert(1.0, "Generating mitigation plan... Please wait.\n")
            self.root.update()
            
            # Generate mitigation plan
            plan = self.mitigation_engine.generate_mitigation_plan(self.scanner.scan_results)
            self.mitigation_plan = plan
            
            # Display results
            self.display_mitigation_plan(plan)
            
            # Save to database if connected
            if self.db_connected and self.scan_id:
                self.save_mitigation_plan_to_db(plan)
            
        except Exception as e:
            self.show_error(f"Mitigation plan generation failed: {str(e)}")
        finally:
            self.mitigation_generate_btn.config(state=NORMAL, text="Generate Mitigation Plan")
    
    def display_mitigation_plan(self, plan):
        """Display mitigation plan in the tree and details"""
        self.mitigation_tree.delete(*self.mitigation_tree.get_children())
        self.mitigation_details_text.delete(1.0, tk.END)
        
        if not plan or 'mitigation_plan' not in plan:
            self.mitigation_details_text.insert(1.0, "No mitigation recommendations available.")
            return
        
        # Display summary
        summary = plan.get('summary', {})
        summary_text = f"Mitigation Plan Summary\n"
        summary_text += "=" * 25 + "\n\n"
        summary_text += f"Total Recommendations: {summary.get('total_recommendations', 0)}\n"
        summary_text += f"Critical Actions: {summary.get('critical_actions', 0)}\n"
        summary_text += f"High Actions: {summary.get('high_actions', 0)}\n"
        summary_text += f"Medium Actions: {summary.get('medium_actions', 0)}\n"
        summary_text += f"Low Actions: {summary.get('low_actions', 0)}\n"
        summary_text += f"Estimated Timeline: {summary.get('estimated_timeline', 'N/A')}\n"
        summary_text += f"Overall Effort: {summary.get('overall_effort', 'N/A')}\n\n"
        
        self.mitigation_details_text.insert(1.0, summary_text)
        
        # Add recommendations to tree
        for rec in plan['mitigation_plan']:
            for recommendation in rec.get('recommendations', []):
                self.mitigation_tree.insert("", "end", values=(
                    rec.get('priority', 'N/A'),
                    rec.get('title', 'N/A'),
                    recommendation.get('timeline', 'N/A'),
                    rec.get('estimated_effort', 'N/A'),
                    'Pending'
                ))
    
    def on_mitigation_select(self, event):
        """Handle mitigation recommendation selection"""
        selection = self.mitigation_tree.selection()
        if not selection:
            return
        
        item = self.mitigation_tree.item(selection[0])
        values = item['values']
        
        # Find the corresponding recommendation in the plan
        title = values[1]
        for rec in self.mitigation_plan.get('mitigation_plan', []):
            if rec.get('title') == title:
                details_text = f"Mitigation Recommendation Details\n"
                details_text += "=" * 35 + "\n\n"
                details_text += f"Title: {rec.get('title', 'N/A')}\n"
                details_text += f"Description: {rec.get('description', 'N/A')}\n"
                details_text += f"Priority: {rec.get('priority', 'N/A')}\n"
                details_text += f"Vulnerability Type: {rec.get('vulnerability_type', 'N/A')}\n"
                details_text += f"Host: {rec.get('host_ip', 'N/A')}:{rec.get('port', 'N/A')}\n\n"
                
                details_text += "Recommendations:\n"
                details_text += "-" * 15 + "\n"
                for i, rec_detail in enumerate(rec.get('recommendations', []), 1):
                    details_text += f"{i}. {rec_detail.get('action', 'N/A')}\n"
                    details_text += f"   Timeline: {rec_detail.get('timeline', 'N/A')}\n"
                    details_text += f"   Description: {rec_detail.get('description', 'N/A')}\n"
                    details_text += f"   Difficulty: {rec_detail.get('difficulty', 'N/A')}\n"
                    details_text += f"   Tools Needed: {', '.join(rec_detail.get('tools_needed', []))}\n"
                    details_text += f"   Verification: {rec_detail.get('verification', 'N/A')}\n\n"
                
                if 'verification_steps' in rec:
                    details_text += "Verification Steps:\n"
                    details_text += "-" * 18 + "\n"
                    for i, step in enumerate(rec['verification_steps'], 1):
                        details_text += f"{i}. {step}\n"
                
                if 'resources' in rec:
                    details_text += "\nResources:\n"
                    details_text += "-" * 10 + "\n"
                    for category, items in rec['resources'].items():
                        details_text += f"{category.title()}:\n"
                        for item in items:
                            details_text += f"  - {item}\n"
                
                self.mitigation_details_text.delete(1.0, tk.END)
                self.mitigation_details_text.insert(1.0, details_text)
                break
    
    def save_ai_analysis_to_db(self, analysis):
        """Save AI analysis to database"""
        try:
            with Database(password=self.db_password) as db:
                db.save_ai_analysis(
                    scan_id=self.scan_id,
                    analysis_type="vulnerability_analysis",
                    compliance_score=None,
                    risk_level=analysis.get('risk_assessment', {}).get('overall_risk_level'),
                    analysis_data=analysis
                )
        except Exception as e:
            print(f"Error saving AI analysis to database: {e}")
    
    def save_compliance_analysis_to_db(self, results, standard):
        """Save compliance analysis to database"""
        try:
            with Database(password=self.db_password) as db:
                db.save_ai_analysis(
                    scan_id=self.scan_id,
                    analysis_type="compliance",
                    standard=standard,
                    compliance_score=results.get('compliance_score'),
                    risk_level=results.get('status'),
                    analysis_data=results
                )
        except Exception as e:
            print(f"Error saving compliance analysis to database: {e}")
    
    def save_mitigation_plan_to_db(self, plan):
        """Save mitigation plan to database"""
        try:
            with Database(password=self.db_password) as db:
                recommendations = []
                for rec in plan.get('mitigation_plan', []):
                    for recommendation in rec.get('recommendations', []):
                        recommendations.append({
                            'vulnerability_id': rec.get('vulnerability_id', ''),
                            'recommendation_type': recommendation.get('timeline', ''),
                            'priority': rec.get('priority', ''),
                            'title': rec.get('title', ''),
                            'description': rec.get('description', ''),
                            'steps': [rec_detail.get('action', '') for rec_detail in rec.get('recommendations', [])],
                            'resources': rec.get('resources', {}),
                            'estimated_effort': rec.get('estimated_effort', ''),
                            'status': 'pending',
                            'due_date': recommendation.get('timeline', '')
                        })
                
                if recommendations:
                    db.save_mitigation_recommendations(self.scan_id, recommendations)
        except Exception as e:
            print(f"Error saving mitigation plan to database: {e}")
        
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()

# Main execution
# if __name__ == "__main__":
#     app = CapScanGUI()
#     app.run()