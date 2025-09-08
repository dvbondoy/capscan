#!/usr/bin/env python3
"""
CapScan - Vulnerability Scanner
A comprehensive vulnerability scanner using nmap with vulners NSE script.

Usage:
    python main.py                    # Launch GUI
    python main.py --gui              # Launch GUI
    python main.py --cli              # Command line interface
    python main.py --help             # Show help
    python main.py --scan <target>    # Quick scan
"""

import argparse
import json
import sys
import os
from datetime import datetime
from engine import Scanner
from database import Database

def print_banner():
    """Print CapScan banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                    CapScan Vulnerability Scanner             ║
    ║                                                              ║
    ║  A comprehensive vulnerability scanner using nmap with      ║
    ║  vulners NSE script and keyword-based scoring system        ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def run_gui():
    """Launch the GUI interface"""
    try:
        from gui import CapScanGUI
        import tkinter as tk
        from tkinter import simpledialog, messagebox
        from database import Database

        # Prompt for DB password before launching main window
        print("Launching CapScan GUI...")
        password = None
        while True:
            # Create a minimal hidden root just for dialogs
            root = tk.Tk()
            root.withdraw()

            password = simpledialog.askstring(
                title="Database Authentication",
                prompt="Enter database password:",
                show="*",
                parent=root
            )

            if password is None:
                root.destroy()
                print("Database password entry cancelled. Exiting.")
                sys.exit(1)

            try:
                # Verify password by attempting a connection
                with Database(password=password) as _db:
                    pass
                root.destroy()
                break
            except Exception as e:
                messagebox.showerror("Authentication Failed", f"Invalid password or DB error.\n{e}", parent=root)
                root.destroy()
                continue

        # Launch main application with verified password
        app = CapScanGUI(db_password=password)
        app.run()
    except ImportError as e:
        print(f"Error: Could not import GUI module: {e}")
        print("Make sure ttkbootstrap is installed: pip install ttkbootstrap")
        sys.exit(1)
    except Exception as e:
        print(f"Error launching GUI: {e}")
        sys.exit(1)

def run_cli_scan(target, ports="22,80,443", max_reports=10, enhance_scores=True, save_files=True, save_to_db=True, db_password=None):
    """Run command line vulnerability scan"""
    print_banner()
    
    # Create scanner instance
    scanner = Scanner()
    
    print(f"Starting vulnerability scan for target: {target}")
    print(f"Port range: {ports}")
    print(f"Max reports per port: {max_reports}")
    print(f"Keyword-based scoring: {'Enabled' if enhance_scores else 'Disabled'}")
    print(f"Save to database: {'Enabled' if save_to_db else 'Disabled'}")
    print("-" * 60)
    
    try:
        # Perform scan
        vulners_args = f"--script-args vulners.maxreports={max_reports}"
        results = scanner.scan_host(target, ports, vulners_args)
        
        if 'error' in results:
            print(f"❌ Scan failed: {results['error']}")
            return False
        
        print(f"✅ Scan completed successfully!")
        print(f"Found {len(scanner.vulnerabilities)} vulnerabilities")
        
        # Enhance with scores if enabled
        if enhance_scores:
            print("\n🔍 Enhancing vulnerabilities with keyword-based scoring...")
            enhanced_count = scanner.enhance_vulnerabilities_with_scores()
            print(f"✅ Enhanced {enhanced_count} vulnerabilities with scores")
        
        # Save to database if enabled
        scan_id = None
        if save_to_db:
            try:
                print("\n💾 Saving scan results to database...")
                with Database(password=db_password) as db:
                    scan_id = db.save_scan_results(results)
                    print(f"✅ Scan results saved to database with ID: {scan_id}")
            except KeyboardInterrupt:
                print("\n⚠️  Database password prompt cancelled by user")
                print("Continuing with file-based saving...")
            except Exception as e:
                print(f"❌ Error saving to database: {e}")
                print("Continuing with file-based saving...")
        
        # Display scoring statistics
        stats = scanner.get_scoring_statistics()
        print(f"\n📊 Scoring Statistics:")
        print(f"  Total vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
        print(f"  Scored vulnerabilities: {stats.get('scored_vulnerabilities', 0)}")
        print(f"  High severity: {stats.get('high_severity', 0)}")
        print(f"  Medium severity: {stats.get('medium_severity', 0)}")
        print(f"  Low severity: {stats.get('low_severity', 0)}")
        print(f"  Scoring coverage: {stats.get('scoring_coverage', 0):.1f}%")
        
        # Print summary
        scanner.print_summary()
        
        # Display vulnerabilities
        vulnerabilities = scanner.get_vulnerabilities()
        if vulnerabilities:
            print("\n" + "="*80)
            print("VULNERABILITIES FOUND")
            print("="*80)
            
            for i, vuln in enumerate(vulnerabilities, 1):
                cve_id = vuln.get('cve_id', 'N/A')
                score = vuln.get('score', 'N/A')
                description = vuln.get('description', 'N/A')
                
                # Determine severity
                if score == 'N/A' or score is None:
                    severity = "Unknown"
                elif score >= 7.0:
                    severity = "🔴 High"
                elif score >= 4.0:
                    severity = "🟡 Medium"
                else:
                    severity = "🟢 Low"
                
                print(f"\n{i}. {cve_id} - {severity} (Score: {score})")
                print(f"   Description: {description}")
                if vuln.get('raw_output'):
                    print(f"   Raw Output: {vuln.get('raw_output')}")
                print("-" * 60)
        else:
            print("\n✅ No vulnerabilities found!")
        
        # Save results if requested
        if save_files:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Save XML
            xml_file = scanner.save_as_xml(f"vuln_scan_{timestamp}.xml")
            print(f"\n💾 Results saved to: {xml_file}")
            
            # Save JSON files
            vuln_file = f"vulnerabilities_{timestamp}.json"
            with open(vuln_file, 'w') as f:
                json.dump(vulnerabilities, f, indent=2)
            print(f"💾 Vulnerabilities saved to: {vuln_file}")
            
            summary_file = f"summary_{timestamp}.json"
            with open(summary_file, 'w') as f:
                json.dump(scanner.get_scan_summary(), f, indent=2)
            print(f"💾 Summary saved to: {summary_file}")
        
        return True
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        return False
    except Exception as e:
        print(f"\n❌ Error during scan: {e}")
        return False

def show_database_info(db_password=None):
    """Show database information and statistics"""
    try:
        with Database(password=db_password) as db:
            summary = db.get_scan_summary()
            print("\n📊 Database Statistics:")
            print(f"  Total scans: {summary.get('total_scans', 0)}")
            print(f"  Total vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
            print(f"  High severity: {summary.get('high_severity', 0)}")
            print(f"  Medium severity: {summary.get('medium_severity', 0)}")
            print(f"  Low severity: {summary.get('low_severity', 0)}")
            print(f"  Unknown severity: {summary.get('unknown_severity', 0)}")
            
            # Show recent scans
            all_scans = db.get_all_scan_results()
            if all_scans:
                print(f"\n📋 Recent Scans (last 5):")
                for i, scan in enumerate(all_scans[:5], 1):
                    print(f"  {i}. {scan.get('target', 'Unknown')} - {scan.get('scan_time', 'Unknown')} - {scan.get('total_vulnerabilities', 0)} vulnerabilities")
            else:
                print("\n📋 No scans found in database")
                
    except KeyboardInterrupt:
        print("\n⚠️  Database password prompt cancelled by user")
    except Exception as e:
        print(f"❌ Error accessing database: {e}")

def interactive_mode():
    """Run interactive command line mode"""
    print_banner()
    print("🔧 Interactive Mode - CapScan Vulnerability Scanner")
    print("=" * 60)
    
    # Get target
    while True:
        target = input("\nEnter target host/IP: ").strip()
        if target:
            break
        print("❌ Please enter a valid target")
    
    # Get port range
    print("\nPort range options:")
    print("1. Quick scan (22,80,443)")
    print("2. Common ports (22,23,25,53,80,110,143,443,993,995,3389,5432,5900,8080)")
    print("3. All ports (1-65535)")
    print("4. Custom range")
    
    while True:
        choice = input("\nSelect option (1-4): ").strip()
        if choice == "1":
            ports = "22,80,443"
            break
        elif choice == "2":
            ports = "22,23,25,53,80,110,143,443,993,995,3389,5432,5900,8080"
            break
        elif choice == "3":
            ports = "1-65535"
            break
        elif choice == "4":
            ports = input("Enter custom port range: ").strip()
            if ports:
                break
            print("❌ Please enter a valid port range")
        else:
            print("❌ Please select 1-4")
    
    # Get max reports
    while True:
        try:
            max_reports = int(input("\nMax reports per port (1-100, default 10): ").strip() or "10")
            if 1 <= max_reports <= 100:
                break
            print("❌ Please enter a number between 1 and 100")
        except ValueError:
            print("❌ Please enter a valid number")
    
    # Get scoring preference
    enhance_scores = input("\nEnable keyword-based scoring? (y/n, default y): ").strip().lower()
    enhance_scores = enhance_scores != 'n'
    
    # Get save preference
    save_files = input("\nSave results to files? (y/n, default y): ").strip().lower()
    save_files = save_files != 'n'
    
    # Get database save preference
    save_to_db = input("\nSave results to database? (y/n, default y): ").strip().lower()
    save_to_db = save_to_db != 'n'
    
    print(f"\n🚀 Starting scan with configuration:")
    print(f"   Target: {target}")
    print(f"   Ports: {ports}")
    print(f"   Max reports: {max_reports}")
    print(f"   Keyword scoring: {'Enabled' if enhance_scores else 'Disabled'}")
    print(f"   Save files: {'Yes' if save_files else 'No'}")
    print(f"   Save to database: {'Yes' if save_to_db else 'No'}")
    
    # Run the scan
    return run_cli_scan(target, ports, max_reports, enhance_scores, save_files, save_to_db, None)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="CapScan - Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                          # Launch GUI
  python main.py --gui                    # Launch GUI
  python main.py --cli                    # Interactive CLI mode
  python main.py --scan 192.168.1.1      # Quick scan (will prompt for DB password)
  python main.py --scan 192.168.1.1 --ports "22,80,443" --max-reports 20
  python main.py --scan 192.168.1.1 --all-ports --no-scoring
  python main.py --scan 192.168.1.1 --no-db --no-save  # Scan without saving
  python main.py --scan 192.168.1.1 --db-password "mypass"  # Scan with DB password
  python main.py --db-info                # Show database statistics (will prompt for password)
  python main.py --db-info --db-password "mypass"  # Show DB stats with password
        """
    )
    
    parser.add_argument('--gui', action='store_true', help='Launch GUI interface')
    parser.add_argument('--cli', action='store_true', help='Launch interactive CLI mode')
    parser.add_argument('--scan', metavar='TARGET', help='Quick scan target host/IP')
    parser.add_argument('--ports', metavar='PORTS', default='22,80,443', 
                       help='Port range (default: 22,80,443)')
    parser.add_argument('--all-ports', action='store_true', 
                       help='Scan all ports (1-65535)')
    parser.add_argument('--max-reports', type=int, default=10, 
                       help='Max reports per port (default: 10)')
    parser.add_argument('--no-scoring', action='store_true', 
                       help='Disable keyword-based scoring')
    parser.add_argument('--no-save', action='store_true', 
                       help='Do not save results to files')
    parser.add_argument('--no-db', action='store_true', 
                       help='Do not save results to database')
    parser.add_argument('--db-info', action='store_true', 
                       help='Show database statistics and recent scans')
    parser.add_argument('--db-password', metavar='PASSWORD', 
                       help='Database password (if not provided, will prompt)')
    parser.add_argument('--version', action='version', version='CapScan 1.0.0')
    
    args = parser.parse_args()
    
    # Handle database info request
    if args.db_info:
        show_database_info(args.db_password)
        sys.exit(0)
    
    # Determine mode
    if args.gui or (not args.cli and not args.scan):
        # Default to GUI if no specific mode requested
        run_gui()
    elif args.cli:
        # Interactive CLI mode
        success = interactive_mode()
        sys.exit(0 if success else 1)
    elif args.scan:
        # Quick scan mode
        target = args.scan
        ports = "1-65535" if args.all_ports else args.ports
        enhance_scores = not args.no_scoring
        save_files = not args.no_save
        save_to_db = not args.no_db
        
        success = run_cli_scan(target, ports, args.max_reports, enhance_scores, save_files, save_to_db, args.db_password)
        sys.exit(0 if success else 1)
    else:
        # Show help
        parser.print_help()

if __name__ == "__main__":
    main()