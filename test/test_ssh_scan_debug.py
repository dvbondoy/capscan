#!/usr/bin/env python3
"""
Test SSH scan with specific credentials to debug the zero vulnerabilities issue.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ssh_scanner import SSHAuthenticatedScanner, SSHCredentials

def test_ssh_scan_with_credentials():
    """Test SSH scan with specific credentials."""
    print("=== SSH Scan Test with 192.168.88.250 ===")
    
    # Create SSH credentials
    credentials = SSHCredentials(
        username="msfadmin",
        password="msfadmin",
        port=22,
        timeout=30
    )
    
    # Create SSH scanner
    ssh_scanner = SSHAuthenticatedScanner()
    
    # Test targets
    targets = ["192.168.88.250"]
    
    print(f"Testing SSH scan with:")
    print(f"  Target: {targets[0]}")
    print(f"  Username: {credentials.username}")
    print(f"  Password: {'*' * len(credentials.password)}")
    print(f"  Port: {credentials.port}")
    print(f"  Timeout: {credentials.timeout}s")
    print()
    
    try:
        # Run SSH scan
        print("Starting SSH scan...")
        results = ssh_scanner.scan_hosts_with_ssh(targets, credentials)
        
        print("\n=== SSH Scan Results ===")
        print(f"Scan completed at: {results.get('scan_time', 'N/A')}")
        print(f"Targets scanned: {len(results.get('hosts', {}))}")
        print(f"Vulnerabilities found: {len(results.get('vulnerabilities', []))}")
        
        # Check host results
        for target, host_info in results.get('hosts', {}).items():
            print(f"\nHost: {target}")
            print(f"  Status: {host_info.get('status', 'unknown')}")
            print(f"  Has system_info: {host_info.get('system_info') is not None}")
            print(f"  Errors: {host_info.get('errors', [])}")
            
            if host_info.get('system_info'):
                sys_info = host_info['system_info']
                print(f"  OS Distro: {sys_info.distro}")
                print(f"  Kernel: {sys_info.kernel_version}")
                print(f"  Architecture: {sys_info.architecture}")
                print(f"  Packages: {len(sys_info.package_list)}")
            else:
                print("  No system information gathered")
        
        # Check vulnerabilities
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"\nVulnerabilities found ({len(vulnerabilities)}):")
            for i, vuln in enumerate(vulnerabilities[:5]):  # Show first 5
                print(f"  {i+1}. {vuln.get('cve_id', 'N/A')} - {vuln.get('description', 'N/A')[:60]}...")
        else:
            print("\nNo vulnerabilities found")
            
        # Get summary
        summary = ssh_scanner.get_scan_summary()
        print(f"\n=== Summary ===")
        print(f"Total hosts: {summary.get('total_hosts', 0)}")
        print(f"Successful scans: {summary.get('successful_scans', 0)}")
        print(f"Failed scans: {summary.get('failed_scans', 0)}")
        print(f"Total vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        
        return len(vulnerabilities) > 0
        
    except Exception as e:
        print(f"Error during SSH scan: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_basic_ssh_connection():
    """Test basic SSH connectivity using nmap."""
    print("\n=== Testing Basic SSH Connectivity ===")
    
    try:
        import nmap
        nm = nmap.PortScanner()
        
        # Test if SSH port is open
        print("Checking if SSH port 22 is open...")
        nm.scan("192.168.88.250", "22")
        
        if "192.168.88.250" in nm.all_hosts():
            host_info = nm["192.168.88.250"]
            print(f"Host is reachable")
            
            if "tcp" in host_info:
                tcp_ports = host_info["tcp"]
                if "22" in tcp_ports:
                    port_22 = tcp_ports["22"]
                    print(f"Port 22 state: {port_22.get('state', 'unknown')}")
                    print(f"Port 22 service: {port_22.get('name', 'unknown')}")
                    print(f"Port 22 version: {port_22.get('version', 'unknown')}")
                else:
                    print("Port 22 not found in scan results")
            else:
                print("No TCP ports found")
        else:
            print("Host 192.168.88.250 is not reachable")
            
    except Exception as e:
        print(f"Error testing SSH connectivity: {e}")

if __name__ == "__main__":
    print("SSH Scan Debug Test")
    print("=" * 50)
    
    # Test basic connectivity first
    test_basic_ssh_connection()
    
    # Test SSH scan
    success = test_ssh_scan_with_credentials()
    
    print(f"\n=== Test Result ===")
    print(f"SSH scan successful: {'✓' if success else '✗'}")
    
    if not success:
        print("\n*** SSH scan failed - this explains why zero vulnerabilities are found ***")
        print("Check the debug output above to see what went wrong.")
