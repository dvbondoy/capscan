#!/usr/bin/env python3
"""
Test script for SSH authenticated scanning functionality.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ssh_scanner import SSHAuthenticatedScanner, SSHCredentials
from ssh_credentials_manager import SSHCredentialsManager
from services.exploitdb_service import ExploitDBService

def test_ssh_scan():
    """Test SSH scan functionality."""
    print("Testing SSH Authenticated Scanner...")
    
    # Initialize services
    exploitdb_service = ExploitDBService()
    ssh_scanner = SSHAuthenticatedScanner(exploitdb_service)
    cred_manager = SSHCredentialsManager()
    
    print(f"ExploitDB loaded: {len(exploitdb_service.exploits_data)} exploits")
    
    # Test credentials (you would replace these with real credentials)
    test_credentials = SSHCredentials(
        username="testuser",
        password="testpass",
        port=22,
        timeout=30
    )
    
    # Test targets (replace with real targets)
    test_targets = ["192.168.1.100"]  # Replace with actual SSH-enabled host
    
    print(f"Testing SSH scan with targets: {test_targets}")
    print("Note: This will only work if you have SSH access to the target hosts")
    
    try:
        # Run SSH scan
        results = ssh_scanner.scan_hosts_with_ssh(test_targets, test_credentials)
        
        # Print results
        print("\nSSH Scan Results:")
        print(f"Total hosts scanned: {len(results.get('hosts', {}))}")
        print(f"Vulnerabilities found: {len(results.get('vulnerabilities', []))}")
        
        # Print summary
        summary = ssh_scanner.get_scan_summary()
        print(f"\nSummary:")
        print(f"  Successful scans: {summary.get('successful_scans', 0)}")
        print(f"  Failed scans: {summary.get('failed_scans', 0)}")
        print(f"  Total vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        
        # Print vulnerability types
        vuln_types = summary.get('vulnerability_types', {})
        if vuln_types:
            print(f"\nVulnerability types:")
            for vuln_type, count in vuln_types.items():
                print(f"  {vuln_type}: {count}")
        
        # Print first few vulnerabilities
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"\nFirst 3 vulnerabilities:")
            for i, vuln in enumerate(vulnerabilities[:3]):
                print(f"  {i+1}. {vuln.get('cve_id', 'N/A')} - {vuln.get('description', 'N/A')[:50]}...")
        
    except Exception as e:
        print(f"Error during SSH scan: {e}")
        print("This is expected if the target host is not accessible or credentials are invalid")

def test_credentials_manager():
    """Test SSH credentials manager."""
    print("\nTesting SSH Credentials Manager...")
    
    cred_manager = SSHCredentialsManager()
    
    # Test saving credentials
    success = cred_manager.save_credentials(
        name="test_creds",
        username="testuser",
        password="testpass",
        port=22
    )
    
    if success:
        print("✓ Credentials saved successfully")
    else:
        print("✗ Failed to save credentials")
    
    # Test listing credentials
    credentials = cred_manager.list_credentials()
    print(f"Saved credentials: {len(credentials)}")
    for cred in credentials:
        print(f"  - {cred['name']}: {cred['username']}@{cred['port']}")
    
    # Test retrieving credentials
    retrieved = cred_manager.get_credentials("test_creds")
    if retrieved:
        print(f"✓ Retrieved credentials: {retrieved['username']}")
    else:
        print("✗ Failed to retrieve credentials")
    
    # Clean up
    cred_manager.delete_credentials("test_creds")
    print("✓ Test credentials cleaned up")

def test_exploitdb_matching():
    """Test ExploitDB vulnerability matching."""
    print("\nTesting ExploitDB vulnerability matching...")
    
    exploitdb_service = ExploitDBService()
    
    # Test searching for specific vulnerabilities
    test_queries = [
        "apache",
        "openssh",
        "linux kernel",
        "CVE-2021-44228"  # Log4j
    ]
    
    for query in test_queries:
        exploits = exploitdb_service.search_exploits(query, limit=3)
        print(f"Query '{query}': {len(exploits)} exploits found")
        
        if exploits:
            for exploit in exploits[:2]:  # Show first 2
                print(f"  - {exploit.get('id', 'N/A')}: {exploit.get('description', 'N/A')[:60]}...")

if __name__ == "__main__":
    print("CapScan SSH Authenticated Scanner Test")
    print("=" * 50)
    
    # Test credentials manager
    test_credentials_manager()
    
    # Test ExploitDB matching
    test_exploitdb_matching()
    
    # Test SSH scan (will likely fail without real targets)
    test_ssh_scan()
    
    print("\nTest completed!")
    print("\nTo use the SSH scan feature:")
    print("1. Add SSH credentials using the GUI (Advanced Options > SSH Authenticated Scan)")
    print("2. Enable SSH scan in Advanced Options")
    print("3. Run a network scan first to discover SSH-enabled hosts")
    print("4. The SSH scan will automatically run after the network scan")
