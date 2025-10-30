#!/usr/bin/env python3
"""
Debug script to test SSH scan functionality and identify why it's finding zero vulnerabilities.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ssh_scanner import SSHAuthenticatedScanner, SSHCredentials
from services.exploitdb_service import ExploitDBService

def test_exploitdb_service():
    """Test if ExploitDB service is working properly."""
    print("=== Testing ExploitDB Service ===")
    
    try:
        edb_service = ExploitDBService()
        stats = edb_service.get_exploit_statistics()
        
        print(f"ExploitDB Statistics:")
        print(f"  Total exploits: {stats.get('total_exploits', 0)}")
        print(f"  Verified exploits: {stats.get('verified_exploits', 0)}")
        print(f"  CVE count: {stats.get('cve_count', 0)}")
        
        # Test a simple search
        test_results = edb_service.search_exploits("linux", limit=3)
        print(f"  Test search for 'linux': {len(test_results)} results")
        
        if test_results:
            print(f"  First result: {test_results[0].get('id', 'N/A')} - {test_results[0].get('description', 'N/A')[:50]}...")
        
        return True
        
    except Exception as e:
        print(f"Error testing ExploitDB service: {e}")
        return False

def test_ssh_scanner_creation():
    """Test if SSH scanner can be created properly."""
    print("\n=== Testing SSH Scanner Creation ===")
    
    try:
        ssh_scanner = SSHAuthenticatedScanner()
        print("SSH scanner created successfully")
        
        # Check if ExploitDB service is properly initialized
        if hasattr(ssh_scanner, 'exploitdb_service'):
            print("ExploitDB service is initialized")
            if hasattr(ssh_scanner.exploitdb_service, 'exploits_data'):
                print(f"ExploitDB data loaded: {len(ssh_scanner.exploitdb_service.exploits_data)} exploits")
            else:
                print("ExploitDB data not loaded")
        else:
            print("ExploitDB service not found")
        
        return True
        
    except Exception as e:
        print(f"Error creating SSH scanner: {e}")
        return False

def test_vulnerability_matching():
    """Test vulnerability matching with mock data."""
    print("\n=== Testing Vulnerability Matching ===")
    
    try:
        from ssh_scanner import SystemInfo
        
        # Create mock system info
        mock_system_info = SystemInfo(
            host_ip="192.168.1.100",
            uname_output="Linux testhost 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux",
            os_release="PRETTY_NAME=\"Ubuntu 20.04.2 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"20.04\"",
            package_list=[
                {"name": "openssh-server", "version": "1:8.2p1-4ubuntu0.2", "manager": "dpkg"},
                {"name": "apache2", "version": "2.4.41-4ubuntu3.1", "manager": "dpkg"},
                {"name": "libc6", "version": "2.31-0ubuntu9.2", "manager": "dpkg"}
            ],
            distro="ubuntu",
            kernel_version="5.4.0-74-generic",
            architecture="x86_64",
            timestamp="2023-01-01T00:00:00"
        )
        
        ssh_scanner = SSHAuthenticatedScanner()
        
        # Test vulnerability matching
        vulnerabilities = ssh_scanner._match_vulnerabilities_from_system_info(
            "192.168.1.100", mock_system_info
        )
        
        print(f"Found {len(vulnerabilities)} vulnerabilities")
        
        if vulnerabilities:
            print("Sample vulnerabilities:")
            for i, vuln in enumerate(vulnerabilities[:3]):
                print(f"  {i+1}. {vuln.get('cve_id', 'N/A')} - {vuln.get('description', 'N/A')[:50]}...")
        else:
            print("No vulnerabilities found - this might be the issue!")
        
        return len(vulnerabilities) > 0
        
    except Exception as e:
        print(f"Error testing vulnerability matching: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print("SSH Scan Debug Script")
    print("=" * 50)
    
    # Test ExploitDB service
    edb_ok = test_exploitdb_service()
    
    # Test SSH scanner creation
    scanner_ok = test_ssh_scanner_creation()
    
    # Test vulnerability matching
    vuln_ok = test_vulnerability_matching()
    
    print("\n=== Summary ===")
    print(f"ExploitDB Service: {'✓' if edb_ok else '✗'}")
    print(f"SSH Scanner Creation: {'✓' if scanner_ok else '✗'}")
    print(f"Vulnerability Matching: {'✓' if vuln_ok else '✗'}")
    
    if not vuln_ok:
        print("\n*** ISSUE FOUND: Vulnerability matching is not working properly ***")
        print("This explains why SSH scan finds zero vulnerabilities.")
    else:
        print("\nAll tests passed. The issue might be elsewhere.")

if __name__ == "__main__":
    main()
