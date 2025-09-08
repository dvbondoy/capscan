#!/usr/bin/env python3
"""
Test script for CapScan database functionality.
This script demonstrates how to use the SQLCipher3 database to store and retrieve scan results.
"""

from database import Database
import json
from datetime import datetime

def test_database():
    """Test the database functionality with sample data"""
    print("🧪 Testing CapScan Database Functionality")
    print("=" * 50)
    
    # Sample scan results for testing
    sample_scan_results = {
        'target': '192.168.1.100',
        'scan_time': datetime.now().isoformat(),
        'scan_args': '-sV -sC -vv --script vulners --script-args vulners.maxreports=10 -p 22,80,443',
        'hosts': {
            '192.168.1.100': {
                'hostname': 'test-server.local',
                'state': 'up',
                'protocols': ['tcp'],
                'ports': {
                    'tcp/22': {
                        'state': 'open',
                        'name': 'ssh',
                        'product': 'OpenSSH',
                        'version': '8.2p1',
                        'extrainfo': 'Ubuntu-4ubuntu0.2',
                        'script_results': {
                            'vulners': 'CVE-2020-14145 7.5 OpenSSH through 8.3 and earlier'
                        }
                    },
                    'tcp/80': {
                        'state': 'open',
                        'name': 'http',
                        'product': 'Apache httpd',
                        'version': '2.4.41',
                        'extrainfo': 'Ubuntu',
                        'script_results': {
                            'vulners': 'CVE-2021-44228 9.8 Apache Log4j2 2.0-beta9 through 2.15.0'
                        }
                    }
                },
                'vulnerabilities': []
            }
        },
        'vulnerabilities': [
            {
                'cve_id': 'CVE-2020-14145',
                'score': 7.5,
                'description': 'OpenSSH through 8.3 and earlier',
                'raw_output': 'CVE-2020-14145 7.5 OpenSSH through 8.3 and earlier',
                'score_source': 'vulners',
                'host_ip': '192.168.1.100',
                'port': 'tcp/22'
            },
            {
                'cve_id': 'CVE-2021-44228',
                'score': 9.8,
                'description': 'Apache Log4j2 2.0-beta9 through 2.15.0',
                'raw_output': 'CVE-2021-44228 9.8 Apache Log4j2 2.0-beta9 through 2.15.0',
                'score_source': 'vulners',
                'host_ip': '192.168.1.100',
                'port': 'tcp/80'
            }
        ]
    }
    
    try:
        # Test database operations
        print("Note: You'll be prompted for a database password...")
        with Database() as db:
            print("✅ Database connection established")
            
            # Save scan results
            print("\n💾 Saving sample scan results...")
            scan_id = db.save_scan_results(sample_scan_results)
            print(f"✅ Scan saved with ID: {scan_id}")
            
            # Retrieve scan results
            print("\n📖 Retrieving scan results...")
            retrieved_scan = db.get_scan_results(scan_id)
            if retrieved_scan:
                print(f"✅ Retrieved scan for target: {retrieved_scan['target']}")
                print(f"   Vulnerabilities found: {retrieved_scan['total_vulnerabilities']}")
                print(f"   Hosts scanned: {retrieved_scan['hosts_scanned']}")
            else:
                print("❌ Failed to retrieve scan results")
            
            # Get all scans
            print("\n📋 Retrieving all scans...")
            all_scans = db.get_all_scan_results()
            print(f"✅ Found {len(all_scans)} scans in database")
            
            # Get scans by target
            print("\n🎯 Retrieving scans by target...")
            target_scans = db.get_scan_results_by_target('192.168.1.100')
            print(f"✅ Found {len(target_scans)} scans for target 192.168.1.100")
            
            # Get database summary
            print("\n📊 Database summary...")
            summary = db.get_scan_summary()
            print(f"✅ Database summary:")
            print(f"   Total scans: {summary.get('total_scans', 0)}")
            print(f"   Total vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
            print(f"   High severity: {summary.get('high_severity', 0)}")
            print(f"   Medium severity: {summary.get('medium_severity', 0)}")
            print(f"   Low severity: {summary.get('low_severity', 0)}")
            print(f"   Unknown severity: {summary.get('unknown_severity', 0)}")
            
            print("\n🎉 All database tests completed successfully!")
            
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = test_database()
    exit(0 if success else 1)
