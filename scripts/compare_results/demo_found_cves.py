#!/usr/bin/env python3
"""
Demo script to show found CVEs by each scan type
"""

import json

def main():
    # Load data
    with open('vulnerabilities_full_scan.json', 'r') as f:
        full_scan = json.load(f)
    
    with open('vulnerabilities_quick_scan.json', 'r') as f:
        quick_scan = json.load(f)
    
    with open('nexpose_metasploitable2_cves.txt', 'r') as f:
        nexpose_cves = set(line.strip() for line in f if line.strip().startswith('CVE-'))
    
    # Extract CVE IDs
    full_scan_cves = set(item['cve_id'] for item in full_scan if item['cve_id'])
    quick_scan_cves = set(item['cve_id'] for item in quick_scan if item['cve_id'])
    
    print('=' * 80)
    print('FOUND CVEs ANALYSIS')
    print('=' * 80)
    
    print(f'\n📊 SUMMARY:')
    print(f'  Full scan found:     {len(full_scan_cves):3d} CVEs')
    print(f'  Quick scan found:    {len(quick_scan_cves):3d} CVEs')
    print(f'  Nexpose baseline:    {len(nexpose_cves):3d} CVEs')
    
    # Find overlaps
    found_by_both = full_scan_cves & quick_scan_cves
    found_by_full_only = full_scan_cves - quick_scan_cves
    found_by_quick_only = quick_scan_cves - full_scan_cves
    
    print(f'\n📈 OVERLAP ANALYSIS:')
    print(f'  Found by both scans:     {len(found_by_both):3d} CVEs')
    print(f'  Found by full only:      {len(found_by_full_only):3d} CVEs')
    print(f'  Found by quick only:     {len(found_by_quick_only):3d} CVEs')
    
    print(f'\n📊 FULL SCAN FOUND CVEs (first 20):')
    print('-' * 50)
    for cve in sorted(list(full_scan_cves))[:20]:
        print(f'  {cve}')
    if len(full_scan_cves) > 20:
        print(f'  ... and {len(full_scan_cves) - 20} more')
    
    print(f'\n📊 QUICK SCAN FOUND CVEs (first 20):')
    print('-' * 50)
    for cve in sorted(list(quick_scan_cves))[:20]:
        print(f'  {cve}')
    if len(quick_scan_cves) > 20:
        print(f'  ... and {len(quick_scan_cves) - 20} more')
    
    print(f'\n📊 CVEs FOUND BY BOTH SCANS (first 20):')
    print('-' * 50)
    for cve in sorted(list(found_by_both))[:20]:
        print(f'  {cve}')
    if len(found_by_both) > 20:
        print(f'  ... and {len(found_by_both) - 20} more')
    
    print(f'\n📊 CVEs FOUND ONLY BY FULL SCAN (first 20):')
    print('-' * 50)
    for cve in sorted(list(found_by_full_only))[:20]:
        print(f'  {cve}')
    if len(found_by_full_only) > 20:
        print(f'  ... and {len(found_by_full_only) - 20} more')
    
    if found_by_quick_only:
        print(f'\n📊 CVEs FOUND ONLY BY QUICK SCAN:')
        print('-' * 50)
        for cve in sorted(list(found_by_quick_only)):
            print(f'  {cve}')
    else:
        print(f'\n✅ No CVEs found only by quick scan (all quick scan CVEs are also in full scan)')

if __name__ == "__main__":
    main()
