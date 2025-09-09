#!/usr/bin/env python3
"""
Scan Results Comparison Tool

Compares vulnerability scan results (JSON) against Nexpose audit report (text)
with focus on identifying missed CVEs and scan effectiveness analysis.
"""

import json
import argparse
import sys
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ScanResult:
    """Represents a single CVE from scan results"""
    cve_id: str
    score: float
    description: str
    raw_output: str
    score_source: str
    keyword_score: float
    year_score: float


@dataclass
class ComparisonStats:
    """Statistics from the comparison analysis"""
    nexpose_total: int
    full_scan_total: int
    quick_scan_total: int
    
    nexpose_cves: Set[str]
    full_scan_cves: Set[str]
    quick_scan_cves: Set[str]
    
    # Coverage metrics
    full_scan_coverage: float
    quick_scan_coverage: float
    
    # Missed CVEs analysis
    missed_by_both: Set[str]
    missed_by_full_only: Set[str]
    missed_by_quick_only: Set[str]
    
    # False positives
    full_scan_false_positives: Set[str]
    quick_scan_false_positives: Set[str]
    
    # Overlap analysis
    found_by_both_scans: Set[str]
    found_by_full_only: Set[str]
    found_by_quick_only: Set[str]


class ScanResultsParser:
    """Parser for JSON scan result files"""
    
    @staticmethod
    def parse_json_file(file_path: str) -> List[ScanResult]:
        """Parse a JSON scan result file"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            results = []
            for item in data:
                result = ScanResult(
                    cve_id=item['cve_id'],
                    score=item['score'],
                    description=item['description'],
                    raw_output=item['raw_output'],
                    score_source=item['score_source'],
                    keyword_score=item['keyword_score'],
                    year_score=item['year_score']
                )
                results.append(result)
            
            return results
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            sys.exit(1)


class NexposeParser:
    """Parser for Nexpose text file"""
    
    @staticmethod
    def parse_nexpose_file(file_path: str) -> Set[str]:
        """Parse Nexpose CVE list from text file"""
        try:
            cves = set()
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('CVE-'):
                        cves.add(line)
            return cves
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            sys.exit(1)


class ScanComparator:
    """Main comparison engine"""
    
    def __init__(self, full_scan_file: str, quick_scan_file: str, nexpose_file: str):
        self.full_scan_file = full_scan_file
        self.quick_scan_file = quick_scan_file
        self.nexpose_file = nexpose_file
        
        # Parse all files
        print("Parsing scan results and Nexpose report...")
        self.full_scan_results = ScanResultsParser.parse_json_file(full_scan_file)
        self.quick_scan_results = ScanResultsParser.parse_json_file(quick_scan_file)
        self.nexpose_cves = NexposeParser.parse_nexpose_file(nexpose_file)
        
        # Extract CVE IDs
        self.full_scan_cves = {result.cve_id for result in self.full_scan_results}
        self.quick_scan_cves = {result.cve_id for result in self.quick_scan_results}
        
        print(f"Loaded {len(self.full_scan_cves)} CVEs from full scan")
        print(f"Loaded {len(self.quick_scan_cves)} CVEs from quick scan")
        print(f"Loaded {len(self.nexpose_cves)} CVEs from Nexpose report")
    
    def compare_scans(self) -> ComparisonStats:
        """Perform comprehensive comparison analysis"""
        print("\nPerforming comparison analysis...")
        
        # Calculate coverage metrics
        full_scan_coverage = len(self.nexpose_cves.intersection(self.full_scan_cves)) / len(self.nexpose_cves) * 100
        quick_scan_coverage = len(self.nexpose_cves.intersection(self.quick_scan_cves)) / len(self.nexpose_cves) * 100
        
        # Find missed CVEs
        missed_by_both = self.nexpose_cves - (self.full_scan_cves | self.quick_scan_cves)
        missed_by_full_only = self.nexpose_cves - self.full_scan_cves
        missed_by_quick_only = self.nexpose_cves - self.quick_scan_cves
        
        # Find false positives
        full_scan_false_positives = self.full_scan_cves - self.nexpose_cves
        quick_scan_false_positives = self.quick_scan_cves - self.nexpose_cves
        
        # Find overlaps
        found_by_both_scans = self.full_scan_cves.intersection(self.quick_scan_cves)
        found_by_full_only = self.full_scan_cves - self.quick_scan_cves
        found_by_quick_only = self.quick_scan_cves - self.full_scan_cves
        
        return ComparisonStats(
            nexpose_total=len(self.nexpose_cves),
            full_scan_total=len(self.full_scan_cves),
            quick_scan_total=len(self.quick_scan_cves),
            
            nexpose_cves=self.nexpose_cves,
            full_scan_cves=self.full_scan_cves,
            quick_scan_cves=self.quick_scan_cves,
            
            full_scan_coverage=full_scan_coverage,
            quick_scan_coverage=quick_scan_coverage,
            
            missed_by_both=missed_by_both,
            missed_by_full_only=missed_by_full_only,
            missed_by_quick_only=missed_by_quick_only,
            
            full_scan_false_positives=full_scan_false_positives,
            quick_scan_false_positives=quick_scan_false_positives,
            
            found_by_both_scans=found_by_both_scans,
            found_by_full_only=found_by_full_only,
            found_by_quick_only=found_by_quick_only
        )
    
    def generate_detailed_report(self, stats: ComparisonStats) -> str:
        """Generate detailed comparison report"""
        report = []
        report.append("=" * 80)
        report.append("SCAN RESULTS COMPARISON REPORT")
        report.append("=" * 80)
        
        # Summary statistics
        report.append(f"\nSUMMARY STATISTICS:")
        report.append(f"  Nexpose Report CVEs:     {stats.nexpose_total:3d}")
        report.append(f"  Full Scan CVEs:          {stats.full_scan_total:3d}")
        report.append(f"  Quick Scan CVEs:         {stats.quick_scan_total:3d}")
        
        # Coverage analysis
        report.append(f"\nCOVERAGE ANALYSIS:")
        report.append(f"  Full Scan Coverage:      {stats.full_scan_coverage:5.1f}% ({len(stats.nexpose_cves.intersection(stats.full_scan_cves))}/{stats.nexpose_total})")
        report.append(f"  Quick Scan Coverage:     {stats.quick_scan_coverage:5.1f}% ({len(stats.nexpose_cves.intersection(stats.quick_scan_cves))}/{stats.nexpose_total})")
        
        # Missed CVEs analysis - CRITICAL SECTION
        report.append(f"\n🚨 MISSED CVEs ANALYSIS:")
        report.append(f"  Missed by BOTH scans:    {len(stats.missed_by_both):3d} ({len(stats.missed_by_both)/stats.nexpose_total*100:.1f}%)")
        report.append(f"  Missed by Full only:     {len(stats.missed_by_full_only):3d}")
        report.append(f"  Missed by Quick only:    {len(stats.missed_by_quick_only):3d}")
        
        # False positives
        report.append(f"\nFALSE POSITIVES:")
        report.append(f"  Full Scan False Positives:  {len(stats.full_scan_false_positives):3d}")
        report.append(f"  Quick Scan False Positives: {len(stats.quick_scan_false_positives):3d}")
        
        # Scan overlap analysis
        report.append(f"\nSCAN OVERLAP ANALYSIS:")
        report.append(f"  Found by both scans:     {len(stats.found_by_both_scans):3d}")
        report.append(f"  Found by Full only:      {len(stats.found_by_full_only):3d}")
        report.append(f"  Found by Quick only:     {len(stats.found_by_quick_only):3d}")
        
        # Quick scan effectiveness
        quick_effectiveness = len(stats.found_by_both_scans) / len(stats.full_scan_cves) * 100
        report.append(f"\nQUICK SCAN EFFECTIVENESS:")
        report.append(f"  Quick scan finds {quick_effectiveness:.1f}% of Full scan results")
        
        return "\n".join(report)
    
    def generate_found_cves_report(self, stats: ComparisonStats) -> str:
        """Generate detailed report of found CVEs by each scan"""
        report = []
        report.append("\n" + "=" * 80)
        report.append("DETAILED FOUND CVEs REPORT")
        report.append("=" * 80)
        
        # CVEs found by full scan
        report.append(f"\n📊 FULL SCAN FOUND CVEs ({len(stats.full_scan_cves)} total):")
        report.append("-" * 50)
        for cve in sorted(stats.full_scan_cves):
            report.append(f"  {cve}")
        
        # CVEs found by quick scan
        report.append(f"\n📊 QUICK SCAN FOUND CVEs ({len(stats.quick_scan_cves)} total):")
        report.append("-" * 50)
        for cve in sorted(stats.quick_scan_cves):
            report.append(f"  {cve}")
        
        # CVEs found by both scans
        report.append(f"\n📊 CVEs FOUND BY BOTH SCANS ({len(stats.found_by_both_scans)} total):")
        report.append("-" * 50)
        for cve in sorted(stats.found_by_both_scans):
            report.append(f"  {cve}")
        
        # CVEs found only by full scan
        report.append(f"\n📊 CVEs FOUND ONLY BY FULL SCAN ({len(stats.found_by_full_only)} total):")
        report.append("-" * 50)
        for cve in sorted(stats.found_by_full_only):
            report.append(f"  {cve}")
        
        # CVEs found only by quick scan
        report.append(f"\n📊 CVEs FOUND ONLY BY QUICK SCAN ({len(stats.found_by_quick_only)} total):")
        report.append("-" * 50)
        for cve in sorted(stats.found_by_quick_only):
            report.append(f"  {cve}")
        
        return "\n".join(report)
    
    def generate_missed_cves_report(self, stats: ComparisonStats) -> str:
        """Generate detailed report of missed CVEs"""
        report = []
        report.append("\n" + "=" * 80)
        report.append("DETAILED MISSED CVEs REPORT")
        report.append("=" * 80)
        
        if stats.missed_by_both:
            report.append(f"\n🚨 CRITICAL: {len(stats.missed_by_both)} CVEs MISSED BY BOTH SCANS:")
            report.append("-" * 50)
            for cve in sorted(stats.missed_by_both):
                report.append(f"  {cve}")
        else:
            report.append("\n✅ No CVEs were missed by both scans!")
        
        if stats.missed_by_full_only:
            report.append(f"\n⚠️  {len(stats.missed_by_full_only)} CVEs MISSED BY FULL SCAN ONLY:")
            report.append("-" * 50)
            for cve in sorted(stats.missed_by_full_only):
                report.append(f"  {cve}")
        
        if stats.missed_by_quick_only:
            report.append(f"\n⚠️  {len(stats.missed_by_quick_only)} CVEs MISSED BY QUICK SCAN ONLY:")
            report.append("-" * 50)
            for cve in sorted(stats.missed_by_quick_only):
                report.append(f"  {cve}")
        
        return "\n".join(report)
    
    def save_missed_cves_to_file(self, stats: ComparisonStats, output_file: str):
        """Save missed CVEs to a text file for further analysis"""
        with open(output_file, 'w') as f:
            f.write("CVEs Missed by Both Scans\n")
            f.write("=" * 30 + "\n\n")
            
            if stats.missed_by_both:
                f.write(f"Total: {len(stats.missed_by_both)} CVEs\n\n")
                for cve in sorted(stats.missed_by_both):
                    f.write(f"{cve}\n")
            else:
                f.write("No CVEs were missed by both scans!\n")
        
        print(f"\nMissed CVEs saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(description='Compare scan results against Nexpose audit report')
    parser.add_argument('--full-scan', required=True, help='Full scan JSON file')
    parser.add_argument('--quick-scan', required=True, help='Quick scan JSON file')
    parser.add_argument('--nexpose', required=True, help='Nexpose CVE list text file')
    parser.add_argument('--output', help='Output file for missed CVEs list')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate input files
    for file_path in [args.full_scan, args.quick_scan, args.nexpose]:
        if not Path(file_path).exists():
            print(f"Error: File not found: {file_path}")
            sys.exit(1)
    
    # Perform comparison
    comparator = ScanComparator(args.full_scan, args.quick_scan, args.nexpose)
    stats = comparator.compare_scans()
    
    # Generate and display reports
    print(comparator.generate_detailed_report(stats))
    print(comparator.generate_found_cves_report(stats))
    print(comparator.generate_missed_cves_report(stats))
    
    # Save missed CVEs to file if requested
    if args.output:
        comparator.save_missed_cves_to_file(stats, args.output)
    
    # Verbose output
    if args.verbose:
        print(f"\nVERBOSE ANALYSIS:")
        print(f"  Full scan CVE IDs: {sorted(list(stats.full_scan_cves))}")
        print(f"  Quick scan CVE IDs: {sorted(list(stats.quick_scan_cves))}")
        print(f"  Nexpose CVE IDs: {sorted(list(stats.nexpose_cves))}")


if __name__ == "__main__":
    main()
