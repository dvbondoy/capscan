#!/usr/bin/env python3
"""
Enhanced Scan Results Comparison Tool

Advanced comparison of vulnerability scan results (JSON) against Nexpose audit report (text)
with comprehensive analysis, multiple output formats, and detailed reporting.
"""

import json
import argparse
import sys
import csv
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from datetime import datetime


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
    
    # Score analysis
    full_scan_avg_score: float
    quick_scan_avg_score: float
    nexpose_found_avg_score: float


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
                # Skip items with missing or None cve_id
                if not item.get('cve_id') or item['cve_id'] is None:
                    continue
                    
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


class EnhancedScanComparator:
    """Enhanced comparison engine with advanced analysis"""
    
    def __init__(self, full_scan_file: str, quick_scan_file: str, nexpose_file: str):
        self.full_scan_file = full_scan_file
        self.quick_scan_file = quick_scan_file
        self.nexpose_file = nexpose_file
        
        # Parse all files
        print("Parsing scan results and Nexpose report...")
        self.full_scan_results = ScanResultsParser.parse_json_file(full_scan_file)
        self.quick_scan_results = ScanResultsParser.parse_json_file(quick_scan_file)
        self.nexpose_cves = NexposeParser.parse_nexpose_file(nexpose_file)
        
        # Extract CVE IDs (filter out None values)
        self.full_scan_cves = {result.cve_id for result in self.full_scan_results if result.cve_id is not None}
        self.quick_scan_cves = {result.cve_id for result in self.quick_scan_results if result.cve_id is not None}
        
        print(f"Loaded {len(self.full_scan_cves)} CVEs from full scan")
        print(f"Loaded {len(self.quick_scan_cves)} CVEs from quick scan")
        print(f"Loaded {len(self.nexpose_cves)} CVEs from Nexpose report")
    
    def compare_scans(self) -> ComparisonStats:
        """Perform comprehensive comparison analysis"""
        print("\nPerforming enhanced comparison analysis...")
        
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
        
        # Calculate score averages
        full_scan_avg_score = sum(result.score for result in self.full_scan_results) / len(self.full_scan_results)
        quick_scan_avg_score = sum(result.score for result in self.quick_scan_results) / len(self.quick_scan_results)
        
        # Calculate average score for CVEs found in Nexpose
        nexpose_found_scores = []
        for result in self.full_scan_results:
            if result.cve_id in self.nexpose_cves:
                nexpose_found_scores.append(result.score)
        for result in self.quick_scan_results:
            if result.cve_id in self.nexpose_cves and result.cve_id not in [r.cve_id for r in self.full_scan_results if r.cve_id in self.nexpose_cves]:
                nexpose_found_scores.append(result.score)
        
        nexpose_found_avg_score = sum(nexpose_found_scores) / len(nexpose_found_scores) if nexpose_found_scores else 0
        
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
            found_by_quick_only=found_by_quick_only,
            
            full_scan_avg_score=full_scan_avg_score,
            quick_scan_avg_score=quick_scan_avg_score,
            nexpose_found_avg_score=nexpose_found_avg_score
        )
    
    def generate_executive_summary(self, stats: ComparisonStats) -> str:
        """Generate executive summary for management"""
        report = []
        report.append("=" * 80)
        report.append("EXECUTIVE SUMMARY - VULNERABILITY SCAN EFFECTIVENESS")
        report.append("=" * 80)
        
        report.append(f"\n📊 KEY METRICS:")
        report.append(f"  • Nexpose Baseline:        {stats.nexpose_total} CVEs")
        report.append(f"  • Full Scan Coverage:      {stats.full_scan_coverage:.1f}% ({len(stats.nexpose_cves.intersection(stats.full_scan_cves))}/{stats.nexpose_total})")
        report.append(f"  • Quick Scan Coverage:     {stats.quick_scan_coverage:.1f}% ({len(stats.nexpose_cves.intersection(stats.quick_scan_cves))}/{stats.nexpose_total})")
        
        report.append(f"\n🚨 CRITICAL FINDINGS:")
        report.append(f"  • CVEs Missed by Both:     {len(stats.missed_by_both)} ({len(stats.missed_by_both)/stats.nexpose_total*100:.1f}%)")
        report.append(f"  • False Positive Rate:     {len(stats.full_scan_false_positives)/stats.full_scan_total*100:.1f}% (Full), {len(stats.quick_scan_false_positives)/stats.quick_scan_total*100:.1f}% (Quick)")
        
        report.append(f"\n📈 SCAN EFFICIENCY:")
        report.append(f"  • Quick Scan Effectiveness: {len(stats.found_by_both_scans)/stats.full_scan_total*100:.1f}% of Full Scan results")
        report.append(f"  • Average Vulnerability Score: {stats.full_scan_avg_score:.1f} (Full), {stats.quick_scan_avg_score:.1f} (Quick)")
        
        # Recommendations
        report.append(f"\n💡 RECOMMENDATIONS:")
        if stats.full_scan_coverage < 50:
            report.append(f"  • CRITICAL: Full scan coverage is only {stats.full_scan_coverage:.1f}% - immediate review needed")
        if len(stats.missed_by_both) > stats.nexpose_total * 0.5:
            report.append(f"  • HIGH: {len(stats.missed_by_both)} CVEs missed by both scans - scanning methodology needs improvement")
        if len(stats.full_scan_false_positives) > stats.full_scan_total * 0.5:
            report.append(f"  • MEDIUM: High false positive rate ({len(stats.full_scan_false_positives)/stats.full_scan_total*100:.1f}%) - tune scanning parameters")
        
        return "\n".join(report)
    
    def generate_detailed_report(self, stats: ComparisonStats) -> str:
        """Generate detailed comparison report"""
        report = []
        report.append("=" * 80)
        report.append("DETAILED SCAN RESULTS COMPARISON REPORT")
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
        report.append(f"  Full Scan False Positives:  {len(stats.full_scan_false_positives):3d} ({len(stats.full_scan_false_positives)/stats.full_scan_total*100:.1f}%)")
        report.append(f"  Quick Scan False Positives: {len(stats.quick_scan_false_positives):3d} ({len(stats.quick_scan_false_positives)/stats.quick_scan_total*100:.1f}%)")
        
        # Scan overlap analysis
        report.append(f"\nSCAN OVERLAP ANALYSIS:")
        report.append(f"  Found by both scans:     {len(stats.found_by_both_scans):3d}")
        report.append(f"  Found by Full only:      {len(stats.found_by_full_only):3d}")
        report.append(f"  Found by Quick only:     {len(stats.found_by_quick_only):3d}")
        
        # Quick scan effectiveness
        quick_effectiveness = len(stats.found_by_both_scans) / len(stats.full_scan_cves) * 100
        report.append(f"\nQUICK SCAN EFFECTIVENESS:")
        report.append(f"  Quick scan finds {quick_effectiveness:.1f}% of Full scan results")
        
        # Score analysis
        report.append(f"\nSCORE ANALYSIS:")
        report.append(f"  Full Scan Avg Score:     {stats.full_scan_avg_score:.2f}")
        report.append(f"  Quick Scan Avg Score:    {stats.quick_scan_avg_score:.2f}")
        report.append(f"  Nexpose Found Avg Score: {stats.nexpose_found_avg_score:.2f}")
        
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
        for cve in sorted([cve for cve in stats.full_scan_cves if cve is not None]):
            report.append(f"  {cve}")
        
        # CVEs found by quick scan
        report.append(f"\n📊 QUICK SCAN FOUND CVEs ({len(stats.quick_scan_cves)} total):")
        report.append("-" * 50)
        for cve in sorted([cve for cve in stats.quick_scan_cves if cve is not None]):
            report.append(f"  {cve}")
        
        # CVEs found by both scans
        report.append(f"\n📊 CVEs FOUND BY BOTH SCANS ({len(stats.found_by_both_scans)} total):")
        report.append("-" * 50)
        for cve in sorted([cve for cve in stats.found_by_both_scans if cve is not None]):
            report.append(f"  {cve}")
        
        # CVEs found only by full scan
        report.append(f"\n📊 CVEs FOUND ONLY BY FULL SCAN ({len(stats.found_by_full_only)} total):")
        report.append("-" * 50)
        for cve in sorted([cve for cve in stats.found_by_full_only if cve is not None]):
            report.append(f"  {cve}")
        
        # CVEs found only by quick scan
        report.append(f"\n📊 CVEs FOUND ONLY BY QUICK SCAN ({len(stats.found_by_quick_only)} total):")
        report.append("-" * 50)
        for cve in sorted([cve for cve in stats.found_by_quick_only if cve is not None]):
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
            for cve in sorted([cve for cve in stats.missed_by_both if cve is not None]):
                report.append(f"  {cve}")
        else:
            report.append("\n✅ No CVEs were missed by both scans!")
        
        if stats.missed_by_full_only:
            report.append(f"\n⚠️  {len(stats.missed_by_full_only)} CVEs MISSED BY FULL SCAN ONLY:")
            report.append("-" * 50)
            for cve in sorted([cve for cve in stats.missed_by_full_only if cve is not None]):
                report.append(f"  {cve}")
        
        if stats.missed_by_quick_only:
            report.append(f"\n⚠️  {len(stats.missed_by_quick_only)} CVEs MISSED BY QUICK SCAN ONLY:")
            report.append("-" * 50)
            for cve in sorted([cve for cve in stats.missed_by_quick_only if cve is not None]):
                report.append(f"  {cve}")
        
        return "\n".join(report)
    
    def save_json_report(self, stats: ComparisonStats, output_file: str):
        """Save detailed comparison report as JSON"""
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "nexpose_total": stats.nexpose_total,
                "full_scan_total": stats.full_scan_total,
                "quick_scan_total": stats.quick_scan_total,
                "full_scan_coverage_percent": round(stats.full_scan_coverage, 2),
                "quick_scan_coverage_percent": round(stats.quick_scan_coverage, 2),
                "missed_by_both_count": len(stats.missed_by_both),
                "missed_by_both_percent": round(len(stats.missed_by_both) / stats.nexpose_total * 100, 2)
            },
            "missed_cves": {
                "by_both_scans": sorted([cve for cve in stats.missed_by_both if cve is not None]),
                "by_full_scan_only": sorted([cve for cve in stats.missed_by_full_only if cve is not None]),
                "by_quick_scan_only": sorted([cve for cve in stats.missed_by_quick_only if cve is not None])
            },
            "false_positives": {
                "full_scan": sorted([cve for cve in stats.full_scan_false_positives if cve is not None]),
                "quick_scan": sorted([cve for cve in stats.quick_scan_false_positives if cve is not None])
            },
            "score_analysis": {
                "full_scan_avg": round(stats.full_scan_avg_score, 2),
                "quick_scan_avg": round(stats.quick_scan_avg_score, 2),
                "nexpose_found_avg": round(stats.nexpose_found_avg_score, 2)
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\nDetailed JSON report saved to: {output_file}")
    
    def save_csv_report(self, stats: ComparisonStats, output_file: str):
        """Save comparison data as CSV for further analysis"""
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(['CVE_ID', 'In_Nexpose', 'In_Full_Scan', 'In_Quick_Scan', 'Status', 'Score'])
            
            # Get all unique CVEs
            all_cves = stats.nexpose_cves | stats.full_scan_cves | stats.quick_scan_cves
            
            # Create score lookup
            full_scan_scores = {result.cve_id: result.score for result in self.full_scan_results}
            quick_scan_scores = {result.cve_id: result.score for result in self.quick_scan_results}
            
            for cve in sorted([cve for cve in all_cves if cve is not None]):
                in_nexpose = cve in stats.nexpose_cves
                in_full = cve in stats.full_scan_cves
                in_quick = cve in stats.quick_scan_cves
                
                # Determine status
                if in_nexpose and in_full and in_quick:
                    status = "Found by all"
                elif in_nexpose and in_full:
                    status = "Found by Nexpose + Full"
                elif in_nexpose and in_quick:
                    status = "Found by Nexpose + Quick"
                elif in_nexpose:
                    status = "Missed by both scans"
                elif in_full and in_quick:
                    status = "False positive (both scans)"
                elif in_full:
                    status = "False positive (full scan)"
                elif in_quick:
                    status = "False positive (quick scan)"
                else:
                    status = "Unknown"
                
                # Get score (prefer full scan if available)
                score = full_scan_scores.get(cve, quick_scan_scores.get(cve, 0))
                
                writer.writerow([cve, in_nexpose, in_full, in_quick, status, score])
        
        print(f"\nCSV report saved to: {output_file}")
    
    def save_missed_cves_to_file(self, stats: ComparisonStats, output_file: str):
        """Save missed CVEs to a text file for further analysis"""
        with open(output_file, 'w') as f:
            f.write("CVEs Missed by Both Scans\n")
            f.write("=" * 30 + "\n\n")
            
            if stats.missed_by_both:
                f.write(f"Total: {len(stats.missed_by_both)} CVEs\n\n")
                for cve in sorted([cve for cve in stats.missed_by_both if cve is not None]):
                    f.write(f"{cve}\n")
            else:
                f.write("No CVEs were missed by both scans!\n")
        
        print(f"\nMissed CVEs saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(description='Enhanced scan results comparison against Nexpose audit report')
    parser.add_argument('--full-scan', required=True, help='Full scan JSON file')
    parser.add_argument('--quick-scan', required=True, help='Quick scan JSON file')
    parser.add_argument('--nexpose', required=True, help='Nexpose CVE list text file')
    parser.add_argument('--output', help='Output file for missed CVEs list')
    parser.add_argument('--json-report', help='Output file for detailed JSON report')
    parser.add_argument('--csv-report', help='Output file for CSV report')
    parser.add_argument('--executive-summary', action='store_true', help='Show executive summary only')
    parser.add_argument('--found-cves-only', action='store_true', help='Show found CVEs report only')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate input files
    for file_path in [args.full_scan, args.quick_scan, args.nexpose]:
        if not Path(file_path).exists():
            print(f"Error: File not found: {file_path}")
            sys.exit(1)
    
    # Perform comparison
    comparator = EnhancedScanComparator(args.full_scan, args.quick_scan, args.nexpose)
    stats = comparator.compare_scans()
    
    # Generate and display reports
    if args.executive_summary:
        print(comparator.generate_executive_summary(stats))
    elif args.found_cves_only:
        print(comparator.generate_found_cves_report(stats))
    else:
        print(comparator.generate_executive_summary(stats))
        print(comparator.generate_detailed_report(stats))
        print(comparator.generate_found_cves_report(stats))
        print(comparator.generate_missed_cves_report(stats))
    
    # Save reports if requested
    if args.output:
        comparator.save_missed_cves_to_file(stats, args.output)
    
    if args.json_report:
        comparator.save_json_report(stats, args.json_report)
    
    if args.csv_report:
        comparator.save_csv_report(stats, args.csv_report)
    
    # Verbose output
    if args.verbose:
        print(f"\nVERBOSE ANALYSIS:")
        print(f"  Full scan CVE IDs: {sorted([cve for cve in stats.full_scan_cves if cve is not None])}")
        print(f"  Quick scan CVE IDs: {sorted([cve for cve in stats.quick_scan_cves if cve is not None])}")
        print(f"  Nexpose CVE IDs: {sorted([cve for cve in stats.nexpose_cves if cve is not None])}")


if __name__ == "__main__":
    main()
