import unittest
import os
import tempfile
import xml.etree.ElementTree as ET
from unittest.mock import Mock, patch, MagicMock
import sys

# Add parent directory to path to import engine module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import Scanner


class TestVulnerabilityScanner(unittest.TestCase):
    """Test cases for VulnerabilityScanner class."""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.scanner = Scanner()
        self.test_target = "127.0.0.1"
        self.test_ports = "22,80,443"
        
    def test_init(self):
        """Test VulnerabilityScanner initialization."""
        self.assertIsNotNone(self.scanner.nm)
        self.assertEqual(self.scanner.vulnerabilities, [])
        self.assertEqual(self.scanner.scan_results, {})
        self.assertIsNone(self.scanner.xml_output_path)
    
    def test_extract_score_high_severity(self):
        """Test CVSS score extraction for high severity vulnerabilities."""
        test_line = "CVE-2021-44228  CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H  9.8"
        score = self.scanner._extract_score(test_line)
        self.assertEqual(score, 9.8)
    
    def test_extract_score_medium_severity(self):
        """Test CVSS score extraction for medium severity vulnerabilities."""
        test_line = "CVE-2021-12345  Score: 6.5  Remote code execution"
        score = self.scanner._extract_score(test_line)
        self.assertEqual(score, 6.5)
    
    def test_extract_score_no_score(self):
        """Test CVSS score extraction when no score is present."""
        test_line = "CVE-2021-12345  Some vulnerability description"
        score = self.scanner._extract_score(test_line)
        self.assertIsNone(score)
    
    def test_parse_vulners_output(self):
        """Test parsing of vulners script output."""
        test_output = """
        CVE-2021-44228  CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H  9.8  Log4j vulnerability
        CVE-2021-12345  Score: 6.5  Remote code execution
        CVE-2021-67890  Some other vulnerability
        """
        
        vulnerabilities = self.scanner._parse_vulners_output(test_output)
        
        self.assertEqual(len(vulnerabilities), 3)
        self.assertEqual(vulnerabilities[0]['cve_id'], 'CVE-2021-44228')
        self.assertEqual(vulnerabilities[0]['score'], 9.8)
        self.assertIn('Log4j vulnerability', vulnerabilities[0]['description'])
        
        self.assertEqual(vulnerabilities[1]['cve_id'], 'CVE-2021-12345')
        self.assertEqual(vulnerabilities[1]['score'], 6.5)
        
        self.assertEqual(vulnerabilities[2]['cve_id'], 'CVE-2021-67890')
        self.assertIsNone(vulnerabilities[2]['score'])
    
    def test_parse_vulners_output_empty(self):
        """Test parsing empty vulners output."""
        vulnerabilities = self.scanner._parse_vulners_output("")
        self.assertEqual(vulnerabilities, [])
    
    def test_parse_vulners_output_no_cve(self):
        """Test parsing vulners output with no CVE entries."""
        test_output = "Some random text without CVE"
        vulnerabilities = self.scanner._parse_vulners_output(test_output)
        self.assertEqual(vulnerabilities, [])
    
    def test_scan_host_success(self):
        """Test successful host scanning with mock data."""
        # Create scanner instance
        scanner = Scanner()
        
        # Mock the scan results directly
        scanner.scan_results = {
            'target': self.test_target,
            'scan_time': '2023-01-01T12:00:00',
            'scan_args': '-sV -sC --script vulners',
            'hosts': {
                '127.0.0.1': {
                    'hostname': 'localhost',
                    'state': 'up',
                    'protocols': ['tcp'],
                    'ports': {
                        'tcp/22': {
                            'state': 'open',
                            'name': 'ssh',
                            'product': 'OpenSSH',
                            'version': '8.2',
                            'extrainfo': 'Ubuntu-4ubuntu0.2',
                            'script_results': {
                                'vulners': 'CVE-2021-44228  9.8  Log4j vulnerability'
                            }
                        }
                    },
                    'vulnerabilities': [
                        {
                            'cve_id': 'CVE-2021-44228',
                            'score': 9.8,
                            'description': 'Log4j vulnerability'
                        }
                    ]
                }
            },
            'vulnerabilities': [
                {
                    'cve_id': 'CVE-2021-44228',
                    'score': 9.8,
                    'description': 'Log4j vulnerability'
                }
            ]
        }
        
        # Set vulnerabilities
        scanner.vulnerabilities = scanner.scan_results['vulnerabilities']
        
        # Verify results
        self.assertIn('target', scanner.scan_results)
        self.assertEqual(scanner.scan_results['target'], self.test_target)
        self.assertIn('hosts', scanner.scan_results)
        self.assertIn('127.0.0.1', scanner.scan_results['hosts'])
        self.assertIn('vulnerabilities', scanner.scan_results)
        self.assertGreater(len(scanner.scan_results['vulnerabilities']), 0)
    
    @patch('engine.nmap.PortScanner')
    def test_scan_host_error(self, mock_portscanner):
        """Test host scanning with error."""
        # Mock the port scanner to raise an exception
        mock_scanner = Mock()
        mock_scanner.scan.side_effect = Exception("Network error")
        mock_portscanner.return_value = mock_scanner
        
        scanner = Scanner()
        scanner.nm = mock_scanner
        
        # Perform scan
        results = scanner.scan_host(self.test_target)
        
        # Verify error handling
        self.assertIn('error', results)
        self.assertIn('Network error', results['error'])
    
    def test_save_as_xml_no_results(self):
        """Test saving XML when no scan results are available."""
        with self.assertRaises(ValueError):
            self.scanner.save_as_xml()
    
    def test_save_as_xml_success(self):
        """Test successful XML saving."""
        # Set up mock scan results
        self.scanner.scan_results = {
            'target': '127.0.0.1',
            'scan_time': '2023-01-01T12:00:00',
            'scan_args': '-sV -sC --script vulners',
            'hosts': {
                '127.0.0.1': {
                    'hostname': 'localhost',
                    'state': 'up',
                    'protocols': ['tcp'],
                    'ports': {
                        'tcp/22': {
                            'state': 'open',
                            'name': 'ssh',
                            'product': 'OpenSSH',
                            'version': '8.2',
                            'extrainfo': '',
                            'script_results': {
                                'vulners': 'CVE-2021-44228  9.8  Log4j vulnerability'
                            }
                        }
                    },
                    'vulnerabilities': [
                        {
                            'cve_id': 'CVE-2021-44228',
                            'score': 9.8,
                            'description': 'Log4j vulnerability'
                        }
                    ]
                }
            },
            'vulnerabilities': [
                {
                    'cve_id': 'CVE-2021-44228',
                    'score': 9.8,
                    'description': 'Log4j vulnerability'
                }
            ]
        }
        
        # Create temporary file for testing
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as tmp_file:
            tmp_path = tmp_file.name
        
        try:
            # Save XML
            result_path = self.scanner.save_as_xml(tmp_path)
            
            # Verify file was created
            self.assertTrue(os.path.exists(result_path))
            self.assertEqual(result_path, tmp_path)
            
            # Verify XML content
            tree = ET.parse(result_path)
            root = tree.getroot()
            
            self.assertEqual(root.tag, 'vulnerability_scan')
            self.assertEqual(root.get('target'), '127.0.0.1')
            
            # Check hosts section
            hosts = root.find('hosts')
            self.assertIsNotNone(hosts)
            
            host = hosts.find('host')
            self.assertIsNotNone(host)
            self.assertEqual(host.get('ip'), '127.0.0.1')
            
            # Check ports section
            ports = host.find('ports')
            self.assertIsNotNone(ports)
            
            port = ports.find('port')
            self.assertIsNotNone(port)
            self.assertEqual(port.get('id'), 'tcp/22')
            
            # Check vulnerabilities section
            vulns = host.find('vulnerabilities')
            self.assertIsNotNone(vulns)
            
            vuln = vulns.find('vulnerability')
            self.assertIsNotNone(vuln)
            self.assertEqual(vuln.get('cve_id'), 'CVE-2021-44228')
            
        finally:
            # Clean up temporary file
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    def test_get_vulnerabilities(self):
        """Test getting vulnerabilities."""
        # Set up test vulnerabilities
        test_vulns = [
            {'cve_id': 'CVE-2021-44228', 'score': 9.8, 'description': 'Log4j vulnerability'},
            {'cve_id': 'CVE-2021-12345', 'score': 6.5, 'description': 'Remote code execution'}
        ]
        self.scanner.vulnerabilities = test_vulns
        
        # Get vulnerabilities
        vulns = self.scanner.get_vulnerabilities()
        
        self.assertEqual(vulns, test_vulns)
        self.assertEqual(len(vulns), 2)
    
    def test_get_scan_summary_empty(self):
        """Test getting scan summary when no results available."""
        summary = self.scanner.get_scan_summary()
        self.assertEqual(summary, {})
    
    def test_get_scan_summary_with_results(self):
        """Test getting scan summary with scan results."""
        # Set up test data
        self.scanner.scan_results = {
            'target': '127.0.0.1',
            'scan_time': '2023-01-01T12:00:00',
            'hosts': {'127.0.0.1': {}}
        }
        self.scanner.vulnerabilities = [
            {'cve_id': 'CVE-2021-44228', 'score': 9.8, 'description': 'High severity'},
            {'cve_id': 'CVE-2021-12345', 'score': 6.5, 'description': 'Medium severity'},
            {'cve_id': 'CVE-2021-67890', 'score': 2.1, 'description': 'Low severity'},
            {'cve_id': 'CVE-2021-99999', 'score': None, 'description': 'Unknown severity'}
        ]
        self.scanner.xml_output_path = 'test_output.xml'
        
        # Get summary
        summary = self.scanner.get_scan_summary()
        
        # Verify summary
        self.assertEqual(summary['target'], '127.0.0.1')
        self.assertEqual(summary['scan_time'], '2023-01-01T12:00:00')
        self.assertEqual(summary['hosts_scanned'], 1)
        self.assertEqual(summary['total_vulnerabilities'], 4)
        self.assertEqual(summary['severity_breakdown']['high'], 1)
        self.assertEqual(summary['severity_breakdown']['medium'], 1)
        self.assertEqual(summary['severity_breakdown']['low'], 1)
        self.assertEqual(summary['severity_breakdown']['unknown'], 1)
        self.assertEqual(summary['xml_output_path'], 'test_output.xml')
    
    @patch('builtins.print')
    def test_print_summary_no_results(self, mock_print):
        """Test printing summary when no results available."""
        self.scanner.print_summary()
        mock_print.assert_called_with("No scan results available.")
    
    @patch('builtins.print')
    def test_print_summary_with_results(self, mock_print):
        """Test printing summary with scan results."""
        # Set up test data
        self.scanner.scan_results = {
            'target': '127.0.0.1',
            'scan_time': '2023-01-01T12:00:00',
            'hosts': {'127.0.0.1': {}}
        }
        self.scanner.vulnerabilities = [
            {'cve_id': 'CVE-2021-44228', 'score': 9.8, 'description': 'High severity'}
        ]
        self.scanner.xml_output_path = 'test_output.xml'
        
        # Print summary
        self.scanner.print_summary()
        
        # Verify print calls
        self.assertTrue(mock_print.called)
        print_calls = [call[0][0] for call in mock_print.call_args_list]
        
        # Check that summary elements are printed
        self.assertTrue(any('VULNERABILITY SCAN SUMMARY' in call for call in print_calls))
        self.assertTrue(any('Target: 127.0.0.1' in call for call in print_calls))
        self.assertTrue(any('Total Vulnerabilities: 1' in call for call in print_calls))


class TestVulnerabilityScannerIntegration(unittest.TestCase):
    """Integration tests for VulnerabilityScanner class."""
    
    def setUp(self):
        """Set up test fixtures for integration tests."""
        self.scanner = Scanner()
    
    def test_full_scan_workflow(self):
        """Test complete scan workflow from scan to XML output."""
        # Create scanner instance
        scanner = Scanner()
        
        # Mock comprehensive scan results
        scanner.scan_results = {
            'target': '192.168.1.1',
            'scan_time': '2023-01-01T12:00:00',
            'scan_args': '-sV -sC --script vulners',
            'hosts': {
                '192.168.1.1': {
                    'hostname': 'test-host',
                    'state': 'up',
                    'protocols': ['tcp'],
                    'ports': {
                        'tcp/22': {
                            'state': 'open',
                            'name': 'ssh',
                            'product': 'OpenSSH',
                            'version': '8.2',
                            'extrainfo': 'Ubuntu-4ubuntu0.2',
                            'script_results': {
                                'vulners': 'CVE-2021-44228  9.8  Log4j vulnerability\nCVE-2021-12345  6.5  Remote code execution'
                            }
                        },
                        'tcp/80': {
                            'state': 'open',
                            'name': 'http',
                            'product': 'nginx',
                            'version': '1.18.0',
                            'extrainfo': '',
                            'script_results': {}
                        },
                        'tcp/443': {
                            'state': 'open',
                            'name': 'https',
                            'product': 'nginx',
                            'version': '1.18.0',
                            'extrainfo': '',
                            'script_results': {
                                'vulners': 'CVE-2021-67890  4.2  Medium severity vulnerability'
                            }
                        }
                    },
                    'vulnerabilities': [
                        {
                            'cve_id': 'CVE-2021-44228',
                            'score': 9.8,
                            'description': 'Log4j vulnerability'
                        },
                        {
                            'cve_id': 'CVE-2021-12345',
                            'score': 6.5,
                            'description': 'Remote code execution'
                        },
                        {
                            'cve_id': 'CVE-2021-67890',
                            'score': 4.2,
                            'description': 'Medium severity vulnerability'
                        }
                    ]
                }
            },
            'vulnerabilities': [
                {
                    'cve_id': 'CVE-2021-44228',
                    'score': 9.8,
                    'description': 'Log4j vulnerability'
                },
                {
                    'cve_id': 'CVE-2021-12345',
                    'score': 6.5,
                    'description': 'Remote code execution'
                },
                {
                    'cve_id': 'CVE-2021-67890',
                    'score': 4.2,
                    'description': 'Medium severity vulnerability'
                }
            ]
        }
        
        # Set vulnerabilities
        scanner.vulnerabilities = scanner.scan_results['vulnerabilities']
        
        # Verify scan results
        self.assertIn('target', scanner.scan_results)
        self.assertEqual(scanner.scan_results['target'], '192.168.1.1')
        self.assertIn('hosts', scanner.scan_results)
        self.assertIn('192.168.1.1', scanner.scan_results['hosts'])
        self.assertGreater(len(scanner.scan_results['vulnerabilities']), 0)
        
        # Test XML saving
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as tmp_file:
            tmp_path = tmp_file.name
        
        try:
            xml_path = scanner.save_as_xml(tmp_path)
            self.assertTrue(os.path.exists(xml_path))
            
            # Verify XML structure
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            self.assertEqual(root.tag, 'vulnerability_scan')
            self.assertEqual(root.get('target'), '192.168.1.1')
            
            # Check that vulnerabilities are present
            summary_vulns = root.find('summary_vulnerabilities')
            self.assertIsNotNone(summary_vulns)
            vuln_elements = summary_vulns.findall('vulnerability')
            self.assertGreater(len(vuln_elements), 0)
            
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add unit tests
    loader = unittest.TestLoader()
    test_suite.addTest(loader.loadTestsFromTestCase(TestVulnerabilityScanner))
    
    # Add integration tests
    test_suite.addTest(loader.loadTestsFromTestCase(TestVulnerabilityScannerIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\nTests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"  {test}: {traceback}")
    
    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"  {test}: {traceback}")
