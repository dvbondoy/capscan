#!/usr/bin/env python3
"""
SSH Authenticated Scanner Module
Provides authenticated SSH scanning using nmap ssh-run script for enhanced vulnerability detection.
"""

import nmap
import re
import json
import os
import tempfile
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from services.exploitdb_service import ExploitDBService


@dataclass
class SSHCredentials:
    """SSH credentials container."""
    username: str
    password: Optional[str] = None
    private_key_path: Optional[str] = None
    passphrase: Optional[str] = None
    port: int = 22
    timeout: int = 30


@dataclass
class SystemInfo:
    """System information collected from SSH commands."""
    host_ip: str
    uname_output: str
    os_release: str
    package_list: List[Dict[str, str]]  # [{"name": "package", "version": "1.0"}]
    distro: str
    kernel_version: str
    architecture: str
    timestamp: str


class SSHAuthenticatedScanner:
    """
    SSH Authenticated Scanner using nmap ssh-run script.
    Executes system commands via SSH to gather detailed system information
    and match vulnerabilities with ExploitDB data.
    """
    
    def __init__(self, exploitdb_service: Optional[ExploitDBService] = None):
        """
        Initialize SSH Authenticated Scanner.
        
        Args:
            exploitdb_service: ExploitDB service instance for vulnerability matching
        """
        self.nm = nmap.PortScanner()
        self.exploitdb_service = exploitdb_service or ExploitDBService()
        self.ssh_results = {}
        self.system_inventory = {}
        
    def scan_hosts_with_ssh(self, 
                           targets: List[str], 
                           credentials: SSHCredentials,
                           commands: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Scan hosts using SSH authentication to gather system information.
        
        Args:
            targets: List of target IP addresses or hostnames
            credentials: SSH credentials for authentication
            commands: Custom commands to run (optional)
            
        Returns:
            Dict containing scan results and system information
        """
        if not commands:
            commands = self._get_default_commands()
        
        print(f"Starting SSH authenticated scan for {len(targets)} targets")
        
        scan_results = {
            'scan_time': datetime.now().isoformat(),
            'targets': targets,
            'credentials_used': {
                'username': credentials.username,
                'port': credentials.port,
                'auth_method': 'key' if credentials.private_key_path else 'password'
            },
            'hosts': {},
            'vulnerabilities': [],
            'system_inventory': {}
        }
        
        for target in targets:
            try:
                print(f"Scanning {target} with SSH authentication...")
                host_results = self._scan_single_host_ssh(target, credentials, commands)
                scan_results['hosts'][target] = host_results
                
                print(f"DEBUG: Host {target} scan status: {host_results.get('status', 'unknown')}")
                print(f"DEBUG: Host {target} has system_info: {host_results.get('system_info') is not None}")
                
                if host_results.get('system_info'):
                    self.system_inventory[target] = host_results['system_info']
                    print(f"DEBUG: Starting vulnerability matching for {target}")
                    # Match vulnerabilities based on system information
                    vulnerabilities = self._match_vulnerabilities_from_system_info(
                        target, host_results['system_info']
                    )
                    print(f"DEBUG: Found {len(vulnerabilities)} vulnerabilities for {target}")
                    scan_results['vulnerabilities'].extend(vulnerabilities)
                    scan_results['system_inventory'][target] = host_results['system_info']
                else:
                    print(f"DEBUG: No system_info for {target}, skipping vulnerability matching")
                
            except Exception as e:
                print(f"Error scanning {target}: {str(e)}")
                scan_results['hosts'][target] = {
                    'error': str(e),
                    'status': 'failed'
                }
        
        self.ssh_results = scan_results
        print(f"SSH scan completed. Found {len(scan_results['vulnerabilities'])} vulnerabilities")
        return scan_results
    
    def _scan_single_host_ssh(self, 
                             target: str, 
                             credentials: SSHCredentials, 
                             commands: List[str]) -> Dict[str, Any]:
        """
        Scan a single host using SSH authentication.
        
        Args:
            target: Target host IP or hostname
            credentials: SSH credentials
            commands: Commands to execute
            
        Returns:
            Dict containing scan results for the host
        """
        host_results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'status': 'unknown',
            'system_info': None,
            'command_outputs': {},
            'errors': []
        }
        
        try:
            # First, detect the operating system
            distro_info = self._detect_os_distro(target, credentials)
            if not distro_info:
                host_results['status'] = 'failed'
                host_results['errors'].append("Could not detect operating system")
                return host_results
            
            # Execute commands based on detected OS
            os_commands = self._get_os_specific_commands(distro_info['distro'])
            command_outputs = {}
            
            for command in os_commands:
                try:
                    output = self._execute_ssh_command(target, credentials, command)
                    command_outputs[command] = output
                except Exception as e:
                    command_outputs[command] = {'error': str(e), 'output': '', 'exit_code': -1}
                    host_results['errors'].append(f"Command '{command}' failed: {str(e)}")
            
            # Parse system information
            system_info = self._parse_system_information(target, command_outputs, distro_info)
            host_results['system_info'] = system_info
            host_results['command_outputs'] = command_outputs
            host_results['status'] = 'success'
            
        except Exception as e:
            host_results['status'] = 'failed'
            host_results['errors'].append(str(e))
        
        return host_results
    
    def _detect_os_distro(self, target: str, credentials: SSHCredentials) -> Optional[Dict[str, str]]:
        """
        Detect operating system and distribution.
        
        Args:
            target: Target host
            credentials: SSH credentials
            
        Returns:
            Dict containing OS information
        """
        # Try multiple detection methods
        detection_commands = [
            "cat /etc/os-release 2>/dev/null || echo 'NO_OS_RELEASE'",
            "cat /etc/lsb-release 2>/dev/null || echo 'NO_LSB_RELEASE'",
            "uname -a"
        ]
        
        try:
            print(f"DEBUG: Attempting to detect OS for {target}")
            
            # Try os-release first
            output = self._execute_ssh_command(target, credentials, detection_commands[0])
            if output.get('exit_code') == 0 and 'NO_OS_RELEASE' not in output.get('output', ''):
                print(f"DEBUG: Found /etc/os-release for {target}")
                distro_info = self._parse_os_release(output.get('output', ''))
                if distro_info.get('distro'):
                    print(f"DEBUG: Parsed distro info from os-release: {distro_info}")
                    return distro_info
            
            # Try lsb-release
            output = self._execute_ssh_command(target, credentials, detection_commands[1])
            if output.get('exit_code') == 0 and 'NO_LSB_RELEASE' not in output.get('output', ''):
                print(f"DEBUG: Found /etc/lsb-release for {target}")
                distro_info = self._parse_lsb_release(output.get('output', ''))
                if distro_info.get('distro'):
                    print(f"DEBUG: Parsed distro info from lsb-release: {distro_info}")
                    return distro_info
            
            # Fallback to uname
            output = self._execute_ssh_command(target, credentials, detection_commands[2])
            if output.get('exit_code') == 0:
                print(f"DEBUG: Using uname for {target}")
                distro_info = self._parse_uname(output.get('output', ''))
                print(f"DEBUG: Parsed distro info from uname: {distro_info}")
                return distro_info
            
            print(f"DEBUG: Could not detect OS for {target}")
            return None
            
        except Exception as e:
            print(f"Error detecting OS for {target}: {e}")
            return None
    
    def _execute_ssh_command(self, target: str, credentials: SSHCredentials, command: str) -> Dict[str, Any]:
        """
        Execute a command via SSH using nmap ssh-run script.
        
        Args:
            target: Target host
            credentials: SSH credentials
            command: Command to execute
            
        Returns:
            Dict containing command output and metadata
        """
        # Build nmap command with ssh-run script
        nmap_args = f"-p{credentials.port} --script ssh-run --script-args"
        
        # Add authentication parameters with correct ssh-run prefix
        script_args = []
        script_args.append(f"ssh-run.username={credentials.username}")
        
        if credentials.private_key_path:
            script_args.append(f"ssh-run.privatekey={credentials.private_key_path}")
            if credentials.passphrase:
                script_args.append(f"ssh-run.passphrase={credentials.passphrase}")
        elif credentials.password:
            script_args.append(f"ssh-run.password={credentials.password}")
        
        # Escape the command properly
        escaped_command = command.replace('"', '\\"').replace("'", "\\'")
        script_args.append(f"ssh-run.cmd=\"{escaped_command}\"")
        
        # Combine arguments - use proper format for ssh-run script
        script_args_str = ",".join(script_args)
        full_args = f"{nmap_args} {script_args_str} -Pn -n --host-timeout={credentials.timeout}s"
        
        try:
            print(f"DEBUG: Executing nmap SSH command for {target}")
            print(f"DEBUG: Full nmap args: {full_args}")
            
            # Execute nmap scan
            self.nm.scan(target, arguments=full_args)
            
            print(f"DEBUG: Nmap scan completed for {target}")
            print(f"DEBUG: Available hosts: {self.nm.all_hosts()}")
            
            if target not in self.nm.all_hosts():
                print(f"DEBUG: Target {target} not found in nmap results")
                return {'error': 'Host not reachable', 'output': '', 'exit_code': -1}
            
            # Extract script output
            port_info = self.nm[target]['tcp'].get(credentials.port, {})
            script_results = port_info.get('script', {})
            
            print(f"DEBUG: Port info for {target}:{credentials.port}: {port_info}")
            print(f"DEBUG: Script results for {target}: {script_results}")
            
            if 'ssh-run' in script_results:
                ssh_output = script_results['ssh-run']
                print(f"DEBUG: SSH script output for {target}: {ssh_output}")
                return self._parse_ssh_run_output(ssh_output)
            else:
                print(f"DEBUG: SSH script did not run for {target}")
                return {'error': 'SSH script did not run', 'output': '', 'exit_code': -1}
                
        except Exception as e:
            print(f"DEBUG: Exception during SSH command execution for {target}: {e}")
            return {'error': str(e), 'output': '', 'exit_code': -1}
    
    def _parse_ssh_run_output(self, ssh_output: str) -> Dict[str, Any]:
        """
        Parse output from nmap ssh-run script.
        
        Args:
            ssh_output: Raw output from ssh-run script
            
        Returns:
            Dict containing parsed output
        """
        lines = ssh_output.strip().split('\n')
        output_lines = []
        exit_code = 0
        
        # Parse the new format from ssh-run script
        in_output_section = False
        for line in lines:
            line = line.strip()
            if line.startswith('output:'):
                in_output_section = True
                continue
            elif in_output_section and line:
                if line.startswith('|'):
                    # Remove the | prefix
                    output_lines.append(line[1:].strip())
                elif not line.startswith('|') and not line.startswith('_'):
                    # Regular output line
                    output_lines.append(line)
            elif 'exit code' in line.lower():
                # Extract exit code
                try:
                    exit_code = int(re.search(r'(\d+)', line).group(1))
                except:
                    exit_code = 0
        
        return {
            'output': '\n'.join(output_lines),
            'exit_code': exit_code,
            'raw_output': ssh_output
        }
    
    def _get_default_commands(self) -> List[str]:
        """Get default commands to execute."""
        return [
            "uname -a",
            "cat /etc/os-release",
            "whoami",
            "id"
        ]
    
    def _get_os_specific_commands(self, distro: str) -> List[str]:
        """
        Get OS-specific commands based on detected distribution.
        
        Args:
            distro: Detected distribution name
            
        Returns:
            List of commands to execute
        """
        base_commands = [
            "uname -a",
            "cat /etc/os-release",
            "whoami",
            "id"
        ]
        
        if 'debian' in distro.lower() or 'ubuntu' in distro.lower():
            base_commands.extend([
                "dpkg -l | head -100",  # Limit output size
                "lsb_release -a 2>/dev/null || true",
                "cat /proc/version"
            ])
        elif 'redhat' in distro.lower() or 'centos' in distro.lower() or 'fedora' in distro.lower():
            base_commands.extend([
                "rpm -qa | head -100",  # Limit output size
                "cat /etc/redhat-release 2>/dev/null || true",
                "cat /proc/version"
            ])
        elif 'suse' in distro.lower():
            base_commands.extend([
                "rpm -qa | head -100",
                "cat /etc/SuSE-release 2>/dev/null || true",
                "cat /proc/version"
            ])
        else:
            # Generic Linux commands
            base_commands.extend([
                "cat /proc/version",
                "ls -la /etc/*release 2>/dev/null || true"
            ])
        
        return base_commands
    
    def _parse_os_release(self, content: str) -> Dict[str, str]:
        """Parse /etc/os-release content."""
        distro_info = {
            'distro': 'unknown',
            'version': 'unknown',
            'id': 'unknown',
            'name': 'unknown'
        }
        
        for line in content.split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip().lower()
                value = value.strip().strip('"')
                
                if key == 'id':
                    distro_info['id'] = value
                elif key == 'name':
                    distro_info['name'] = value
                elif key == 'version_id':
                    distro_info['version'] = value
                elif key == 'id_like':
                    distro_info['distro'] = value
        
        # Set distro based on ID
        if distro_info['id'] != 'unknown':
            distro_info['distro'] = distro_info['id']
        
        return distro_info
    
    def _parse_lsb_release(self, content: str) -> Dict[str, str]:
        """Parse /etc/lsb-release content."""
        distro_info = {
            'distro': 'unknown',
            'version': 'unknown',
            'id': 'unknown',
            'name': 'unknown'
        }
        
        for line in content.split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip().lower()
                value = value.strip().strip('"')
                
                if key == 'distrib_id':
                    distro_info['id'] = value.lower()
                    distro_info['distro'] = value.lower()
                elif key == 'distrib_release':
                    distro_info['version'] = value
                elif key == 'distrib_description':
                    distro_info['name'] = value
        
        return distro_info
    
    def _parse_uname(self, content: str) -> Dict[str, str]:
        """Parse uname -a output."""
        distro_info = {
            'distro': 'unknown',
            'version': 'unknown',
            'id': 'unknown',
            'name': 'unknown'
        }
        
        # Extract kernel version
        kernel_match = re.search(r'Linux\s+([^\s]+)', content)
        if kernel_match:
            distro_info['version'] = kernel_match.group(1)
        
        # Try to identify distribution from uname
        content_lower = content.lower()
        if 'ubuntu' in content_lower:
            distro_info['distro'] = 'ubuntu'
        elif 'debian' in content_lower:
            distro_info['distro'] = 'debian'
        elif 'centos' in content_lower:
            distro_info['distro'] = 'centos'
        elif 'redhat' in content_lower:
            distro_info['distro'] = 'redhat'
        elif 'fedora' in content_lower:
            distro_info['distro'] = 'fedora'
        
        return distro_info
    
    def _parse_system_information(self, 
                                 host_ip: str, 
                                 command_outputs: Dict[str, Dict[str, Any]], 
                                 distro_info: Dict[str, str]) -> SystemInfo:
        """
        Parse system information from command outputs.
        
        Args:
            host_ip: Host IP address
            command_outputs: Outputs from executed commands
            distro_info: OS distribution information
            
        Returns:
            SystemInfo object
        """
        uname_output = command_outputs.get('uname -a', {}).get('output', '')
        os_release = command_outputs.get('cat /etc/os-release', {}).get('output', '')
        
        # Parse package list
        package_list = []
        
        # Look for dpkg command (could be 'dpkg -l' or 'dpkg -l | head -100')
        dpkg_key = None
        for key in command_outputs.keys():
            if 'dpkg -l' in key:
                dpkg_key = key
                break
        
        if dpkg_key:
            dpkg_output = command_outputs[dpkg_key].get('output', '')
            print(f"DEBUG: Found dpkg command: {dpkg_key}")
            print(f"DEBUG: dpkg output length: {len(dpkg_output)}")
            print(f"DEBUG: dpkg output preview: {dpkg_output[:200]}...")
            package_list = self._parse_dpkg_output(dpkg_output)
            print(f"DEBUG: Parsed {len(package_list)} packages from dpkg output")
        else:
            # Look for rpm command (could be 'rpm -qa' or 'rpm -qa | head -100')
            rpm_key = None
            for key in command_outputs.keys():
                if 'rpm -qa' in key:
                    rpm_key = key
                    break
            
            if rpm_key:
                rpm_output = command_outputs[rpm_key].get('output', '')
                print(f"DEBUG: Found rpm command: {rpm_key}")
                print(f"DEBUG: rpm output length: {len(rpm_output)}")
                package_list = self._parse_rpm_output(rpm_output)
                print(f"DEBUG: Parsed {len(package_list)} packages from rpm output")
            else:
                print("DEBUG: No package manager commands found in command outputs")
                print(f"DEBUG: Available commands: {list(command_outputs.keys())}")
        
        # Extract kernel version and architecture
        kernel_version = self._extract_kernel_version(uname_output)
        architecture = self._extract_architecture(uname_output)
        
        return SystemInfo(
            host_ip=host_ip,
            uname_output=uname_output,
            os_release=os_release,
            package_list=package_list,
            distro=distro_info.get('distro', 'unknown'),
            kernel_version=kernel_version,
            architecture=architecture,
            timestamp=datetime.now().isoformat()
        )
    
    def _parse_dpkg_output(self, output: str) -> List[Dict[str, str]]:
        """Parse dpkg -l output."""
        packages = []
        lines = output.split('\n')
        
        print(f"DEBUG: Processing {len(lines)} lines from dpkg output")
        
        for i, line in enumerate(lines):
            line = line.strip()
            
            # Skip empty lines
            if not line:
                continue
                
            # Look for lines that start with 'ii' (installed packages)
            if line.startswith('ii'):
                # Split by whitespace but handle multiple spaces
                parts = line.split()
                if len(parts) >= 3:
                    # Find the package name and version
                    # Format: ii  package-name  version  description...
                    package_name = parts[1]
                    version = parts[2]
                    
                    packages.append({
                        'name': package_name,
                        'version': version,
                        'manager': 'dpkg'
                    })
                    
                    if len(packages) <= 5:  # Debug first few packages
                        print(f"DEBUG: Parsed package {len(packages)}: {package_name} = {version}")
                else:
                    print(f"DEBUG: Skipping malformed line {i}: {line[:50]}...")
            # Also handle lines that start with '|' followed by 'ii' (from nmap output format)
            elif line.startswith('|') and 'ii' in line:
                # Remove the '|' prefix and parse
                clean_line = line[1:].strip()
                if clean_line.startswith('ii'):
                    parts = clean_line.split()
                    if len(parts) >= 3:
                        package_name = parts[1]
                        version = parts[2]
                        
                        packages.append({
                            'name': package_name,
                            'version': version,
                            'manager': 'dpkg'
                        })
                        
                        if len(packages) <= 5:  # Debug first few packages
                            print(f"DEBUG: Parsed package {len(packages)}: {package_name} = {version}")
            # Debug: Show what we're skipping
            elif i < 10:  # Only show first 10 non-matching lines for debugging
                print(f"DEBUG: Skipping line {i}: {line[:50]}...")
        
        print(f"DEBUG: Total packages parsed: {len(packages)}")
        return packages
    
    def _parse_rpm_output(self, output: str) -> List[Dict[str, str]]:
        """Parse rpm -qa output."""
        packages = []
        lines = output.split('\n')
        
        for line in lines:
            if line.strip():
                # RPM format: name-version-release.arch
                parts = line.rsplit('-', 2)
                if len(parts) >= 2:
                    packages.append({
                        'name': parts[0],
                        'version': '-'.join(parts[1:]),
                        'manager': 'rpm'
                    })
        
        return packages
    
    def _extract_kernel_version(self, uname_output: str) -> str:
        """Extract kernel version from uname output."""
        match = re.search(r'Linux\s+([^\s]+)', uname_output)
        return match.group(1) if match else 'unknown'
    
    def _extract_architecture(self, uname_output: str) -> str:
        """Extract architecture from uname output."""
        match = re.search(r'(\w+)$', uname_output)
        return match.group(1) if match else 'unknown'
    
    def _match_vulnerabilities_from_system_info(self, 
                                               host_ip: str, 
                                               system_info: SystemInfo) -> List[Dict[str, Any]]:
        """
        Match vulnerabilities based on system information.
        
        Args:
            host_ip: Host IP address
            system_info: System information
            
        Returns:
            List of matched vulnerabilities
        """
        vulnerabilities = []
        
        print(f"DEBUG: Starting vulnerability matching for {host_ip}")
        print(f"DEBUG: System info - distro: {system_info.distro}, kernel: {system_info.kernel_version}")
        print(f"DEBUG: Package list length: {len(system_info.package_list)}")
        print(f"DEBUG: ExploitDB service available: {self.exploitdb_service is not None}")
        
        # Check if ExploitDB has data
        if hasattr(self.exploitdb_service, 'exploits_data'):
            print(f"DEBUG: ExploitDB data loaded: {len(self.exploitdb_service.exploits_data)} exploits")
        else:
            print("DEBUG: ExploitDB data not loaded")
        
        # Limit package processing to prevent hanging
        max_packages = 50  # Process only first 50 packages to prevent timeout
        packages_to_process = system_info.package_list[:max_packages]
        
        print(f"Processing {len(packages_to_process)} packages for vulnerability matching (limited from {len(system_info.package_list)})")
        
        # Match vulnerabilities for each package
        for i, package in enumerate(packages_to_process):
            try:
                print(f"Processing package {i+1}/{len(packages_to_process)}: {package['name']}")
                package_vulns = self._find_package_vulnerabilities(package, system_info)
                vulnerabilities.extend(package_vulns)
                
                # Add small delay to prevent overwhelming the system
                import time
                time.sleep(0.1)
                
            except Exception as e:
                print(f"Error processing package {package['name']}: {e}")
                continue
        
        # Match kernel vulnerabilities
        try:
            print("Processing kernel vulnerabilities...")
            kernel_vulns = self._find_kernel_vulnerabilities(system_info)
            vulnerabilities.extend(kernel_vulns)
        except Exception as e:
            print(f"Error processing kernel vulnerabilities: {e}")
        
        # Match OS-level vulnerabilities
        try:
            print("Processing OS vulnerabilities...")
            os_vulns = self._find_os_vulnerabilities(system_info)
            vulnerabilities.extend(os_vulns)
        except Exception as e:
            print(f"Error processing OS vulnerabilities: {e}")
        
        print(f"Vulnerability matching completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _find_package_vulnerabilities(self, 
                                    package: Dict[str, str], 
                                    system_info: SystemInfo) -> List[Dict[str, Any]]:
        """
        Find vulnerabilities for a specific package.
        
        Args:
            package: Package information
            system_info: System information
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        package_name = package['name']
        package_version = package['version']
        
        # Skip common system packages that are unlikely to have vulnerabilities
        skip_packages = [
            'libc6', 'libgcc1', 'libstdc++6', 'libc6-dev', 'gcc-9-base',
            'libc-bin', 'libc-dev-bin', 'libc6-dbg', 'libc6-i386',
            'libc6-x32', 'libc6-dev-i386', 'libc6-dev-x32', 'libc6-pic',
            'libc6-prof', 'libc6-udeb', 'libc6-udeb-i386', 'libc6-udeb-x32',
            'libc6-udeb-x32', 'libc6-udeb-i386', 'libc6-udeb-x32'
        ]
        
        if package_name in skip_packages:
            return vulnerabilities
        
        # Search ExploitDB for package-related vulnerabilities (reduced search terms)
        search_terms = [
            package_name,  # Most important search
            f"{package_name} vulnerability"  # Second most important
        ]
        
        for term in search_terms:
            try:
                exploits = self.exploitdb_service.search_exploits(term, limit=5)  # Reduced limit
                for exploit in exploits:
                    vuln = self._create_vulnerability_from_exploit(exploit, package, system_info)
                    if vuln:
                        vulnerabilities.append(vuln)
                        
                        # Limit vulnerabilities per package to prevent overwhelming results
                        if len(vulnerabilities) >= 3:
                            break
                            
            except Exception as e:
                print(f"Error searching vulnerabilities for {package_name}: {e}")
                continue
            
            # Break if we found vulnerabilities to avoid redundant searches
            if vulnerabilities:
                break
        
        return vulnerabilities
    
    def _find_kernel_vulnerabilities(self, system_info: SystemInfo) -> List[Dict[str, Any]]:
        """Find kernel-related vulnerabilities."""
        vulnerabilities = []
        
        if system_info.kernel_version == 'unknown':
            return vulnerabilities
        
        # Search for kernel vulnerabilities (reduced search terms)
        search_terms = [
            f"linux kernel {system_info.kernel_version}",
            "linux kernel vulnerability"
        ]
        
        for term in search_terms:
            try:
                exploits = self.exploitdb_service.search_exploits(term, limit=3)  # Reduced limit
                for exploit in exploits:
                    vuln = self._create_vulnerability_from_exploit(exploit, None, system_info)
                    if vuln:
                        vuln['vulnerability_type'] = 'kernel_vulnerability'
                        vulnerabilities.append(vuln)
                        
                        # Limit kernel vulnerabilities
                        if len(vulnerabilities) >= 2:
                            break
                            
            except Exception as e:
                print(f"Error searching kernel vulnerabilities: {e}")
                continue
            
            # Break if we found vulnerabilities
            if vulnerabilities:
                break
        
        return vulnerabilities
    
    def _find_os_vulnerabilities(self, system_info: SystemInfo) -> List[Dict[str, Any]]:
        """Find OS-level vulnerabilities."""
        vulnerabilities = []
        
        # Skip if distro is unknown
        if system_info.distro == 'unknown':
            return vulnerabilities
        
        # Search for OS-specific vulnerabilities (reduced search terms)
        search_terms = [
            f"{system_info.distro} vulnerability"
        ]
        
        for term in search_terms:
            try:
                exploits = self.exploitdb_service.search_exploits(term, limit=3)  # Reduced limit
                for exploit in exploits:
                    vuln = self._create_vulnerability_from_exploit(exploit, None, system_info)
                    if vuln:
                        vuln['vulnerability_type'] = 'os_vulnerability'
                        vulnerabilities.append(vuln)
                        
                        # Limit OS vulnerabilities
                        if len(vulnerabilities) >= 2:
                            break
                            
            except Exception as e:
                print(f"Error searching OS vulnerabilities: {e}")
                continue
            
            # Break if we found vulnerabilities
            if vulnerabilities:
                break
        
        return vulnerabilities
    
    def _create_vulnerability_from_exploit(self, 
                                         exploit: Dict[str, Any], 
                                         package: Optional[Dict[str, str]], 
                                         system_info: SystemInfo) -> Optional[Dict[str, Any]]:
        """
        Create vulnerability entry from ExploitDB exploit.
        
        Args:
            exploit: ExploitDB exploit data
            package: Package information (if applicable)
            system_info: System information
            
        Returns:
            Vulnerability dictionary or None
        """
        try:
            # Extract CVE IDs
            cves = self._extract_cves_from_exploit(exploit)
            if not cves:
                return None
            
            # Create vulnerability entry
            vuln = {
                'cve_id': cves[0],  # Use first CVE
                'all_cves': cves,
                'description': exploit.get('description', ''),
                'exploit_id': exploit.get('id', ''),
                'attack_type': exploit.get('attack_type', 'unknown'),
                'platform': exploit.get('platform', ''),
                'verified': exploit.get('is_verified', False),
                'complexity': exploit.get('complexity', 'unknown'),
                'host_ip': system_info.host_ip,
                'vulnerability_type': 'package_vulnerability' if package else 'system_vulnerability',
                'package_name': package['name'] if package else None,
                'package_version': package['version'] if package else None,
                'os_distro': system_info.distro,
                'kernel_version': system_info.kernel_version,
                'architecture': system_info.architecture,
                'discovery_method': 'ssh_authenticated_scan',
                'scan_time': datetime.now().isoformat(),
                'references': self._extract_references(exploit),
                'tags': exploit.get('parsed_tags', []),
                'date_published': exploit.get('date_published'),
                'score': self._calculate_vulnerability_score(exploit, package, system_info)
            }
            
            return vuln
            
        except Exception as e:
            print(f"Error creating vulnerability from exploit: {e}")
            return None
    
    def _extract_cves_from_exploit(self, exploit: Dict[str, Any]) -> List[str]:
        """Extract CVE IDs from exploit data."""
        cves = []
        
        # Check codes field
        codes = exploit.get('codes', '')
        if codes:
            cve_pattern = r'CVE-\d{4}-\d{4,7}'
            cves.extend(re.findall(cve_pattern, codes, re.IGNORECASE))
        
        # Check aliases field
        aliases = exploit.get('aliases', '')
        if aliases:
            cve_pattern = r'CVE-\d{4}-\d{4,7}'
            cves.extend(re.findall(cve_pattern, aliases, re.IGNORECASE))
        
        return list(set(cves))  # Remove duplicates
    
    def _extract_references(self, exploit: Dict[str, Any]) -> List[str]:
        """Extract reference URLs from exploit."""
        references = []
        
        # Check source_url
        if exploit.get('source_url'):
            references.append(exploit['source_url'])
        
        # Check application_url
        if exploit.get('application_url'):
            references.append(exploit['application_url'])
        
        return references
    
    def _calculate_vulnerability_score(self, 
                                     exploit: Dict[str, Any], 
                                     package: Optional[Dict[str, str]], 
                                     system_info: SystemInfo) -> float:
        """Calculate vulnerability score based on various factors."""
        base_score = 5.0  # Base score
        
        # Verified exploits get higher score
        if exploit.get('is_verified', False):
            base_score += 2.0
        
        # High complexity exploits get higher score
        complexity = exploit.get('complexity', 'unknown')
        if complexity == 'high':
            base_score += 1.5
        elif complexity == 'medium':
            base_score += 1.0
        
        # Recent exploits get higher score
        date_published = exploit.get('date_published')
        if date_published:
            try:
                pub_date = datetime.fromisoformat(str(date_published).replace('Z', '+00:00'))
                years_old = (datetime.now() - pub_date).days / 365
                if years_old < 1:
                    base_score += 1.0
                elif years_old < 3:
                    base_score += 0.5
            except:
                pass
        
        # Package-specific vulnerabilities get higher score
        if package:
            base_score += 0.5
        
        return min(base_score, 10.0)  # Cap at 10.0
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get summary of SSH scan results."""
        if not self.ssh_results:
            return {}
        
        total_hosts = len(self.ssh_results.get('hosts', {}))
        successful_scans = len([h for h in self.ssh_results.get('hosts', {}).values() 
                              if h.get('status') == 'success'])
        total_vulnerabilities = len(self.ssh_results.get('vulnerabilities', []))
        
        # Count vulnerabilities by type
        vuln_types = {}
        for vuln in self.ssh_results.get('vulnerabilities', []):
            vuln_type = vuln.get('vulnerability_type', 'unknown')
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        return {
            'total_hosts': total_hosts,
            'successful_scans': successful_scans,
            'failed_scans': total_hosts - successful_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'vulnerability_types': vuln_types,
            'scan_time': self.ssh_results.get('scan_time', ''),
            'credentials_used': self.ssh_results.get('credentials_used', {})
        }
    
    def save_results_to_file(self, output_path: str) -> str:
        """Save SSH scan results to JSON file."""
        if not self.ssh_results:
            raise ValueError("No scan results to save")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.ssh_results, f, indent=2, default=str)
        
        print(f"SSH scan results saved to: {output_path}")
        return output_path


# Example usage
if __name__ == "__main__":
    # Initialize services
    exploitdb_service = ExploitDBService()
    ssh_scanner = SSHAuthenticatedScanner(exploitdb_service)
    
    # Example credentials
    credentials = SSHCredentials(
        username="testuser",
        password="testpass",
        port=22,
        timeout=30
    )
    
    # Example scan
    targets = ["192.168.1.100", "192.168.1.101"]
    results = ssh_scanner.scan_hosts_with_ssh(targets, credentials)
    
    # Print summary
    summary = ssh_scanner.get_scan_summary()
    print(f"Scan completed: {summary['successful_scans']}/{summary['total_hosts']} hosts successful")
    print(f"Found {summary['total_vulnerabilities']} vulnerabilities")
