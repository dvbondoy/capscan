"""
This is a triggered scan agent

Things to do:
1. List services [done]
2. scan Installed Software / Applications and its version [done]
Use: Win32_Product (slow, but built-in) or query registry:
3. Operating System Info [done]
OS version, build number, architecture:
4. scan Open Ports [done]
Use psutil or netstat
5. scan User Accounts and Privileges [done]
Useful to detect privilege escalation opportunities.
Also list:
Users with admin rights
Unused/disabled users
Users with weak passwords (test policy)
6. Startup Programs & Scheduled Tasks [done]
Check autostarts (persistence risks).
Use registry, schtasks, or tools like Autoruns.
7. Security Settings / Patch Status [done]
Check:
Windows Defender / AV status
Firewall config
Recent updates (wmic qfe)
8. Group Policy Settings [done]
Can reveal misconfigurations.
Use gpresult /h report.html to generate a report.
9. Registry Keys of Interest [done]
Like SMB v1 status, UAC, RDP settings.
10. Files of Interest
Detect:
World-writable binaries
Misconfigured services
Executables with dangerous permissions

research https with mtls for communication
research cython to protect agent code

Requirements:
wmi psutil pywin32
"""
import wmi
import psutil
import os
import winreg
import json
import socket
import subprocess
import requests
import time
from datetime import datetime

def get_os_info():
    c = wmi.WMI()

    # Collect OS version, build number, and architecture
    print("Collecting OS info...")
    os_info = c.Win32_OperatingSystem()[0]
    os_data = {
        "os": os_info.Caption,
        "version": os_info.Version,
        "build_number": os_info.BuildNumber,
        "architecture": os_info.OSArchitecture
    }
    return os_data

def get_pid_port_map():
    pid_port_map = {}
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == "LISTEN" and conn.pid:
            pid_port_map.setdefault(conn.pid, []).append(conn.laddr.port)
    return pid_port_map

def get_open_ports():
    print("Collecting open ports...")
    open_ports = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == "LISTEN" and conn.pid:
            open_ports.append({
                "pid": conn.pid,
                "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
            })
    return open_ports

def get_services():
    print("Collecting services...")
    services = []
    pid_port_map = get_pid_port_map()
    c = wmi.WMI()
    for service in c.Win32_Service(State="Running"):
        name = service.DisplayName
        pid = service.ProcessId
        ports = pid_port_map.get(pid, [])

        # Extract executable path
        path = None
        version = "Unknown"
        if service.PathName:
            path = service.PathName.strip('"').split(" ")[0]
            if os.path.exists(path):
                try:
                    wmic_path = path.replace("\\", "\\\\")
                    version_output = os.popen(
                        f'wmic datafile where name="{wmic_path}" get Version /value'
                    ).read()
                    version = version_output.strip().split("=")[-1] if "=" in version_output else "Unknown"
                except Exception:
                    version = "Unknown"
            else:
                path = "Not Found"
        else:
            path = "None"

        services.append({
            "name": name,
            "path": path,
            "version": version,
            "ports": ports
        })
    return services

def get_installed_software():
    print("Collecting installed software...")
    software_list = []
    reg_paths = [
        r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    ]
    hives = [
        (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
        (winreg.HKEY_CURRENT_USER, "HKCU")
    ]
    for hive, hive_name in hives:
        for reg_path in reg_paths:
            try:
                reg_key = winreg.OpenKey(hive, reg_path)
            except FileNotFoundError:
                continue
            for i in range(0, winreg.QueryInfoKey(reg_key)[0]):
                try:
                    subkey_name = winreg.EnumKey(reg_key, i)
                    subkey = winreg.OpenKey(reg_key, subkey_name)
                    name, version = None, None
                    try:
                        name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                    except FileNotFoundError:
                        continue
                    try:
                        version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                    except FileNotFoundError:
                        version = "Unknown"
                    software_list.append({
                        "name": name,
                        "version": version,
                        "source": f"{hive_name}\\{reg_path}"
                    })
                except Exception:
                    continue
    return software_list

def get_user_accounts():
    print("Collecting user accounts...")
    c = wmi.WMI()
    users = []
    for user in c.Win32_UserAccount(LocalAccount=True):
        users.append({
            "name": user.Name,
            "full_name": user.FullName,
            "description": user.Description,
            "disabled": user.Disabled,
            "lockout": user.Lockout,
            "password_changeable": user.PasswordChangeable,
            "password_expires": user.PasswordExpires,
            "password_required": user.PasswordRequired,
            "sid": user.SID,
            "status": user.Status,
        })
    return users

def get_admin_users():
    print("Collecting admin users...")
    c = wmi.WMI()
    admins = []
    for group in c.Win32_GroupUser():
        group_path = str(group.GroupComponent)
        if group_path.endswith('Name="Administrators"'):
            user = str(group.PartComponent).split('Name="')[1].split('"')[0]
            admins.append(user)
    return admins

def get_registry_autostarts():
    print("Collecting registry autostarts...")
    autostarts = []
    run_keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ]
    for hive, path in run_keys:
        try:
            reg_key = winreg.OpenKey(hive, path)
            for i in range(winreg.QueryInfoKey(reg_key)[1]):
                name, value, _ = winreg.EnumValue(reg_key, i)
                autostarts.append({
                    "location": f"{'HKLM' if hive == winreg.HKEY_LOCAL_MACHINE else 'HKCU'}\\{path}",
                    "name": name,
                    "command": value
                })
        except FileNotFoundError:
            continue
    return autostarts

def get_startup_folder_entries():
    print("Collecting startup folder entries...")
    startup_entries = []
    folders = [
        os.path.expandvars(r"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        os.path.expandvars(r"%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
    ]
    for folder in folders:
        if os.path.exists(folder):
            for entry in os.listdir(folder):
                startup_entries.append({
                    "folder": folder,
                    "entry": entry
                })
    return startup_entries

def get_scheduled_tasks():
    print("Collecting scheduled tasks...")
    c = wmi.WMI()
    tasks = []
    for task in c.Win32_ScheduledJob():
        tasks.append({
            "name": getattr(task, 'Name', None),
            "command": getattr(task, 'Command', None),
            "user": getattr(task, 'Owner', None),
            "run_time": str(getattr(task, 'RunTime', None)),
        })
    return tasks

def get_av_status():
    print("Collecting AV status...")
    try:
        c = wmi.WMI(namespace="root\\SecurityCenter2")
        av_products = []
        for av in c.AntiVirusProduct():
            av_products.append({
                "displayName": getattr(av, 'displayName', None),
                "productState": getattr(av, 'productState', None),
                "pathToSignedProductExe": getattr(av, 'pathToSignedProductExe', None),
            })
        return av_products
    except Exception:
        return []

def get_firewall_status():
    print("Collecting firewall status...")
    try:
        c = wmi.WMI(namespace="root\\StandardCimv2")
        fw = c.MSFT_NetFirewallProfile()
        return [{"name": getattr(f, 'Name', None), "enabled": getattr(f, 'Enabled', None)} for f in fw]
    except Exception:
        return []

def get_recent_updates():
    print("Collecting recent updates...")
    try:
        c = wmi.WMI()
        updates = []
        for qfe in c.Win32_QuickFixEngineering():
            updates.append({
                "hotfix_id": getattr(qfe, 'HotFixID', None),
                "description": getattr(qfe, 'Description', None),
                "installed_on": getattr(qfe, 'InstalledOn', None),
            })
        return updates
    except Exception:
        return []

def get_registry_security_settings():
    print("Collecting registry security settings...")
    """
    Checks registry keys for:
    - SMB1: SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1
        Possible values: 1 = enabled (insecure), 0 = disabled (secure), Not Present = secure (default on new Windows)
    - EnableLUA: SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
        Possible values: 1 = UAC enabled (secure), 0 = UAC disabled (insecure)
    - fDenyTSConnections: SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections
        Possible values: 1 = RDP disabled (secure), 0 = RDP enabled (insecure)
    """
    import winreg
    results = {}
    # SMB v1 status
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            smb1, _ = winreg.QueryValueEx(key, "SMB1")
            results["SMB1"] = smb1
    except FileNotFoundError:
        results["SMB1"] = "Not Present"
    except Exception as e:
        results["SMB1"] = str(e)
    # UAC status
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            enable_lua, _ = winreg.QueryValueEx(key, "EnableLUA")
            results["EnableLUA"] = enable_lua
    except FileNotFoundError:
        results["EnableLUA"] = "Not Present"
    except Exception as e:
        results["EnableLUA"] = str(e)
    # RDP status
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server") as key:
            fDenyTSConnections, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
            results["fDenyTSConnections"] = fDenyTSConnections
    except FileNotFoundError:
        results["fDenyTSConnections"] = "Not Present"
    except Exception as e:
        results["fDenyTSConnections"] = str(e)
    return results

def find_world_writable_files(paths=[r"C:\\Program Files", r"C:\\Windows\\System32"]):
    print("Collecting world-writable files...")
    """
    Uses icacls to find files in the given paths that are world-writable (Everyone or Users have Full or Modify access).
    Returns a list of file paths with dangerous permissions.
    """
    import subprocess
    world_writable = []
    for path in paths:
        try:
            result = subprocess.run(
                ["icacls", path, "/T", "/C"],
                capture_output=True, text=True, check=False
            )
            for line in result.stdout.splitlines():
                if ("Everyone:(F)" in line or "Everyone:(M)" in line or
                    "Users:(F)" in line or "Users:(M)" in line):
                    world_writable.append(line.strip())
        except Exception:
            continue
    return world_writable

def check_service_binary_permissions(services):
    print("Checking service binary permissions...")
    """
    For each service, checks if the binary path is world-writable.
    Returns a list of services with dangerous binary permissions.
    """
    import subprocess
    dangerous_services = []
    for svc in services:
        path = svc.get("path")
        if not path or path in ["None", "Not Found"]:
            continue
        try:
            result = subprocess.run(
                ["icacls", path],
                capture_output=True, text=True, check=False
            )
            output = result.stdout
            if ("Everyone:(F)" in output or "Everyone:(M)" in output or
                "Users:(F)" in output or "Users:(M)" in output):
                dangerous_services.append({
                    "service": svc.get("name"),
                    "path": path,
                    "icacls": output.strip()
                })
        except Exception:
            continue
    return dangerous_services

# Combine all data into a single variable for JSON serialization
scan_data = {
    "os_info": get_os_info(),
    "services": get_services(),
    "installed_software": get_installed_software(),
    "open_ports": get_open_ports(),
    "user_accounts": get_user_accounts(),
    "admin_users": get_admin_users(),
    "registry_autostarts": get_registry_autostarts(),
    "startup_folder_entries": get_startup_folder_entries(),
    "scheduled_tasks": get_scheduled_tasks(),
    "av_status": get_av_status(),
    "firewall_status": get_firewall_status(),
    "recent_updates": get_recent_updates(),
    "registry_security_settings": get_registry_security_settings(),
    "world_writable_files": find_world_writable_files(),
    "service_binary_permissions": check_service_binary_permissions(get_services())
}

class JWTAuthenticatedAgent:
    """JWT Authenticated Windows Agent for secure communication with scanner server."""
    
    def __init__(self, auth_server_url="http://localhost:8000", agent_id="agent_001", agent_secret=None):
        self.auth_server_url = auth_server_url
        self.agent_id = agent_id
        self.agent_secret = agent_secret or os.getenv(f"{agent_id.upper()}_SECRET", "secret_001")
        self.access_token = None
        self.token_expires_at = None
        self.session = requests.Session()
        
        print(f"🔐 Initializing JWT Agent: {agent_id}")
        print(f"🌐 Auth Server: {auth_server_url}")
    
    def authenticate(self):
        """Authenticate with the auth server and get JWT token."""
        try:
            credentials = {
                "agent_id": self.agent_id,
                "secret": self.agent_secret
            }
            
            print(f"🔑 Authenticating agent {self.agent_id}...")
            response = self.session.post(
                f"{self.auth_server_url}/auth/token",
                json=credentials,
                timeout=30
            )
            
            if response.status_code == 200:
                token_data = response.json()
                self.access_token = token_data["access_token"]
                self.token_expires_at = time.time() + token_data["expires_in"]
                
                print(f"✅ Authentication successful!")
                print(f"⏰ Token expires in {token_data['expires_in']} seconds")
                return True
            else:
                print(f"❌ Authentication failed: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Authentication request failed: {e}")
            return False
    
    def is_token_valid(self):
        """Check if the current token is still valid."""
        if not self.access_token:
            return False
        
        # Check if token is expired (with 60 second buffer)
        if self.token_expires_at and time.time() > (self.token_expires_at - 60):
            return False
        
        return True
    
    def get_auth_headers(self):
        """Get authentication headers for API requests."""
        if not self.is_token_valid():
            if not self.authenticate():
                return None
        
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
    
    def send_scan_report(self, scan_data, report_server_url="http://localhost:8001/report"):
        """Send scan report with JWT authentication."""
        headers = self.get_auth_headers()
        if not headers:
            print("❌ Failed to get authentication headers")
            return False
        
        try:
            print(f"📤 Sending scan report to {report_server_url}...")
            response = self.session.post(
                report_server_url,
                json=scan_data,
                headers=headers,
                timeout=60
            )
            
            if response.status_code == 200:
                print("✅ Scan report sent successfully!")
                return True
            else:
                print(f"❌ Failed to send scan report: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Failed to send scan report: {e}")
            return False
    
    def verify_token(self):
        """Verify the current token with the auth server."""
        headers = self.get_auth_headers()
        if not headers:
            return False
        
        try:
            response = self.session.get(
                f"{self.auth_server_url}/auth/verify",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                token_info = response.json()
                print(f"✅ Token verified for agent: {token_info.get('agent_id')}")
                return True
            else:
                print(f"❌ Token verification failed: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Token verification request failed: {e}")
            return False

def generate_gpresult_report(output_path="gpresult_report.html"):
    try:
        subprocess.run(["gpresult", "/h", output_path], check=True)
        return output_path
    except Exception as e:
        return None

if __name__ == "__main__":
    print("🔍 Starting Windows Security Scan...")
    print("=" * 50)
    
    # Initialize JWT authenticated agent
    agent = JWTAuthenticatedAgent(
        auth_server_url="http://localhost:8000",
        agent_id="agent_001"
    )
    
    # Authenticate first
    if not agent.authenticate():
        print("❌ Failed to authenticate. Exiting.")
        exit(1)
    
    # Verify token
    if not agent.verify_token():
        print("❌ Token verification failed. Exiting.")
        exit(1)
    
    print("\n📊 Collecting system information...")
    print("=" * 50)
    
    # Collect scan data
    scan_data = {
        "agent_id": agent.agent_id,
        "timestamp": datetime.utcnow().isoformat(),
        "os_info": get_os_info(),
        "services": get_services(),
        "installed_software": get_installed_software(),
        "open_ports": get_open_ports(),
        "user_accounts": get_user_accounts(),
        "admin_users": get_admin_users(),
        "registry_autostarts": get_registry_autostarts(),
        "startup_folder_entries": get_startup_folder_entries(),
        "scheduled_tasks": get_scheduled_tasks(),
        "av_status": get_av_status(),
        "firewall_status": get_firewall_status(),
        "recent_updates": get_recent_updates(),
        "registry_security_settings": get_registry_security_settings(),
        "world_writable_files": find_world_writable_files(),
        "service_binary_permissions": check_service_binary_permissions(get_services())
    }
    
    # Save scan data locally
    with open("scan_data.json", "w") as f:
        json.dump(scan_data, f, indent=2)
    print("✅ Scan data saved to scan_data.json")
    
    # Generate Group Policy report
    print("\n📋 Generating Group Policy report...")
    report_path = generate_gpresult_report()
    if report_path:
        print(f"✅ Group Policy report generated: {report_path}")
    else:
        print("⚠️  Failed to generate Group Policy report")
    
    # Send scan report with JWT authentication
    print("\n📤 Sending scan report to server...")
    success = agent.send_scan_report(scan_data)
    
    if success:
        print("🎉 Scan completed and report sent successfully!")
    else:
        print("❌ Failed to send scan report. Data saved locally.")
    
    print("\n📊 Scan Summary:")
    print(f"   - OS: {scan_data['os_info']['os']} {scan_data['os_info']['version']}")
    print(f"   - Services: {len(scan_data['services'])} running")
    print(f"   - Software: {len(scan_data['installed_software'])} installed")
    print(f"   - Open Ports: {len(scan_data['open_ports'])}")
    print(f"   - Users: {len(scan_data['user_accounts'])} local accounts")
    print(f"   - Admin Users: {len(scan_data['admin_users'])}")
    print(f"   - Autostarts: {len(scan_data['registry_autostarts'])}")
    print(f"   - Scheduled Tasks: {len(scan_data['scheduled_tasks'])}")