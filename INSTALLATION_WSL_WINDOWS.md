# CapScan Installation Guide - Windows WSL Ubuntu

This guide provides step-by-step instructions for installing CapScan vulnerability scanner on Windows using WSL (Windows Subsystem for Linux) with Ubuntu.

## Prerequisites

### System Requirements
- Windows 10 version 2004 and higher (Build 19041 and higher) or Windows 11
- WSL 2 enabled
- Ubuntu distribution installed in WSL
- Administrator privileges on Windows

## Step 1: Enable WSL and Install Ubuntu

### 1.1 Enable WSL Feature
Open PowerShell as Administrator and run:
```powershell
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

### 1.2 Restart Your Computer
Restart your computer to complete the WSL installation.

### 1.3 Set WSL 2 as Default
After restart, open PowerShell as Administrator and run:
```powershell
wsl --set-default-version 2
```

### 1.4 Install Ubuntu
1. Open Microsoft Store
2. Search for "Ubuntu"
3. Install "Ubuntu" (latest LTS version recommended)
4. Launch Ubuntu from Start Menu
5. Create a username and password when prompted

## Step 2: Update Ubuntu System

Open Ubuntu terminal in WSL and run:
```bash
sudo apt update && sudo apt upgrade -y
```

## Step 3: Install Python and pip

### 3.1 Install Python 3.9+ and pip
```bash
sudo apt install python3 python3-pip python3-venv -y
```

### 3.2 Verify Installation
```bash
python3 --version
pip3 --version
```

## Step 4: Install nmap

### 4.1 Install nmap
```bash
sudo apt install nmap -y
```

### 4.2 Verify nmap Installation
```bash
nmap --version
```

## Step 5: Install System Dependencies for Python Packages

### 5.1 Install Required System Libraries
```bash
sudo apt install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    libsqlite3-dev \
    libcairo2-dev \
    libpango1.0-dev \
    libgdk-pixbuf2.0-dev \
    libffi-dev \
    shared-mime-info
```

### 5.2 Install Additional Dependencies for GUI
```bash
sudo apt install -y \
    python3-tk \
    libtk8.6-dev \
    tcl-dev \
    tk-dev
```

## Step 6: Clone CapScan Repository

### 6.1 Navigate to Home Directory
```bash
cd ~
```

### 6.2 Clone the Repository
```bash
git clone <repository-url>
cd capscan
```

*Replace `<repository-url>` with the actual repository URL*

## Step 7: Create Virtual Environment

### 7.1 Create Virtual Environment
```bash
python3 -m venv capscan_env
```

### 7.2 Activate Virtual Environment
```bash
source capscan_env/bin/activate
```

### 7.3 Upgrade pip
```bash
pip install --upgrade pip
```

## Step 8: Install Python Dependencies

### 8.1 Install Core Dependencies
```bash
pip install python-nmap>=0.7.1
pip install ttkbootstrap>=1.10.1
pip install sqlcipher3>=0.5.0
```

### 8.2 Install AI Integration Dependencies
```bash
pip install requests>=2.28.0
pip install openai>=1.0.0
pip install pydantic>=2.0.0
pip install jinja2>=3.0.0
pip install plotly>=5.0.0
```

### 8.3 Install Report Generation Dependencies
```bash
pip install reportlab>=4.0.0
pip install weasyprint>=60.0
```

### 8.4 Install Additional Dependencies
```bash
pip install uuid json datetime typing
```

### Alternative: Install from requirements.txt
If you prefer to install all dependencies at once:
```bash
pip install -r requirements.txt
```

## Step 9: Verify Installation

### 9.1 Test Python Dependencies
```bash
python3 -c "import nmap; print('python-nmap:', nmap.__version__)"
python3 -c "import ttkbootstrap; print('ttkbootstrap installed successfully')"
python3 -c "import sqlcipher3; print('sqlcipher3 installed successfully')"
```

### 9.2 Test CapScan Installation
```bash
python3 main.py --help
```

## Step 10: Configure Database (First Run)

### 10.1 Initialize Database
```bash
python3 main.py --db-info
```
This will prompt you to create a database password on first run.

## Step 11: Test GUI (Optional)

### 11.1 Launch GUI
```bash
python3 gui.py
```

**Note**: GUI functionality in WSL requires X11 forwarding or Windows Terminal with GUI support.

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: Permission Denied for Network Scanning
**Solution**: Run with sudo for network scanning:
```bash
sudo python3 main.py <target_ip>
```

#### Issue 2: GUI Not Displaying
**Solutions**:
1. **Use Windows Terminal**: Install Windows Terminal from Microsoft Store
2. **X11 Forwarding**: Install an X11 server like VcXsrv or Xming
3. **Use CLI Mode**: CapScan works perfectly in command-line mode

#### Issue 3: sqlcipher3 Installation Fails
**Solution**: Install additional dependencies:
```bash
sudo apt install -y libsqlite3-dev libssl-dev
pip install --upgrade pip
pip install sqlcipher3
```

#### Issue 4: ttkbootstrap GUI Issues
**Solution**: Ensure tkinter is properly installed:
```bash
sudo apt install -y python3-tk
python3 -c "import tkinter; print('tkinter working')"
```

#### Issue 5: nmap Not Found
**Solution**: Verify nmap installation and PATH:
```bash
which nmap
sudo apt install nmap -y
```

### Performance Optimization

#### Enable WSL 2 Performance Features
1. **Memory Limit**: Create `.wslconfig` in Windows user directory:
```ini
[wsl2]
memory=4GB
processors=2
```

2. **File System Performance**: Store CapScan in WSL file system, not Windows mounted drives.

## Usage Examples

### Basic Scan
```bash
python3 main.py 192.168.1.1
```

### Advanced Scan with Custom Ports
```bash
python3 main.py 192.168.1.1 --ports "22,80,443,8080" --max-reports 5
```

### Database Operations
```bash
python3 main.py --db-info
```

### Interactive Mode
```bash
python3 main.py --interactive
```

## Security Considerations

1. **Database Encryption**: CapScan uses SQLCipher3 for encrypted database storage
2. **Password Protection**: Database passwords are never hardcoded
3. **Network Scanning**: Requires appropriate permissions for network access
4. **WSL Security**: Ensure WSL is updated and properly configured

## Maintenance

### Updating CapScan
```bash
cd ~/capscan
git pull origin main
source capscan_env/bin/activate
pip install -r requirements.txt --upgrade
```

### Updating System Dependencies
```bash
sudo apt update && sudo apt upgrade -y
```

## Support

For additional help:
1. Check the main README.md file
2. Review error messages for specific guidance
3. Ensure all dependencies are properly installed
4. Verify WSL and Ubuntu are up to date

## Quick Start Checklist

- [ ] WSL 2 enabled and Ubuntu installed
- [ ] Python 3.9+ installed
- [ ] nmap installed and working
- [ ] System dependencies installed
- [ ] CapScan repository cloned
- [ ] Virtual environment created and activated
- [ ] Python dependencies installed
- [ ] Database initialized
- [ ] Test scan completed successfully

---

**CapScan on WSL** - Professional vulnerability scanning on Windows with Linux power.
