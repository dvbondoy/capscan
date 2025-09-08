# CapScan GUI Database Integration Guide

## Overview

The CapScan GUI now includes full database integration, allowing you to save, view, and manage vulnerability scan results using an encrypted SQLCipher3 database. This guide explains how to use all the database features in the GUI.

## Getting Started

### 1. Launch the GUI

```bash
python main.py
# or
python main.py --gui
```

### 2. Database Setup

The first time you use the database, you'll need to set a password:

1. **Enter Database Password**: In the "Database Options" section, enter a secure password in the "DB Password" field
2. **Connect to Database**: Click the "Connect to DB" button to test the connection
3. **Enable Database Saving**: Make sure "Save to Database" checkbox is checked (default: enabled)

## GUI Database Features

### Organized Scan Configuration

The scan configuration is now organized into logical sections for better user experience:

#### 1. Target Configuration
- **Target Host/IP**: Input field for the target to scan
- **Default**: 192.168.1.1

#### 2. Port Configuration
- **Port Range**: Manual port range input
- **Port Presets**: Dropdown menu for common configurations
  - **Custom**: Use manually entered port range
  - **Quick Scan**: 22,80,443 (SSH, HTTP, HTTPS)
  - **Common Ports**: 22,23,25,53,80,110,143,443,993,995,3389,5432,5900,8080
  - **All Ports**: 1-65535 (full port range)

#### 3. Scan Options
- **Max Reports per Port**: Number of vulnerability reports per port (1-100)
- **Enable Keyword-based Scoring**: Checkbox for enhanced vulnerability scoring

#### 4. Database Options
- **Save to Database**: Checkbox to enable/disable automatic database saving
- **Database Password**: Password field for database access (hidden input)
- **Database Info**: Button to show database statistics

#### 5. Actions
- **Start/Stop Scan**: Toggle button that changes based on scan state
  - **When Ready**: Shows "Start Scan" (green button)
  - **When Scanning**: Shows "Stop Scan" (red button)
  - **When Complete**: Returns to "Start Scan" (green button)
- **Save Results to Files**: Button to save scan results as files

### Database Tab

A dedicated tab in the results section with three main areas:

#### 1. Database Controls
- **Status**: Shows current database connection status
- **Connect/Disconnect**: Toggle button to connect or disconnect from database
- **Refresh**: Update database information display (enabled only when connected)

#### 2. Database Information
- **Summary Statistics**: Total scans, vulnerabilities, severity breakdown
- **Connection Status**: Database file location and encryption details
- **Last Updated**: Timestamp of last database update

#### 3. Recent Scans
- **Scan List**: Table showing recent scans with:
  - Target host/IP
  - Scan time
  - Number of vulnerabilities found
  - Scan status

## Step-by-Step Usage

### First Time Setup

1. **Launch CapScan GUI**
   ```bash
   python main.py
   ```

2. **Set Database Password**
   - Enter a secure password in the "DB Password" field
   - Click "Connect to DB" to test the connection
   - You should see "Status: Connected" and the button will change to "Disconnect from DB"

3. **Configure Scan Settings**
   - Enter target host/IP
   - Set port range (manually or use Port Presets dropdown)
   - Ensure "Save to Database" is checked

4. **Run Scan**
   - Click "Start Scan" (button will change to "Stop Scan" during scanning)
   - The scan will automatically save to database when complete

### Viewing Database Information

1. **Switch to Database Tab**
   - Click on the "Database" tab in the results section

2. **View Statistics**
   - Database summary shows total scans and vulnerabilities
   - Severity breakdown shows high/medium/low/unknown counts

3. **Browse Recent Scans**
   - Recent scans table shows all previous scans
   - Click on any scan to view details (if implemented)

### Managing Multiple Scans

1. **Run Additional Scans**
   - Each new scan will be automatically saved to database
   - Database tab will update with new information

2. **View Scan History**
   - Use the "Recent Scans" table to see all previous scans
   - Click "Refresh" to update the list

3. **Database Statistics**
   - View cumulative statistics across all scans
   - Track vulnerability trends over time

### Using Port Presets

1. **Select Preset**: Use the "Port Presets" dropdown to choose a configuration
2. **Quick Scan**: Select for basic web services (SSH, HTTP, HTTPS)
3. **Common Ports**: Select for standard services (SSH, SMTP, DNS, HTTP, etc.)
4. **All Ports**: Select for comprehensive scanning (1-65535)
5. **Custom**: Select when manually entering port ranges
6. **Auto-Detection**: Dropdown automatically updates when you manually type ports

## Database Security Features

### Encryption
- **SQLCipher3**: All data encrypted with AES-256
- **Password Protection**: Database requires password for access
- **Secure Storage**: No plaintext data stored

### Password Management
- **Session Storage**: Password stored in memory during GUI session
- **No Hardcoding**: Passwords never stored in code
- **Secure Input**: Password field uses hidden input (asterisks)

## Troubleshooting

### Common Issues

1. **"Please enter database password"**
   - Solution: Enter password in the "DB Password" field and click "Connect to DB"

2. **"Error connecting to database"**
   - Check if password is correct
   - Ensure you have write permissions in the directory
   - Try creating a new database with a different password

3. **"No scan results to save"**
   - Run a scan first before trying to save to database
   - Ensure scan completed successfully

4. **Database tab shows "Please connect to database first"**
   - Click "Connect to DB" button
   - Enter correct password

### Database File Location

- **Default Location**: `capscan.db` in the current directory
- **File Permissions**: Ensure write access to the directory
- **Backup**: Always backup the database file for data preservation

## Advanced Features

### Manual Database Operations

1. **Connect to Database**
   - Enter password and click "Connect to DB"
   - Status will show "Connected" and button changes to "Disconnect from DB"

2. **Disconnect from Database**
   - Click "Disconnect from DB" to close the connection
   - Status will show "Disconnected" and button changes back to "Connect to DB"

3. **Refresh Database Info**
   - Click "Refresh" to update statistics and recent scans (only available when connected)
   - Useful after running scans from command line

4. **View Database Statistics**
   - Click "DB Info" for detailed database information
   - Shows encryption details and file location

### Integration with Command Line

The GUI database integrates seamlessly with command-line scans:

```bash
# Command line scan with database
python main.py --scan 192.168.1.1 --db-password "your_password"

# View database info from command line
python main.py --db-info --db-password "your_password"
```

## Best Practices

### Security
1. **Use Strong Passwords**: Choose complex, unique passwords
2. **Regular Backups**: Backup the database file regularly
3. **Secure Storage**: Store database file in a secure location
4. **Password Management**: Use a password manager for database passwords

### Performance
1. **Regular Cleanup**: Periodically clean old scan results if needed
2. **Database Maintenance**: Monitor database file size
3. **Connection Management**: Connect to database only when needed

### Workflow
1. **Consistent Passwords**: Use the same password across sessions
2. **Regular Updates**: Refresh database info after scans
3. **Error Handling**: Check status messages for any issues

## Example Workflow

1. **Start CapScan GUI**
   ```bash
   python main.py
   ```

2. **Setup Database**
   - Enter password: `my_secure_password_123`
   - Click "Connect to DB"
   - Verify "Status: Connected"

3. **Configure and Run Scan**
   - Target: `192.168.1.100`
   - Ports: `22,80,443,8080`
   - Ensure "Save to Database" is checked
   - Click "Start Scan"

4. **View Results**
   - Check "Summary" tab for scan overview
   - Check "Vulnerabilities" tab for detailed findings
   - Check "Database" tab for database statistics

5. **Run Additional Scans**
   - Change target to `192.168.1.101`
   - Run another scan
   - Database will automatically save new results

6. **Review Database**
   - Switch to "Database" tab
   - View cumulative statistics
   - Browse recent scans list

## Tips and Tricks

- **Quick Connection**: Enter password once and it's remembered for the session
- **Status Monitoring**: Watch the status label for connection status
- **Error Messages**: Read error dialogs carefully for troubleshooting
- **Refresh Often**: Click "Refresh" to see latest database information
- **Multiple Targets**: Run scans on different targets to build a comprehensive database

The database integration makes CapScan a powerful tool for tracking and managing vulnerability assessments over time, with secure encrypted storage and easy-to-use GUI controls.
