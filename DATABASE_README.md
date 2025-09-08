# CapScan Database Documentation

## Overview

CapScan now includes a comprehensive SQLCipher3 database system for storing and managing vulnerability scan results. The database provides encrypted storage for all scan data, including target host information, port details, and vulnerability findings.

## Features

- **Encrypted Storage**: Uses SQLCipher3 for secure, encrypted database storage
- **Comprehensive Schema**: Stores scan results, host information, port details, and vulnerabilities
- **Flexible Queries**: Retrieve scans by ID, target, or get all scans
- **Statistics**: Built-in summary statistics and reporting
- **Performance**: Indexed tables for fast queries
- **Data Integrity**: Foreign key constraints and proper data relationships

## Database Schema

### Tables

1. **scan_results**: Main scan information
   - `scan_id` (TEXT PRIMARY KEY): Unique scan identifier
   - `target` (TEXT): Target host or IP address
   - `scan_time` (TEXT): ISO timestamp of scan
   - `scan_args` (TEXT): Nmap arguments used
   - `total_vulnerabilities` (INTEGER): Count of vulnerabilities found
   - `hosts_scanned` (INTEGER): Number of hosts scanned
   - `scan_status` (TEXT): Scan completion status
   - `created_at` (TEXT): Record creation timestamp
   - `updated_at` (TEXT): Record update timestamp

2. **host_info**: Host-specific information
   - `id` (INTEGER PRIMARY KEY): Auto-increment ID
   - `scan_id` (TEXT): Foreign key to scan_results
   - `host_ip` (TEXT): Host IP address
   - `hostname` (TEXT): Resolved hostname
   - `state` (TEXT): Host state (up/down)
   - `protocols` (TEXT): JSON array of protocols
   - `created_at` (TEXT): Record creation timestamp

3. **port_info**: Port and service information
   - `id` (INTEGER PRIMARY KEY): Auto-increment ID
   - `scan_id` (TEXT): Foreign key to scan_results
   - `host_ip` (TEXT): Host IP address
   - `port` (TEXT): Port identifier (e.g., "tcp/80")
   - `state` (TEXT): Port state (open/closed/filtered)
   - `name` (TEXT): Service name
   - `product` (TEXT): Service product
   - `version` (TEXT): Service version
   - `extrainfo` (TEXT): Additional service information
   - `script_results` (TEXT): JSON object of NSE script results
   - `created_at` (TEXT): Record creation timestamp

4. **vulnerabilities**: Vulnerability findings
   - `id` (INTEGER PRIMARY KEY): Auto-increment ID
   - `scan_id` (TEXT): Foreign key to scan_results
   - `host_ip` (TEXT): Host IP address
   - `port` (TEXT): Port identifier
   - `cve_id` (TEXT): CVE identifier
   - `score` (REAL): Vulnerability score
   - `description` (TEXT): Vulnerability description
   - `raw_output` (TEXT): Raw NSE script output
   - `score_source` (TEXT): Source of the score
   - `keyword_score` (REAL): Keyword-based score
   - `year_score` (REAL): CVE year-based score
   - `severity` (TEXT): Calculated severity (high/medium/low/unknown)
   - `created_at` (TEXT): Record creation timestamp

## Usage

### Basic Database Operations

```python
from database import Database

# Initialize database (will prompt for password)
with Database() as db:
    # Save scan results
    scan_id = db.save_scan_results(scan_results)
    
    # Retrieve specific scan
    scan = db.get_scan_results(scan_id)
    
    # Get all scans
    all_scans = db.get_all_scan_results()
    
    # Get scans by target
    target_scans = db.get_scan_results_by_target("192.168.1.1")
    
    # Get database summary
    summary = db.get_scan_summary()

# Or provide password programmatically
with Database(password="your_secure_password") as db:
    # Database operations...
```

### Command Line Usage

```bash
# Run scan with database saving (will prompt for password)
python main.py --scan 192.168.1.1

# Run scan with provided password
python main.py --scan 192.168.1.1 --db-password "your_password"

# Run scan without database saving
python main.py --scan 192.168.1.1 --no-db

# Show database statistics (will prompt for password)
python main.py --db-info

# Show database statistics with password
python main.py --db-info --db-password "your_password"

# Interactive mode with database options
python main.py --cli
```

### Database Configuration

The database can be configured with custom settings:

```python
# Custom database path and password
db = Database(db_path="custom_scan.db", password="my_secure_password")

# Use default path but custom password
db = Database(password="my_secure_password")

# Use default settings (will prompt for password)
db = Database()
```

## Security Features

- **Encryption**: All data is encrypted using SQLCipher3
- **Password Protection**: Database requires password for access
- **Secure Defaults**: Uses industry-standard encryption settings
- **Data Isolation**: Each scan is isolated with proper foreign key relationships

## Performance Optimizations

- **Indexes**: Strategic indexes on frequently queried columns
- **Batch Operations**: Efficient bulk insert operations
- **Connection Management**: Proper connection handling with context managers
- **Query Optimization**: Optimized queries for common operations

## Error Handling

The database class includes comprehensive error handling:

- Connection failures are properly reported
- Transaction rollbacks on errors
- Graceful degradation when database is unavailable
- Detailed error messages for troubleshooting

## Testing

Run the database test script to verify functionality:

```bash
python test_database.py
```

This will:
- Create a test database
- Insert sample scan data
- Test all retrieval functions
- Display database statistics
- Clean up test data

## Integration

The database is fully integrated into the CapScan workflow:

1. **Automatic Saving**: Scan results are automatically saved to database
2. **GUI Integration**: Database data can be displayed in the GUI
3. **CLI Integration**: Command-line tools can query database
4. **File Backup**: Database works alongside file-based saving

## Troubleshooting

### Common Issues

1. **SQLCipher3 Not Installed**
   ```bash
   pip install sqlcipher3
   ```

2. **Database Permission Errors**
   - Ensure write permissions in the database directory
   - Check if database file is locked by another process

3. **Encryption Errors**
   - Verify the password is correct
   - Check if database file is corrupted

4. **Import Errors**
   - Ensure all dependencies are installed: `pip install -r requirements.txt`

### Database File Location

- Default: `capscan.db` in the current directory
- Custom: Specify path in Database constructor
- Backup: Always backup the database file for data preservation

## Future Enhancements

- Database migration tools
- Advanced querying capabilities
- Data export/import functionality
- Database maintenance utilities
- Performance monitoring
- Automated cleanup of old scans
