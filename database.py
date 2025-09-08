import sqlite3
import sqlcipher3
import json
import uuid
import os
import getpass
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any


class Database:
    """
    SQLCipher3 database class for storing scan results and target host information.
    Provides encrypted storage for vulnerability scan data.
    """
    
    def __init__(self, db_path: str = "capscan.db", password: str = None):
        """
        Initialize the database connection with SQLCipher3 encryption.
        
        Args:
            db_path (str): Path to the database file
            password (str): Password for database encryption. If None, will prompt user.
        """
        self.db_path = db_path
        self.password = password or self._get_password()
        self.conn = None
        self._init_database()
    
    def _get_password(self) -> str:
        """Prompt user for database password securely."""
        print("🔐 Database Password Required")
        print("=" * 40)
        
        while True:
            try:
                password = getpass.getpass("Enter database password: ")
                if not password:
                    print("❌ Password cannot be empty. Please try again.")
                    continue
                
                # Verify password by attempting to connect
                if self._verify_password(password):
                    print("✅ Password verified successfully!")
                    return password
                else:
                    print("❌ Invalid password. Please try again.")
                    
            except KeyboardInterrupt:
                print("\n\n⚠️  Operation cancelled by user")
                sys.exit(1)
            except Exception as e:
                print(f"❌ Error: {e}")
                continue
    
    def _verify_password(self, password: str) -> bool:
        """Verify if the password is correct by attempting to connect."""
        try:
            # Try to connect with the provided password
            test_conn = sqlcipher3.connect(self.db_path)
            test_conn.execute(f"PRAGMA key='{password}'")
            test_conn.execute("PRAGMA cipher_page_size = 4096")
            test_conn.execute("PRAGMA kdf_iter = 256000")
            test_conn.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA1")
            test_conn.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1")
            
            # Try to execute a simple query to verify the password works
            test_conn.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1")
            test_conn.close()
            return True
            
        except Exception:
            # If database doesn't exist yet, we'll create it with this password
            if not os.path.exists(self.db_path):
                return True
            return False
    
    def _init_database(self):
        """Initialize database connection and create tables if they don't exist."""
        try:
            # Connect to SQLCipher3 database
            self.conn = sqlcipher3.connect(self.db_path)
            self.conn.execute(f"PRAGMA key='{self.password}'")
            self.conn.execute("PRAGMA cipher_page_size = 4096")
            self.conn.execute("PRAGMA kdf_iter = 256000")
            self.conn.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA1")
            self.conn.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1")
            
            # Create tables
            self._create_tables()
            print(f"✅ Database initialized: {self.db_path}")
            
        except Exception as e:
            print(f"❌ Database initialization failed: {e}")
            raise
    
    def _create_tables(self):
        """Create database tables for scan results and host information."""
        cursor = self.conn.cursor()
        
        # Scan results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                scan_time TEXT NOT NULL,
                scan_args TEXT,
                total_vulnerabilities INTEGER DEFAULT 0,
                hosts_scanned INTEGER DEFAULT 0,
                scan_status TEXT DEFAULT 'completed',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Host information table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS host_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                host_ip TEXT NOT NULL,
                hostname TEXT,
                state TEXT,
                protocols TEXT,  -- JSON array of protocols
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scan_results(scan_id) ON DELETE CASCADE
            )
        """)
        
        # Port information table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS port_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                host_ip TEXT NOT NULL,
                port TEXT NOT NULL,  -- Format: protocol/port (e.g., tcp/80)
                state TEXT,
                name TEXT,
                product TEXT,
                version TEXT,
                extrainfo TEXT,
                script_results TEXT,  -- JSON object of script results
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scan_results(scan_id) ON DELETE CASCADE
            )
        """)
        
        # Vulnerabilities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                host_ip TEXT,
                port TEXT,
                cve_id TEXT,
                score REAL,
                description TEXT,
                raw_output TEXT,
                score_source TEXT,
                keyword_score REAL,
                year_score REAL,
                severity TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scan_results(scan_id) ON DELETE CASCADE
            )
        """)
        
        # Create indexes for better performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_target ON scan_results(target)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_time ON scan_results(scan_time)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_host_scan ON host_info(scan_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_port_scan ON port_info(scan_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_scan ON vulnerabilities(scan_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity)")
        
        self.conn.commit()
    
    def save_scan_results(self, scan_results: Dict[str, Any]) -> str:
        """
        Save scan results to the database.
        
        Args:
            scan_results (Dict): Scan results from Scanner.scan_host()
            
        Returns:
            str: Generated scan_id
        """
        if not self.conn:
            raise Exception("Database not initialized")
        
        try:
            # Generate unique scan ID
            scan_id = str(uuid.uuid4())
            
            cursor = self.conn.cursor()
            
            # Insert scan results
            cursor.execute("""
                INSERT INTO scan_results (scan_id, target, scan_time, scan_args, 
                                       total_vulnerabilities, hosts_scanned, scan_status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                scan_results.get('target', ''),
                scan_results.get('scan_time', ''),
                scan_results.get('scan_args', ''),
                len(scan_results.get('vulnerabilities', [])),
                len(scan_results.get('hosts', {})),
                'completed'
            ))
            
            # Insert host information
            for host_ip, host_info in scan_results.get('hosts', {}).items():
                cursor.execute("""
                    INSERT INTO host_info (scan_id, host_ip, hostname, state, protocols)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    host_ip,
                    host_info.get('hostname', ''),
                    host_info.get('state', ''),
                    json.dumps(host_info.get('protocols', []))
                ))
                
                # Insert port information
                for port, port_info in host_info.get('ports', {}).items():
                    cursor.execute("""
                        INSERT INTO port_info (scan_id, host_ip, port, state, name, 
                                             product, version, extrainfo, script_results)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id,
                        host_ip,
                        port,
                        port_info.get('state', ''),
                        port_info.get('name', ''),
                        port_info.get('product', ''),
                        port_info.get('version', ''),
                        port_info.get('extrainfo', ''),
                        json.dumps(port_info.get('script_results', {}))
                    ))
            
            # Insert vulnerabilities
            for vuln in scan_results.get('vulnerabilities', []):
                # Determine severity based on score
                score = vuln.get('score')
                if score is None:
                    severity = 'unknown'
                elif score >= 7.0:
                    severity = 'high'
                elif score >= 4.0:
                    severity = 'medium'
                else:
                    severity = 'low'
                
                cursor.execute("""
                    INSERT INTO vulnerabilities (scan_id, host_ip, port, cve_id, score, 
                                              description, raw_output, score_source, 
                                              keyword_score, year_score, severity)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    vuln.get('host_ip', ''),
                    vuln.get('port', ''),
                    vuln.get('cve_id', ''),
                    score,
                    vuln.get('description', ''),
                    vuln.get('raw_output', ''),
                    vuln.get('score_source', ''),
                    vuln.get('keyword_score'),
                    vuln.get('year_score'),
                    severity
                ))
            
            self.conn.commit()
            print(f"✅ Scan results saved with ID: {scan_id}")
            return scan_id
            
        except Exception as e:
            self.conn.rollback()
            print(f"❌ Error saving scan results: {e}")
            raise
    
    def get_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve scan results by scan ID.
        
        Args:
            scan_id (str): Unique scan identifier
            
        Returns:
            Dict: Complete scan results or None if not found
        """
        if not self.conn:
            raise Exception("Database not initialized")
        
        try:
            cursor = self.conn.cursor()
            
            # Get scan info
            cursor.execute("SELECT * FROM scan_results WHERE scan_id = ?", (scan_id,))
            scan_row = cursor.fetchone()
            if not scan_row:
                return None
            
            # Get host information
            cursor.execute("SELECT * FROM host_info WHERE scan_id = ?", (scan_id,))
            host_rows = cursor.fetchall()
            
            # Get port information
            cursor.execute("SELECT * FROM port_info WHERE scan_id = ?", (scan_id,))
            port_rows = cursor.fetchall()
            
            # Get vulnerabilities
            cursor.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
            vuln_rows = cursor.fetchall()
            
            # Reconstruct scan results
            scan_results = {
                'scan_id': scan_row[0],
                'target': scan_row[1],
                'scan_time': scan_row[2],
                'scan_args': scan_row[3],
                'total_vulnerabilities': scan_row[4],
                'hosts_scanned': scan_row[5],
                'scan_status': scan_row[6],
                'hosts': {},
                'vulnerabilities': []
            }
            
            # Reconstruct hosts
            for host_row in host_rows:
                host_ip = host_row[2]
                scan_results['hosts'][host_ip] = {
                    'hostname': host_row[3],
                    'state': host_row[4],
                    'protocols': json.loads(host_row[5]) if host_row[5] else [],
                    'ports': {},
                    'vulnerabilities': []
                }
            
            # Reconstruct ports
            for port_row in port_rows:
                host_ip = port_row[2]
                port = port_row[3]
                if host_ip in scan_results['hosts']:
                    scan_results['hosts'][host_ip]['ports'][port] = {
                        'state': port_row[4],
                        'name': port_row[5],
                        'product': port_row[6],
                        'version': port_row[7],
                        'extrainfo': port_row[8],
                        'script_results': json.loads(port_row[9]) if port_row[9] else {}
                    }
            
            # Reconstruct vulnerabilities
            for vuln_row in vuln_rows:
                vuln = {
                    'host_ip': vuln_row[2],
                    'port': vuln_row[3],
                    'cve_id': vuln_row[4],
                    'score': vuln_row[5],
                    'description': vuln_row[6],
                    'raw_output': vuln_row[7],
                    'score_source': vuln_row[8],
                    'keyword_score': vuln_row[9],
                    'year_score': vuln_row[10],
                    'severity': vuln_row[11]
                }
                scan_results['vulnerabilities'].append(vuln)
                
                # Add to host-specific vulnerabilities
                if vuln['host_ip'] in scan_results['hosts']:
                    scan_results['hosts'][vuln['host_ip']]['vulnerabilities'].append(vuln)
            
            return scan_results
            
        except Exception as e:
            print(f"❌ Error retrieving scan results: {e}")
            return None
    
    def get_all_scan_results(self) -> List[Dict[str, Any]]:
        """
        Retrieve all scan results.
        
        Returns:
            List[Dict]: List of all scan results
        """
        if not self.conn:
            raise Exception("Database not initialized")
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT scan_id FROM scan_results ORDER BY created_at DESC")
            scan_ids = [row[0] for row in cursor.fetchall()]
            
            results = []
            for scan_id in scan_ids:
                scan_result = self.get_scan_results(scan_id)
                if scan_result:
                    results.append(scan_result)
            
            return results
            
        except Exception as e:
            print(f"❌ Error retrieving all scan results: {e}")
            return []
    
    def get_scan_results_by_target(self, target: str) -> List[Dict[str, Any]]:
        """
        Retrieve scan results filtered by target.
        
        Args:
            target (str): Target host or IP address
            
        Returns:
            List[Dict]: List of scan results for the target
        """
        if not self.conn:
            raise Exception("Database not initialized")
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT scan_id FROM scan_results WHERE target = ? ORDER BY created_at DESC", (target,))
            scan_ids = [row[0] for row in cursor.fetchall()]
            
            results = []
            for scan_id in scan_ids:
                scan_result = self.get_scan_results(scan_id)
                if scan_result:
                    results.append(scan_result)
            
            return results
            
        except Exception as e:
            print(f"❌ Error retrieving scan results by target: {e}")
            return []
    
    def get_scan_summary(self, scan_id: str = None) -> Dict[str, Any]:
        """
        Get summary statistics for scans.
        
        Args:
            scan_id (str, optional): Specific scan ID, or None for all scans
            
        Returns:
            Dict: Summary statistics
        """
        if not self.conn:
            raise Exception("Database not initialized")
        
        try:
            cursor = self.conn.cursor()
            
            if scan_id:
                # Summary for specific scan
                cursor.execute("""
                    SELECT COUNT(*) as total_vulns,
                           COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_severity,
                           COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium_severity,
                           COUNT(CASE WHEN severity = 'low' THEN 1 END) as low_severity,
                           COUNT(CASE WHEN severity = 'unknown' THEN 1 END) as unknown_severity
                    FROM vulnerabilities WHERE scan_id = ?
                """, (scan_id,))
            else:
                # Summary for all scans
                cursor.execute("""
                    SELECT COUNT(*) as total_vulns,
                           COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_severity,
                           COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium_severity,
                           COUNT(CASE WHEN severity = 'low' THEN 1 END) as low_severity,
                           COUNT(CASE WHEN severity = 'unknown' THEN 1 END) as unknown_severity
                    FROM vulnerabilities
                """)
            
            vuln_stats = cursor.fetchone()
            
            if scan_id:
                cursor.execute("SELECT COUNT(*) FROM scan_results WHERE scan_id = ?", (scan_id,))
                total_scans = cursor.fetchone()[0]
            else:
                cursor.execute("SELECT COUNT(*) FROM scan_results")
                total_scans = cursor.fetchone()[0]
            
            return {
                'total_scans': total_scans,
                'total_vulnerabilities': vuln_stats[0] or 0,
                'high_severity': vuln_stats[1] or 0,
                'medium_severity': vuln_stats[2] or 0,
                'low_severity': vuln_stats[3] or 0,
                'unknown_severity': vuln_stats[4] or 0
            }
            
        except Exception as e:
            print(f"❌ Error getting scan summary: {e}")
            return {}
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
            print("✅ Database connection closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
