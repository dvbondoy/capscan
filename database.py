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
        
        # AI Analysis Results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                analysis_type TEXT NOT NULL, -- 'compliance', 'mitigation', 'risk_assessment'
                standard TEXT, -- 'PCI_DSS', 'NIST', 'OWASP', 'ISO27001'
                compliance_score REAL,
                risk_level TEXT, -- 'critical', 'high', 'medium', 'low'
                analysis_data TEXT, -- JSON with detailed analysis
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scan_results(scan_id) ON DELETE CASCADE
            )
        """)
        
        # Mitigation Recommendations table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mitigation_recommendations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                vulnerability_id TEXT,
                recommendation_type TEXT, -- 'immediate', 'short_term', 'long_term'
                priority TEXT, -- 'critical', 'high', 'medium', 'low'
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                steps TEXT, -- JSON array of actionable steps
                resources TEXT, -- JSON array of helpful resources
                estimated_effort TEXT, -- 'low', 'medium', 'high'
                status TEXT DEFAULT 'pending', -- 'pending', 'in_progress', 'completed'
                assigned_to TEXT,
                due_date TEXT,
                completed_at TEXT,
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
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_scan ON ai_analysis(scan_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_type ON ai_analysis(analysis_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_mitigation_scan ON mitigation_recommendations(scan_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_mitigation_status ON mitigation_recommendations(status)")
        
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
    
    def save_ai_analysis(self, scan_id: str, analysis_type: str, 
                        standard: str = None, compliance_score: float = None,
                        risk_level: str = None, analysis_data: Dict[str, Any] = None) -> int:
        """
        Save AI analysis results to the database.
        
        Args:
            scan_id: Scan identifier
            analysis_type: Type of analysis ('compliance', 'mitigation', 'risk_assessment')
            standard: Compliance standard (e.g., 'OWASP', 'PCI_DSS')
            compliance_score: Compliance score (0-100)
            risk_level: Risk level ('critical', 'high', 'medium', 'low')
            analysis_data: Detailed analysis data as JSON
            
        Returns:
            int: Analysis ID
        """
        if not self.conn:
            raise Exception("Database not initialized")
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO ai_analysis (scan_id, analysis_type, standard, 
                                       compliance_score, risk_level, analysis_data)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                analysis_type,
                standard,
                compliance_score,
                risk_level,
                json.dumps(analysis_data) if analysis_data else None
            ))
            
            analysis_id = cursor.lastrowid
            self.conn.commit()
            print(f"✅ AI analysis saved with ID: {analysis_id}")
            return analysis_id
            
        except Exception as e:
            self.conn.rollback()
            print(f"❌ Error saving AI analysis: {e}")
            raise
    
    def save_mitigation_recommendations(self, scan_id: str, 
                                      recommendations: List[Dict[str, Any]]) -> List[int]:
        """
        Save mitigation recommendations to the database.
        
        Args:
            scan_id: Scan identifier
            recommendations: List of mitigation recommendations
            
        Returns:
            List[int]: List of recommendation IDs
        """
        if not self.conn:
            raise Exception("Database not initialized")
        
        try:
            cursor = self.conn.cursor()
            recommendation_ids = []
            
            for rec in recommendations:
                cursor.execute("""
                    INSERT INTO mitigation_recommendations 
                    (scan_id, vulnerability_id, recommendation_type, priority, 
                     title, description, steps, resources, estimated_effort, 
                     status, due_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    rec.get('vulnerability_id', ''),
                    rec.get('recommendation_type', ''),
                    rec.get('priority', 'medium'),
                    rec.get('title', ''),
                    rec.get('description', ''),
                    json.dumps(rec.get('steps', [])),
                    json.dumps(rec.get('resources', {})),
                    rec.get('estimated_effort', 'medium'),
                    rec.get('status', 'pending'),
                    rec.get('due_date', '')
                ))
                
                recommendation_ids.append(cursor.lastrowid)
            
            self.conn.commit()
            print(f"✅ {len(recommendation_ids)} mitigation recommendations saved")
            return recommendation_ids
            
        except Exception as e:
            self.conn.rollback()
            print(f"❌ Error saving mitigation recommendations: {e}")
            raise
    
    def get_ai_analysis(self, scan_id: str, analysis_type: str = None) -> List[Dict[str, Any]]:
        """
        Retrieve AI analysis results for a scan.
        
        Args:
            scan_id: Scan identifier
            analysis_type: Optional filter by analysis type
            
        Returns:
            List[Dict]: AI analysis results
        """
        if not self.conn:
            raise Exception("Database not initialized")
        
        try:
            cursor = self.conn.cursor()
            
            if analysis_type:
                cursor.execute("""
                    SELECT * FROM ai_analysis 
                    WHERE scan_id = ? AND analysis_type = ?
                    ORDER BY created_at DESC
                """, (scan_id, analysis_type))
            else:
                cursor.execute("""
                    SELECT * FROM ai_analysis 
                    WHERE scan_id = ?
                    ORDER BY created_at DESC
                """, (scan_id,))
            
            rows = cursor.fetchall()
            results = []
            
            for row in rows:
                analysis = {
                    'id': row[0],
                    'scan_id': row[1],
                    'analysis_type': row[2],
                    'standard': row[3],
                    'compliance_score': row[4],
                    'risk_level': row[5],
                    'analysis_data': json.loads(row[6]) if row[6] else None,
                    'created_at': row[7]
                }
                results.append(analysis)
            
            return results
            
        except Exception as e:
            print(f"❌ Error retrieving AI analysis: {e}")
            return []
    
    def get_mitigation_recommendations(self, scan_id: str, 
                                     status: str = None) -> List[Dict[str, Any]]:
        """
        Retrieve mitigation recommendations for a scan.
        
        Args:
            scan_id: Scan identifier
            status: Optional filter by status
            
        Returns:
            List[Dict]: Mitigation recommendations
        """
        if not self.conn:
            raise Exception("Database not initialized")
        
        try:
            cursor = self.conn.cursor()
            
            if status:
                cursor.execute("""
                    SELECT * FROM mitigation_recommendations 
                    WHERE scan_id = ? AND status = ?
                    ORDER BY priority DESC, created_at ASC
                """, (scan_id, status))
            else:
                cursor.execute("""
                    SELECT * FROM mitigation_recommendations 
                    WHERE scan_id = ?
                    ORDER BY priority DESC, created_at ASC
                """, (scan_id,))
            
            rows = cursor.fetchall()
            results = []
            
            for row in rows:
                recommendation = {
                    'id': row[0],
                    'scan_id': row[1],
                    'vulnerability_id': row[2],
                    'recommendation_type': row[3],
                    'priority': row[4],
                    'title': row[5],
                    'description': row[6],
                    'steps': json.loads(row[7]) if row[7] else [],
                    'resources': json.loads(row[8]) if row[8] else {},
                    'estimated_effort': row[9],
                    'status': row[10],
                    'assigned_to': row[11],
                    'due_date': row[12],
                    'completed_at': row[13],
                    'created_at': row[14]
                }
                results.append(recommendation)
            
            return results
            
        except Exception as e:
            print(f"❌ Error retrieving mitigation recommendations: {e}")
            return []
    
    def update_mitigation_status(self, recommendation_id: int, 
                               status: str, assigned_to: str = None) -> bool:
        """
        Update mitigation recommendation status.
        
        Args:
            recommendation_id: Recommendation ID
            status: New status
            assigned_to: Optional assignee
            
        Returns:
            bool: Success status
        """
        if not self.conn:
            raise Exception("Database not initialized")
        
        try:
            cursor = self.conn.cursor()
            
            if status == 'completed':
                cursor.execute("""
                    UPDATE mitigation_recommendations 
                    SET status = ?, assigned_to = ?, completed_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (status, assigned_to, recommendation_id))
            else:
                cursor.execute("""
                    UPDATE mitigation_recommendations 
                    SET status = ?, assigned_to = ?
                    WHERE id = ?
                """, (status, assigned_to, recommendation_id))
            
            self.conn.commit()
            return cursor.rowcount > 0
            
        except Exception as e:
            print(f"❌ Error updating mitigation status: {e}")
            return False
    
    def get_ai_summary(self, scan_id: str = None) -> Dict[str, Any]:
        """
        Get AI analysis summary statistics.
        
        Args:
            scan_id: Optional specific scan ID
            
        Returns:
            Dict: AI summary statistics
        """
        if not self.conn:
            raise Exception("Database not initialized")
        
        try:
            cursor = self.conn.cursor()
            
            if scan_id:
                # Summary for specific scan
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_analyses,
                        COUNT(CASE WHEN analysis_type = 'compliance' THEN 1 END) as compliance_analyses,
                        COUNT(CASE WHEN analysis_type = 'mitigation' THEN 1 END) as mitigation_analyses,
                        AVG(compliance_score) as avg_compliance_score
                    FROM ai_analysis WHERE scan_id = ?
                """, (scan_id,))
                
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_recommendations,
                        COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_recommendations,
                        COUNT(CASE WHEN priority = 'critical' THEN 1 END) as critical_recommendations
                    FROM mitigation_recommendations WHERE scan_id = ?
                """, (scan_id,))
            else:
                # Summary for all scans
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_analyses,
                        COUNT(CASE WHEN analysis_type = 'compliance' THEN 1 END) as compliance_analyses,
                        COUNT(CASE WHEN analysis_type = 'mitigation' THEN 1 END) as mitigation_analyses,
                        AVG(compliance_score) as avg_compliance_score
                    FROM ai_analysis
                """)
                
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_recommendations,
                        COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_recommendations,
                        COUNT(CASE WHEN priority = 'critical' THEN 1 END) as critical_recommendations
                    FROM mitigation_recommendations
                """)
            
            ai_stats = cursor.fetchone()
            rec_stats = cursor.fetchone()
            
            return {
                'total_analyses': ai_stats[0] or 0,
                'compliance_analyses': ai_stats[1] or 0,
                'mitigation_analyses': ai_stats[2] or 0,
                'avg_compliance_score': round(ai_stats[3] or 0, 2),
                'total_recommendations': rec_stats[0] or 0,
                'completed_recommendations': rec_stats[1] or 0,
                'critical_recommendations': rec_stats[2] or 0
            }
            
        except Exception as e:
            print(f"❌ Error getting AI summary: {e}")
            return {}
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
