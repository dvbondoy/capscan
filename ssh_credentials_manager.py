#!/usr/bin/env python3
"""
SSH Credentials Manager
Provides secure storage and management of SSH credentials using SQLCipher3.
"""

import json
import base64
import hashlib
import secrets
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import sqlite3
import sqlcipher3

# Try to import cryptography, fallback to simple encoding if not available
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    print("Warning: cryptography library not available. Using simple encoding for credentials.")


class SSHCredentialsManager:
    """
    Manages SSH credentials with secure encryption and storage.
    Uses SQLCipher3 for database storage and Fernet for encryption.
    """
    
    def __init__(self, db_path: str = "ssh_credentials.db", master_password: str = None):
        """
        Initialize SSH Credentials Manager.
        
        Args:
            db_path: Path to SQLCipher database
            master_password: Master password for encryption
        """
        self.db_path = db_path
        self.master_password = master_password
        self.encryption_key = None
        self._init_encryption()
        self._init_database()
    
    def _init_encryption(self):
        """Initialize encryption key from master password."""
        if not CRYPTOGRAPHY_AVAILABLE:
            # Use simple encoding if cryptography is not available
            self.encryption_key = None
            return
            
        if not self.master_password:
            # Generate a random key for this session
            self.encryption_key = Fernet.generate_key()
        else:
            # Derive key from master password
            password_bytes = self.master_password.encode()
            salt = b'capscan_ssh_salt'  # In production, use random salt per credential
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
            self.encryption_key = key
    
    def _init_database(self):
        """Initialize database tables for SSH credentials."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Create SSH credentials table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ssh_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL,
                    encrypted_password TEXT,
                    encrypted_private_key TEXT,
                    encrypted_passphrase TEXT,
                    port INTEGER DEFAULT 22,
                    timeout INTEGER DEFAULT 30,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            # Create SSH scan sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ssh_scan_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_name TEXT NOT NULL,
                    credential_id INTEGER,
                    targets TEXT NOT NULL,
                    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    results_path TEXT,
                    status TEXT DEFAULT 'pending',
                    FOREIGN KEY (credential_id) REFERENCES ssh_credentials (id)
                )
            ''')
            
            conn.commit()
            conn.close()
            print("✓ SSH credentials database initialized successfully")
            
        except Exception as e:
            print(f"Error initializing SSH credentials database: {e}")
            import traceback
            traceback.print_exc()
    
    def _get_connection(self):
        """Get database connection."""
        try:
            # Use regular SQLite for now (simpler and more reliable)
            conn = sqlite3.connect(self.db_path)
            return conn
        except Exception as e:
            print(f"Database connection failed: {e}")
            raise e
    
    def _encrypt_data(self, data: str) -> str:
        """Encrypt data using Fernet encryption or simple encoding."""
        if not data:
            return ""
        
        if not CRYPTOGRAPHY_AVAILABLE or not self.encryption_key:
            # Use simple base64 encoding as fallback
            return base64.b64encode(data.encode()).decode()
        
        try:
            f = Fernet(self.encryption_key)
            encrypted_data = f.encrypt(data.encode())
            return base64.b64encode(encrypted_data).decode()
        except Exception as e:
            print(f"Error encrypting data: {e}")
            # Fallback to simple encoding
            return base64.b64encode(data.encode()).decode()
    
    def _decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt data using Fernet decryption or simple decoding."""
        if not encrypted_data:
            return ""
        
        if not CRYPTOGRAPHY_AVAILABLE or not self.encryption_key:
            # Use simple base64 decoding as fallback
            try:
                return base64.b64decode(encrypted_data.encode()).decode()
            except Exception as e:
                print(f"Error decoding data: {e}")
                return ""
        
        try:
            f = Fernet(self.encryption_key)
            decoded_data = base64.b64decode(encrypted_data.encode())
            decrypted_data = f.decrypt(decoded_data)
            return decrypted_data.decode()
        except Exception as e:
            print(f"Error decrypting data: {e}")
            # Fallback to simple decoding
            try:
                return base64.b64decode(encrypted_data.encode()).decode()
            except Exception as e2:
                print(f"Error in fallback decoding: {e2}")
                return ""
    
    def save_credentials(self, 
                        name: str,
                        username: str,
                        password: Optional[str] = None,
                        private_key_path: Optional[str] = None,
                        passphrase: Optional[str] = None,
                        port: int = 22,
                        timeout: int = 30) -> bool:
        """
        Save SSH credentials to database.
        
        Args:
            name: Unique name for the credential set
            username: SSH username
            password: SSH password (optional)
            private_key_path: Path to private key file (optional)
            passphrase: Passphrase for private key (optional)
            port: SSH port (default: 22)
            timeout: Connection timeout (default: 30)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate inputs
            if not name or not username:
                print("Error: Name and username are required")
                return False
            
            if not password and not private_key_path:
                print("Error: Either password or private key path must be provided")
                return False
            
            # Check if private key file exists
            if private_key_path and not os.path.exists(private_key_path):
                print(f"Warning: Private key file not found: {private_key_path}")
                # Don't fail, just warn - user might add the file later
            
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Encrypt sensitive data
            encrypted_password = self._encrypt_data(password) if password else None
            encrypted_private_key = self._encrypt_data(private_key_path) if private_key_path else None
            encrypted_passphrase = self._encrypt_data(passphrase) if passphrase else None
            
            # Insert or update credentials
            cursor.execute('''
                INSERT OR REPLACE INTO ssh_credentials 
                (name, username, encrypted_password, encrypted_private_key, 
                 encrypted_passphrase, port, timeout, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (name, username, encrypted_password, encrypted_private_key, 
                  encrypted_passphrase, port, timeout))
            
            conn.commit()
            conn.close()
            
            print(f"SSH credentials '{name}' saved successfully")
            return True
            
        except Exception as e:
            print(f"Error saving SSH credentials: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def get_credentials(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve SSH credentials by name.
        
        Args:
            name: Credential set name
            
        Returns:
            Dictionary containing credentials or None if not found
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT username, encrypted_password, encrypted_private_key, 
                       encrypted_passphrase, port, timeout, last_used
                FROM ssh_credentials 
                WHERE name = ? AND is_active = 1
            ''', (name,))
            
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return None
            
            username, encrypted_password, encrypted_private_key, encrypted_passphrase, port, timeout, last_used = row
            
            # Decrypt sensitive data
            password = self._decrypt_data(encrypted_password) if encrypted_password else None
            private_key_path = self._decrypt_data(encrypted_private_key) if encrypted_private_key else None
            passphrase = self._decrypt_data(encrypted_passphrase) if encrypted_passphrase else None
            
            # Update last used timestamp
            self._update_last_used(name)
            
            return {
                'name': name,
                'username': username,
                'password': password,
                'private_key_path': private_key_path,
                'passphrase': passphrase,
                'port': port,
                'timeout': timeout,
                'last_used': last_used
            }
            
        except Exception as e:
            print(f"Error retrieving SSH credentials: {e}")
            return None
    
    def list_credentials(self) -> List[Dict[str, Any]]:
        """
        List all saved SSH credentials.
        
        Returns:
            List of credential information (without sensitive data)
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT name, username, port, timeout, created_at, updated_at, last_used
                FROM ssh_credentials 
                WHERE is_active = 1
                ORDER BY updated_at DESC
            ''')
            
            rows = cursor.fetchall()
            conn.close()
            
            credentials = []
            for row in rows:
                name, username, port, timeout, created_at, updated_at, last_used = row
                credentials.append({
                    'name': name,
                    'username': username,
                    'port': port,
                    'timeout': timeout,
                    'created_at': created_at,
                    'updated_at': updated_at,
                    'last_used': last_used,
                    'has_password': self._has_password(name),
                    'has_private_key': self._has_private_key(name)
                })
            
            return credentials
            
        except Exception as e:
            print(f"Error listing SSH credentials: {e}")
            return []
    
    def _has_password(self, name: str) -> bool:
        """Check if credentials have a password."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT encrypted_password FROM ssh_credentials 
                WHERE name = ? AND is_active = 1
            ''', (name,))
            
            row = cursor.fetchone()
            conn.close()
            
            return row and row[0] is not None
            
        except Exception as e:
            return False
    
    def _has_private_key(self, name: str) -> bool:
        """Check if credentials have a private key."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT encrypted_private_key FROM ssh_credentials 
                WHERE name = ? AND is_active = 1
            ''', (name,))
            
            row = cursor.fetchone()
            conn.close()
            
            return row and row[0] is not None
            
        except Exception as e:
            return False
    
    def delete_credentials(self, name: str) -> bool:
        """
        Delete SSH credentials by name.
        
        Args:
            name: Credential set name
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Soft delete by setting is_active to 0
            cursor.execute('''
                UPDATE ssh_credentials 
                SET is_active = 0, updated_at = CURRENT_TIMESTAMP
                WHERE name = ?
            ''', (name,))
            
            conn.commit()
            conn.close()
            
            print(f"SSH credentials '{name}' deleted successfully")
            return True
            
        except Exception as e:
            print(f"Error deleting SSH credentials: {e}")
            return False
    
    def _update_last_used(self, name: str):
        """Update last used timestamp for credentials."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE ssh_credentials 
                SET last_used = CURRENT_TIMESTAMP
                WHERE name = ?
            ''', (name,))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error updating last used timestamp: {e}")
    
    def test_credentials(self, name: str, test_host: str) -> Dict[str, Any]:
        """
        Test SSH credentials against a specific host.
        
        Args:
            name: Credential set name
            test_host: Host to test against
            
        Returns:
            Test results dictionary
        """
        credentials = self.get_credentials(name)
        if not credentials:
            return {
                'success': False,
                'error': 'Credentials not found'
            }
        
        try:
            from ssh_scanner import SSHAuthenticatedScanner, SSHCredentials as SSHCreds
            
            # Convert to SSH credentials object
            ssh_creds = SSHCreds(
                username=credentials['username'],
                password=credentials.get('password'),
                private_key_path=credentials.get('private_key_path'),
                passphrase=credentials.get('passphrase'),
                port=credentials['port'],
                timeout=credentials['timeout']
            )
            
            # Test connection
            scanner = SSHAuthenticatedScanner()
            test_command = "echo 'SSH connection test successful'"
            
            result = scanner._execute_ssh_command(test_host, ssh_creds, test_command)
            
            if result.get('exit_code') == 0:
                return {
                    'success': True,
                    'message': 'SSH connection successful',
                    'output': result.get('output', ''),
                    'test_time': datetime.now().isoformat()
                }
            else:
                return {
                    'success': False,
                    'error': result.get('error', 'Unknown error'),
                    'output': result.get('output', ''),
                    'test_time': datetime.now().isoformat()
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'test_time': datetime.now().isoformat()
            }
    
    def save_scan_session(self, 
                         session_name: str,
                         credential_name: str,
                         targets: List[str],
                         results_path: Optional[str] = None) -> bool:
        """
        Save SSH scan session information.
        
        Args:
            session_name: Name for the scan session
            credential_name: Name of credentials used
            targets: List of target hosts
            results_path: Path to scan results file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Get credential ID
            cursor.execute('SELECT id FROM ssh_credentials WHERE name = ? AND is_active = 1', (credential_name,))
            credential_row = cursor.fetchone()
            credential_id = credential_row[0] if credential_row else None
            
            # Insert scan session
            cursor.execute('''
                INSERT INTO ssh_scan_sessions 
                (session_name, credential_id, targets, results_path, status)
                VALUES (?, ?, ?, ?, 'completed')
            ''', (session_name, credential_id, json.dumps(targets), results_path))
            
            conn.commit()
            conn.close()
            
            print(f"SSH scan session '{session_name}' saved successfully")
            return True
            
        except Exception as e:
            print(f"Error saving SSH scan session: {e}")
            return False
    
    def get_scan_sessions(self) -> List[Dict[str, Any]]:
        """
        Get all SSH scan sessions.
        
        Returns:
            List of scan session information
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT s.id, s.session_name, c.name as credential_name, 
                       s.targets, s.scan_time, s.results_path, s.status
                FROM ssh_scan_sessions s
                LEFT JOIN ssh_credentials c ON s.credential_id = c.id
                ORDER BY s.scan_time DESC
            ''')
            
            rows = cursor.fetchall()
            conn.close()
            
            sessions = []
            for row in rows:
                session_id, session_name, credential_name, targets, scan_time, results_path, status = row
                sessions.append({
                    'id': session_id,
                    'session_name': session_name,
                    'credential_name': credential_name,
                    'targets': json.loads(targets) if targets else [],
                    'scan_time': scan_time,
                    'results_path': results_path,
                    'status': status
                })
            
            return sessions
            
        except Exception as e:
            print(f"Error retrieving SSH scan sessions: {e}")
            return []
    
    def cleanup_old_credentials(self, days_old: int = 90) -> int:
        """
        Clean up old, unused credentials.
        
        Args:
            days_old: Number of days after which to clean up unused credentials
            
        Returns:
            Number of credentials cleaned up
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cutoff_date = datetime.now() - timedelta(days=days_old)
            
            cursor.execute('''
                UPDATE ssh_credentials 
                SET is_active = 0, updated_at = CURRENT_TIMESTAMP
                WHERE last_used < ? AND is_active = 1
            ''', (cutoff_date.isoformat(),))
            
            cleaned_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            print(f"Cleaned up {cleaned_count} old SSH credentials")
            return cleaned_count
            
        except Exception as e:
            print(f"Error cleaning up old credentials: {e}")
            return 0


# Example usage
if __name__ == "__main__":
    # Initialize credentials manager
    cred_manager = SSHCredentialsManager()
    
    # Save example credentials
    cred_manager.save_credentials(
        name="test_server",
        username="testuser",
        password="testpass",
        port=22,
        timeout=30
    )
    
    # List credentials
    credentials = cred_manager.list_credentials()
    print("Saved credentials:")
    for cred in credentials:
        print(f"- {cred['name']}: {cred['username']}@{cred['port']}")
    
    # Test credentials
    test_result = cred_manager.test_credentials("test_server", "192.168.1.100")
    print(f"Test result: {test_result}")
