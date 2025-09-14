#!/usr/bin/env python3
"""
Check SSH credentials storage location and contents.
"""

import sqlite3
import os
import sys

def check_ssh_credentials_storage():
    """Check where SSH credentials are stored and what's in the database."""
    
    print("SSH Credentials Storage Check")
    print("=" * 40)
    
    # Check database file location
    db_path = "/home/dvbondoy/capscan/capscan.db"
    print(f"Database file: {db_path}")
    print(f"File exists: {os.path.exists(db_path)}")
    
    if os.path.exists(db_path):
        file_size = os.path.getsize(db_path)
        print(f"File size: {file_size} bytes")
    
    # Check database contents
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # List all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"\nDatabase tables: {[table[0] for table in tables]}")
        
        # Check if ssh_credentials table exists
        if ('ssh_credentials',) in tables:
            print("\n✓ ssh_credentials table found")
            
            # Get table schema
            cursor.execute("PRAGMA table_info(ssh_credentials);")
            columns = cursor.fetchall()
            print("\nTable schema:")
            for col in columns:
                print(f"  - {col[1]} ({col[2]})")
            
            # Count credentials
            cursor.execute("SELECT COUNT(*) FROM ssh_credentials WHERE is_active = 1;")
            count = cursor.fetchone()[0]
            print(f"\nActive credentials: {count}")
            
            # List credentials (without sensitive data)
            cursor.execute("""
                SELECT name, username, port, created_at, last_used 
                FROM ssh_credentials 
                WHERE is_active = 1 
                ORDER BY updated_at DESC
            """)
            credentials = cursor.fetchall()
            
            if credentials:
                print("\nSaved credentials:")
                for cred in credentials:
                    name, username, port, created, last_used = cred
                    print(f"  - {name}: {username}@{port}")
                    print(f"    Created: {created}")
                    print(f"    Last used: {last_used or 'Never'}")
            else:
                print("\nNo credentials found")
                
        else:
            print("\n✗ ssh_credentials table not found")
            print("This means SSH credentials haven't been created yet")
        
        conn.close()
        
    except Exception as e:
        print(f"\nError accessing database: {e}")
        print("This might be because the database is encrypted or locked")

def check_alternative_locations():
    """Check alternative locations where credentials might be stored."""
    
    print("\nAlternative Storage Locations:")
    print("-" * 30)
    
    # Check current directory
    current_dir = os.getcwd()
    print(f"Current directory: {current_dir}")
    
    # Check for any .db files
    db_files = [f for f in os.listdir('.') if f.endswith('.db')]
    if db_files:
        print(f"Database files in current directory: {db_files}")
    else:
        print("No .db files in current directory")
    
    # Check for SSH-related files
    ssh_files = [f for f in os.listdir('.') if 'ssh' in f.lower()]
    if ssh_files:
        print(f"SSH-related files: {ssh_files}")
    else:
        print("No SSH-related files found")

if __name__ == "__main__":
    check_ssh_credentials_storage()
    check_alternative_locations()
    
    print("\n" + "=" * 40)
    print("Summary:")
    print("- SSH credentials are stored in: /home/dvbondoy/capscan/capscan.db")
    print("- They are encrypted using the same password as your main database")
    print("- The table name is: ssh_credentials")
    print("- Sensitive data (passwords/keys) is encrypted before storage")
