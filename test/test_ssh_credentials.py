#!/usr/bin/env python3
"""
Test script for SSH credentials manager.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_ssh_credentials():
    """Test SSH credentials manager functionality."""
    print("Testing SSH Credentials Manager...")
    
    try:
        from ssh_credentials_manager import SSHCredentialsManager
        
        # Initialize credentials manager
        cred_manager = SSHCredentialsManager()
        print("✓ Credentials manager initialized")
        
        # Test saving credentials
        print("\nTesting credential save...")
        success = cred_manager.save_credentials(
            name="test_creds",
            username="testuser",
            password="testpass",
            port=22
        )
        
        if success:
            print("✓ Credentials saved successfully")
        else:
            print("✗ Failed to save credentials")
            return False
        
        # Test retrieving credentials
        print("\nTesting credential retrieval...")
        retrieved = cred_manager.get_credentials("test_creds")
        if retrieved:
            print(f"✓ Retrieved credentials: {retrieved['username']}")
        else:
            print("✗ Failed to retrieve credentials")
            return False
        
        # Test listing credentials
        print("\nTesting credential listing...")
        credentials = cred_manager.list_credentials()
        print(f"✓ Found {len(credentials)} credentials")
        for cred in credentials:
            print(f"  - {cred['name']}: {cred['username']}@{cred['port']}")
        
        # Clean up
        print("\nCleaning up...")
        cred_manager.delete_credentials("test_creds")
        print("✓ Test credentials cleaned up")
        
        return True
        
    except Exception as e:
        print(f"✗ Error during test: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("SSH Credentials Manager Test")
    print("=" * 40)
    
    success = test_ssh_credentials()
    
    if success:
        print("\n✓ All tests passed! SSH credentials should work now.")
    else:
        print("\n✗ Tests failed. Check the error messages above.")
        print("\nTroubleshooting tips:")
        print("1. Make sure you have write permissions to the current directory")
        print("2. Check if the database file is locked by another process")
        print("3. Try running: pip install cryptography")
