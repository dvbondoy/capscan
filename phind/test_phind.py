#!/usr/bin/env python3
"""
Simple test script for the Phind Python client
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from phind_client import PhindClient

def test_basic_connection():
    """Test basic connection to Phind"""
    print("Testing basic connection to Phind...")
    
    try:
        client = PhindClient()
        
        # Test with a simple question
        response = client.chat("Hello, can you say 'Hi' back?")
        
        if response and len(response.strip()) > 0:
            print("✅ Basic connection test passed!")
            print(f"Response: {response}")
            return True
        else:
            print("❌ Basic connection test failed - no response received")
            return False
            
    except Exception as e:
        print(f"❌ Basic connection test failed with error: {e}")
        return False

def test_error_handling():
    """Test error handling"""
    print("\nTesting error handling...")
    
    try:
        client = PhindClient()
        
        # Test with empty input
        response = client.chat("")
        
        if response is not None:
            print("✅ Error handling test passed!")
            return True
        else:
            print("❌ Error handling test failed")
            return False
            
    except Exception as e:
        print(f"❌ Error handling test failed with error: {e}")
        return False

def main():
    """Run all tests"""
    print("Phind Python Client - Test Suite")
    print("=" * 40)
    
    tests = [
        test_basic_connection,
        test_error_handling,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print(f"\n" + "=" * 40)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
        return 0
    else:
        print("⚠️  Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
