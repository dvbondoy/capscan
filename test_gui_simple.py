#!/usr/bin/env python3
"""
Simple GUI test to verify AI integration works
"""

import sys
import tkinter as tk
from tkinter import messagebox

def test_gui_creation():
    """Test if GUI can be created without errors"""
    print("🧪 Testing GUI Creation with AI Integration...")
    print("=" * 50)
    
    try:
        # Import GUI
        from gui import CapScanGUI
        print("✅ GUI module imported successfully")
        
        # Create GUI instance
        print("Creating GUI instance...")
        app = CapScanGUI()
        print("✅ GUI instance created successfully")
        
        # Check if AI-related attributes exist
        ai_attributes = [
            'ai_service',
            'compliance_analyzers', 
            'mitigation_engine',
            'ai_analysis_var',
            'compliance_analysis_var',
            'mitigation_recommendations_var'
        ]
        
        print("\nChecking AI attributes...")
        for attr in ai_attributes:
            if hasattr(app, attr):
                print(f"✅ {attr} found")
            else:
                print(f"❌ {attr} not found")
                return False
        
        # Check if AI tabs exist
        print("\nChecking AI tabs...")
        tab_texts = [app.results_notebook.tab(i, "text") for i in range(app.results_notebook.index("end"))]
        ai_tabs = ["AI Analysis", "Compliance", "Mitigation"]
        
        for tab in ai_tabs:
            if tab in tab_texts:
                print(f"✅ {tab} tab found")
            else:
                print(f"❌ {tab} tab not found")
                return False
        
        print("\n🎉 GUI AI integration test passed!")
        print("\nTo test the full functionality:")
        print("1. Run: python gui.py")
        print("2. Perform a vulnerability scan")
        print("3. Use the new AI Analysis, Compliance, and Mitigation tabs")
        
        # Close the GUI
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"❌ GUI creation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run simple GUI test"""
    print("🚀 Starting Simple GUI AI Integration Test")
    print("=" * 60)
    
    success = test_gui_creation()
    
    if success:
        print("\n✅ GUI AI integration is working correctly!")
        return 0
    else:
        print("\n❌ GUI AI integration has issues.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
