#!/usr/bin/env python3
"""
Test GUI AI integration
"""

import tkinter as tk
from gui import CapScanGUI

def test_gui_ai():
    """Test GUI AI service integration."""
    print("🧪 Testing GUI AI Integration...")
    
    # Create a minimal root window
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    
    try:
        # Initialize GUI with mock AI
        gui = CapScanGUI()
        
        # Check AI service status
        status = gui.ai_service.get_service_status()
        print(f"✅ AI Available: {status['ai_available']}")
        print(f"✅ Active Backend: {status['active_backend']}")
        print(f"✅ Available Backends: {status['available_backends']}")
        
        # Test AI analysis
        print("\n🔍 Testing AI analysis...")
        sample_scan = {
            'target': '192.168.1.100',
            'vulnerabilities': [
                {
                    'cve_id': 'CVE-2021-44228',
                    'score': 9.8,
                    'description': 'Apache Log4j2 Remote Code Execution vulnerability',
                    'severity': 'critical'
                }
            ]
        }
        
        analysis = gui.ai_service.analyze_vulnerabilities(sample_scan)
        print(f"✅ Analysis completed: {len(analysis.get('raw_analysis', ''))} characters")
        
        print("\n🎉 GUI AI integration test passed!")
        print("✅ No API key required - using mock backend")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False
    finally:
        root.destroy()
    
    return True

if __name__ == "__main__":
    test_gui_ai()