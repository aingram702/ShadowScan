#!/usr/bin/env python3
"""
ShadowScan - Quick Launch Script
Run this file to start the application
"""

import sys
import os

# Add the project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def check_dependencies():
    """Check if required packages are installed"""
    missing = []
    
    try:
        import shodan
    except ImportError:
        missing.append('shodan')
    
    try:
        import requests
    except ImportError:
        missing.append('requests')
    
    if missing:
        print("[!] Missing required packages:", ', '.join(missing))
        print("[*] Install with: pip install " + ' '.join(missing))
        sys.exit(1)

def main():
    """Main entry point"""
    check_dependencies()
    
    import tkinter as tk
    from tkinter import messagebox
    
    # Create root window
    root = tk.Tk()
    root.title("ShadowScan - Shodan Intelligence Platform")
    root.geometry("1400x900")
    root.minsize(1200, 800)
    root.configure(bg='#0a0a0a')
    
    # Import and initialize app
    from shadowscan_app import ShadowScanApp
    app = ShadowScanApp(root)
    
    # Handle window close
    def on_closing():
        if messagebox.askokcancel("Quit", "Exit ShadowScan?"):
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
