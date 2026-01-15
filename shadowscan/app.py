#!/usr/bin/env python3
"""
ShadowScan - Main Application
=============================
Advanced Shodan Intelligence Platform
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Menu
import threading
import json
import csv
import os
from datetime import datetime
from pathlib import Path

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

from shadowscan.constants import (
    BANNER, MINI_BANNER, COLORS, QUICK_FILTERS, 
    COUNTRY_CODES, COMMON_PORTS, PROTOCOL_SEARCHES, SEARCH_HELP
)
from shadowscan.themes import DarkTheme
from shadowscan.utils import (
    is_valid_ip, is_valid_domain, build_search_query,
    format_timestamp, get_honeypot_score_color, get_honeypot_rating,
    parse_banner, extract_cves, export_to_json, export_to_csv,
    save_config, load_config, format_ports, generate_report_header,
    format_host_summary, get_config_dir
)


class ShadowScanApp:
    """Main ShadowScan Application Class"""
    
    def __init__(self, root):
        self.root = root
        self.colors = COLORS
        
        # Shodan API
        self.api = None
        self.api_key = ""
        self.connected = False
        
        # Data storage
        self.search_results = []
        self.current_host = None
        self.saved_results = []
        self.exploit_results = []
        
        # Apply theme
        DarkTheme.apply(root)
        
        # Build UI
        self.setup_ui()
        
        # Load configuration
        self.load_configuration()
    
    def setup_ui(self):
        """Setup main UI components"""
        self.create_header()
        self.create_api_frame()
        self.create_notebook()
        self.create_status_bar()
        self.create_menus()
    
    def create_header(self):
        """Create application header with banner"""
        header_frame = tk.Frame(self.root, bg=self.colors['bg_darkest'], height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        # Mini banner
        banner_label = tk.Label(
            header_frame,
            text=MINI_BANNER,
            font=('Consolas', 18, 'bold'),
            fg=self.colors['accent_green'],
            bg=self.colors['bg_darkest']
        )
        banner_label.pack(pady=10)
        
        # Subtitle
        subtitle = tk.Label(
            header_frame,
            text="[ Advanced Shodan Intelligence Platform ]",
            font=('Consolas', 10),
            fg=self.colors['accent_cyan'],
            bg=self.colors['bg_darkest']
        )
        subtitle.pack()
    
    def create_api_frame(self):
        """Create API key input section"""
        api_frame = tk.Frame(self.root, bg=self.colors['bg_medium'], pady=10)
        api_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # API Key Label
        tk.Label(
            api_frame,
            text="🔑 SHODAN API KEY:",
            font=('Consolas', 10, 'bold'),
            fg=self.colors['accent_cyan'],
            bg=self.colors['bg_medium']
        ).pack(side=tk.LEFT, padx=10)
        
        # API Key Entry
        self.api_entry = tk.Entry(
            api_frame,
            font=('Consolas', 11),
            bg=self.colors['entry_bg'],
            fg=self.colors['text_primary'],
            insertbackground=self.colors['accent_green'],
            relief=tk.FLAT,
            width=40,
            show='•'
        )
        self.api_entry.pack(side=tk.LEFT, padx=5)
        
        # Show/Hide Button
        self.show_key_var = tk.BooleanVar(value=False)
        self.toggle_btn = tk.Button(
            api_frame,
            text="👁",
            font=('Consolas', 10),
            bg=self.colors['bg_light'],
            fg=self.colors['text_primary'],
            relief=tk.FLAT,
            width=3,
            command=self.toggle_api_visibility
        )
        self.toggle_btn.pack(side=tk.LEFT, padx=2)
        
        # Connect Button
        self.connect_btn = tk.Button(
            api_frame,
            text="⚡ CONNECT",
            font=('Consolas', 10, 'bold'),
            bg=self.colors['accent_green'],
            fg=self.colors['bg_dark'],
            relief=tk.FLAT,
            width=12,
            cursor='hand2',
            command=self.connect_api
        )
        self.connect_btn.pack(side=tk.LEFT, padx=10)
        
        # Status/Credits
        self.api_status_label = tk.Label(
            api_frame,
            text="Status: Disconnected",
            font=('Consolas', 9),
            fg=self.colors['text_secondary'],
            bg=self.colors['bg_medium']
        )
        self.api_status_label.pack(side=tk.RIGHT, padx=10)
    
    def create_notebook(self):
        """Create main notebook with tabs"""
        self.notebook = ttk.Notebook(self.root, style='Dark.TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create all tabs
        self.create_search_tab()
        self.create_host_tab()
        self.create_dns_tab()
        self.create_exploits_tab()
        self.create_honeypot_tab()
        self.create_protocols_tab()
        self.create_saved_tab()
        self.create_help_tab()
    
    def create_status_bar(self):
        """Create status bar at bottom"""
        self.status_frame = tk.Frame(self.root, bg=self.colors['bg_darkest'], height=25)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_frame.pack_propagate(False)
        
        # Status message
        self.status_label = tk.Label(
            self.status_frame,
            text="[*] Ready - Enter API key to connect",
            font=('Consolas', 9),
            fg=self.colors['accent_green'],
            bg=self.colors['bg_darkest'],
            anchor='w'
        )
        self.status_label.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        # Loading indicator
        self.loading_label = tk.Label(
            self.status_frame,
            text="",
            font=('Consolas', 9),
            fg=self.colors['accent_yellow'],
            bg=self.colors['bg_darkest']
        )
        self.loading_label.pack(side=tk.RIGHT, padx=10)
    
    def create_menus(self):
        """Create application menus"""
        menubar = Menu(
            self.root,
            bg=self.colors['bg_medium'],
            fg=self.colors['text_primary'],
            activebackground=self.colors['accent_green'],
            activeforeground=self.colors['bg_dark'],
            borderwidth=0
        )
        
        # File Menu
        file_menu = Menu(menubar, tearoff=0,
                        bg=self.colors['bg_medium'],
                        fg=self.colors['text_primary'],
                        activebackground=self.colors['accent_green'],
                        activeforeground=self.colors['bg_dark'])
        file_menu.add_command(label="📁 Export JSON", command=self.export_json)
        file_menu.add_command(label="📄 Export CSV", command=self.export_csv)
        file_menu.add_command(label="📝 Generate Report", command=self.generate_report)
        file_menu.add_separator()
        file_menu.add_command(label="💾 Save Session", command=self.save_session)
        file_menu.add_command(label="📂 Load Session", command=self.load_session)
        file_menu.add_separator()
        file_menu.add_command(label="❌ Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools Menu
        tools_menu = Menu(menubar, tearoff=0,
                         bg=self.colors['bg_medium'],
                         fg=self.colors['text_primary'],
                         activebackground=self.colors['accent_green'],
                         activeforeground=self.colors['bg_dark'])
        tools_menu.add_command(label="🔄 Refresh Credits", command=self.refresh_credits)
        tools_menu.add_command(label="🗑️ Clear Results", command=self.clear_results)
        tools_menu.add_separator()
        tools_menu.add_command(label="⚙️ Settings", command=self.show_settings)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help Menu
        help_menu = Menu(menubar, tearoff=0,
                        bg=self.colors['bg_medium'],
                        fg=self.colors['text_primary'],
                        activebackground=self.colors['accent_green'],
                        activeforeground=self.colors['bg_dark'])
        help_menu.add_command(label="📖 Search Syntax", command=self.show_search_help)
        help_menu.add_command(label="ℹ️ About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    # =========================================================================
    # SEARCH TAB
    # =========================================================================
    
    def create_search_tab(self):
        """Create main search tab"""
        search_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(search_frame, text='🔍 Search')
        
        # Controls Frame
        controls = tk.Frame(search_frame, bg=self.colors['bg_dark'])
        controls.pack(fill=tk.X, padx=10, pady=10)
        
        # Row 1: Query
        tk.Label(
            controls, text="QUERY:", font=('Consolas', 10, 'bold'),
            fg=self.colors['accent_cyan'], bg=self.colors['bg_dark']
        ).grid(row=0, column=0, sticky='w', padx=5, pady=5)
        
        self.search_entry = tk.Entry(
            controls, font=('Consolas', 11),
            bg=self.colors['entry_bg'], fg=self.colors['text_primary'],
            insertbackground=self.colors['accent_green'],
            relief=tk.FLAT, width=50
        )
        self.search_entry.grid(row=0, column=1, columnspan=2, sticky='ew', padx=5, pady=5)
        self.search_entry.bind('<Return>', lambda e: self.execute_search())
        
        # Quick Filter
        tk.Label(
            controls, text="FILTER:", font=('Consolas', 10, 'bold'),
            fg=self.colors['accent_cyan'], bg=self.colors['bg_dark']
        ).grid(row=0, column=3, sticky='w', padx=(20, 5), pady=5)
        
        self.filter_var = tk.StringVar(value=QUICK_FILTERS[0])
        self.filter_combo = ttk.Combobox(
            controls, textvariable=self.filter_var,
            values=QUICK_FILTERS, width=25, state='readonly'
        )
        self.filter_combo.grid(row=0, column=4, padx=5, pady=5)
        self.filter_combo.bind('<<ComboboxSelected>>', self.apply_quick_filter)
        
        # Row 2: Additional Filters
        tk.Label(
            controls, text="COUNTRY:", font=('Consolas', 10, 'bold'),
            fg=self.colors['accent_cyan'], bg=self.colors['bg_dark']
        ).grid(row=1, column=0, sticky='w', padx=5, pady=5)
        
        self.country_var = tk.StringVar()
        self.country_combo = ttk.Combobox(
            controls, textvariable=self.country_var,
            values=COUNTRY_CODES, width=8
        )
        self.country_combo.grid(row=1, column=1, sticky='w', padx=5, pady=5)
        
        tk.Label(
            controls, text="PORT:", font=('Consolas', 10, 'bold'),
            fg=self.colors['accent_cyan'], bg=self.colors['bg_dark']
        ).grid(row=1, column=2, sticky
