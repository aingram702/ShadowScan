#!/usr/bin/env python3
"""
ShadowScan - Advanced Shodan Intelligence Platform
Complete GUI Application in Single File
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
    print("[!] Shodan library not found. Install with: pip install shodan")


# ============================================================================
# BANNER AND CONSTANTS
# ============================================================================

BANNER = """
███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                    [ Advanced Shodan Intelligence Platform ]
"""

MINI_BANNER = "◢◤ SHADOWSCAN v1.0 ◢◤"

QUICK_FILTERS = [
    "-- Select Filter --",
    "-- Databases --",
    "product:mysql",
    "product:mongodb", 
    "product:postgresql",
    "product:redis",
    "product:elasticsearch",
    "product:memcached",
    "product:couchdb",
    "product:cassandra",
    "-- Web Servers --",
    "product:apache",
    "product:nginx",
    "product:iis",
    "product:tomcat",
    "product:lighttpd",
    "-- Network Devices --",
    "cisco",
    "mikrotik",
    "netgear",
    "fortinet",
    "palo alto",
    "juniper",
    "ubiquiti",
    "-- Industrial/SCADA --",
    "port:502 modbus",
    "port:102 s7",
    "port:44818 ethernet/ip",
    "port:47808 bacnet",
    "port:20000 dnp3",
    "-- Cameras/IoT --",
    "webcam",
    "netcam",
    "hikvision",
    "dahua",
    "axis camera",
    "-- Remote Access --",
    "port:3389 rdp",
    "port:22 ssh",
    "port:23 telnet",
    "port:5900 vnc",
    "-- Vulnerabilities --",
    "vuln:CVE-2021-44228",
    "vuln:CVE-2021-26855",
    "vuln:CVE-2020-1472",
    "vuln:CVE-2019-0708",
    "vuln:CVE-2017-0144",
    "-- Misconfigured --",
    "\"default password\"",
    "\"authentication disabled\"",
    "http.title:\"Index of /\"",
    "http.title:\"Dashboard\"",
    "http.title:\"phpMyAdmin\"",
]

COUNTRY_CODES = [
    "", "US", "GB", "DE", "FR", "CN", "RU", "JP", "KR", "BR",
    "IN", "AU", "CA", "IT", "ES", "NL", "SE", "CH", "PL", "UA",
    "TR", "MX", "ID", "TH", "VN", "PH", "MY", "SG", "HK", "TW",
    "ZA", "NG", "EG", "AE", "SA", "IL", "AR", "CL", "CO", "PE"
]

PROTOCOL_SEARCHES = {
    "HTTP": "port:80,8080,8000",
    "HTTPS": "port:443,8443",
    "SSH": "port:22 ssh",
    "FTP": "port:21 ftp",
    "Telnet": "port:23 telnet",
    "SMTP": "port:25,465,587",
    "DNS": "port:53",
    "RDP": "port:3389",
    "VNC": "port:5900,5901",
    "SMB": "port:445,139",
    "MySQL": "port:3306 mysql",
    "PostgreSQL": "port:5432 postgresql",
    "MongoDB": "port:27017 mongodb",
    "Redis": "port:6379 redis",
    "Elasticsearch": "port:9200 elasticsearch",
    "RTSP": "port:554 rtsp",
    "SIP": "port:5060 sip",
    "SNMP": "port:161 snmp",
    "Modbus": "port:502 modbus",
    "BACnet": "port:47808 bacnet",
}


# ============================================================================
# MAIN APPLICATION CLASS
# ============================================================================

class ShadowScanApp:
    """Main ShadowScan Application"""
    
    def __init__(self, root):
        self.root = root
        
        # Color scheme
        self.colors = {
            'bg_darkest': '#050505',
            'bg_dark': '#0a0a0a',
            'bg_medium': '#1a1a1a',
            'bg_light': '#2a2a2a',
            'accent_green': '#00ff41',
            'accent_green_dark': '#00cc33',
            'accent_red': '#ff0040',
            'accent_cyan': '#00ffff',
            'accent_yellow': '#ffff00',
            'accent_orange': '#ff8c00',
            'text_primary': '#00ff41',
            'text_secondary': '#808080',
            'text_white': '#ffffff',
            'entry_bg': '#0f0f0f',
            'border': '#333333',
        }
        
        # Shodan API client
        self.api = None
        self.api_key = ""
        self.connected = False
        
        # Data storage
        self.search_results = []
        self.current_host = None
        self.saved_results = []
        
        # Apply styling
        self.apply_styles()
        
        # Build UI
        self.setup_ui()
        
        # Load saved API key
        self.load_api_key()
    
    def apply_styles(self):
        """Apply ttk styles for dark theme"""
        style = ttk.Style()
        
        # Configure notebook
        style.configure('Dark.TNotebook',
                       background=self.colors['bg_dark'],
                       borderwidth=0)
        style.configure('Dark.TNotebook.Tab',
                       background=self.colors['bg_medium'],
                       foreground=self.colors['accent_green'],
                       padding=[15, 8],
                       font=('Consolas', 10, 'bold'))
        style.map('Dark.TNotebook.Tab',
                 background=[('selected', self.colors['bg_light'])],
                 foreground=[('selected', self.colors['accent_green'])])
        
        # Configure treeview
        style.configure('Dark.Treeview',
                       background=self.colors['bg_dark'],
                       foreground=self.colors['text_primary'],
                       fieldbackground=self.colors['bg_dark'],
                       borderwidth=0,
                       font=('Consolas', 9))
        style.configure('Dark.Treeview.Heading',
                       background=self.colors['bg_medium'],
                       foreground=self.colors['accent_cyan'],
                       font=('Consolas', 9, 'bold'))
        style.map('Dark.Treeview',
                 background=[('selected', self.colors['bg_light'])],
                 foreground=[('selected', self.colors['accent_green'])])
        
        # Configure frames
        style.configure('Dark.TFrame', background=self.colors['bg_dark'])
        style.configure('Dark.TLabelframe',
                       background=self.colors['bg_dark'],
                       foreground=self.colors['accent_green'])
        style.configure('Dark.TLabelframe.Label',
                       background=self.colors['bg_dark'],
                       foreground=self.colors['accent_cyan'],
                       font=('Consolas', 10, 'bold'))
    
    def setup_ui(self):
        """Setup main UI components"""
        self.create_header()
        self.create_api_frame()
        
        # Create notebook
        self.notebook = ttk.Notebook(self.root, style='Dark.TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs
        self.create_search_tab()
        self.create_host_tab()
        self.create_dns_tab()
        self.create_exploits_tab()
        self.create_honeypot_tab()
        self.create_protocols_tab()
        self.create_saved_tab()
        
        # Status bar
        self.create_status_bar()
    
    def create_header(self):
        """Create application header"""
        header_frame = tk.Frame(self.root, bg=self.colors['bg_darkest'], height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        # Banner text
        banner_label = tk.Label(
            header_frame,
            text=MINI_BANNER,
            font=('Consolas', 16, 'bold'),
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
        """Create API key input frame"""
        api_frame = tk.Frame(self.root, bg=self.colors['bg_medium'], pady=10)
        api_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # API key label
        tk.Label(
            api_frame,
            text="SHODAN API KEY:",
            font=('Consolas', 10, 'bold'),
            fg=self.colors['accent_cyan'],
            bg=self.colors['bg_medium']
        ).pack(side=tk.LEFT, padx=10)
        
        # API key entry
        self.api_entry = tk.Entry(
            api_frame,
            font=('Consolas', 11),
            bg=self.colors['entry_bg'],
            fg=self.colors['text_primary'],
            insertbackground=self.colors['accent_green'],
            relief=tk.FLAT,
            width=45,
            show='•'
        )
        self.api_entry.pack(side=tk.LEFT, padx=5)
        
        # Show/hide toggle
        self.show_key = tk.BooleanVar(value=False)
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
        
        # Connect button
        self.connect_btn = tk.Button(
            api_frame,
            text="⚡ CONNECT",
            font=('Consolas', 10, 'bold'),
            bg=self.colors['accent_green'],
            fg=self.colors['bg_dark'],
            relief=tk.FLAT,
            width=12,
            command=self.connect_api
        )
        self.connect_btn.pack(side=tk.LEFT, padx=10)
        
        # Credits label
        self.credits_label = tk.Label(
            api_frame,
            text="Credits: --",
            font=('Consolas', 9),
            fg=self.colors['text_secondary'],
            bg=self.colors['bg_medium']
        )
        self.credits_label.pack(side=tk.RIGHT, padx=10)
    
    def toggle_api_visibility(self):
        """Toggle API key visibility"""
        if self.show_key.get():
            self.api_entry.config(show='•')
            self.show_key.set(False)
        else:
            self.api_entry.config(show='')
            self.show_key.set(True)
    
    def create_status_bar(self):
        """Create status bar"""
        self.status_frame = tk.Frame(self.root, bg=self.colors['bg_darkest'], height=25)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(
            self.status_frame,
            text="[*] Ready - Enter API key to connect",
            font=('Consolas', 9),
            fg=self.colors['accent_green'],
            bg=self.colors['bg_darkest'],
            anchor='w'
        )
        self.status_label.pack(side=tk.LEFT, padx=10, fill=tk.X)
        
        # Loading indicator
        self.loading_label = tk.Label(
            self.status_frame,
            text="",
            font=('Consolas', 9),
            fg=self.colors['accent_yellow'],
            bg=self.colors['bg_darkest']
        )
        self.loading_label.pack(side=tk.RIGHT, padx=10)
    
    def update_status(self, message, color=None):
        """Update status bar message"""
        if color is None:
            color = self.colors['accent_green']
        self.status_label.config(text=f"[*] {message}", fg=color)
    
    def start_loading(self, message="Loading..."):
        """Start loading animation"""
        self.loading_label.config(text=f"⟳ {message}")
        self.root.update()
    
    def stop_loading(self):
        """Stop loading animation"""
        self.loading_label.config(text="")
    
    # ========================================================================
    # API CONNECTION
    # ========================================================================
    
    def connect_api(self):
        """Connect to Shodan API"""
        api_key = self.api_entry.get().strip()
        
        if not api_key:
            messagebox.showwarning("Warning", "Please enter an API key")
            return
        
        if not SHODAN_AVAILABLE:
            messagebox.showerror("Error", "Shodan library not installed!\nRun: pip install shodan")
            return
        
        self.start_loading("Connecting...")
        self.update_status("Connecting to Shodan API...")
        
        def connect_thread():
            try:
                self.api = shodan.Shodan(api_key)
                info = self.api.info()
                
                self.api_key = api_key
                self.connected = True
                
                # Update UI
                self.root.after(0, lambda: self.update_status(
                    f"Connected - Plan: {info.get('plan', 'N/A')} | Query Credits: {info.get('query_credits', 0)}",
                    self.colors['accent_green']
                ))
                self.root.after(0, lambda: self.connect_btn.config(
                    text="✓ CONNECTED",
                    bg=self.colors['accent_green']
                ))
                self.root.after(0, lambda: self.credits_label.config(
                    text=f"Credits: {info.get('query_credits', 0)}"
                ))
                
                # Save API key
                self.save_api_key()
                
            except shodan.APIError as e:
                self.connected = False
                self.root.after(0, lambda: self.update_status(f"API Error: {str(e)}", self.colors['accent_red']))
                self.root.after(0, lambda: messagebox.showerror("API Error", str(e)))
            except Exception as e:
                self.connected = False
                self.root.after(0, lambda: self.update_status(f"Error: {str(e)}", self.colors['accent_red']))
            finally:
                self.root.after(0, self.stop_loading)
        
        threading.Thread(target=connect_thread, daemon=True).start()
    
    def save_api_key(self):
        """Save API key to config"""
        try:
            config_dir = Path.home() / '.shadowscan'
            config_dir.mkdir(exist_ok=True)
            config_file = config_dir / 'config.json'
            
            with open(config_file, 'w') as f:
                json.dump({'api_key': self.api_key}, f)
        except Exception:
            pass
    
    def load_api_key(self):
        """Load saved API key"""
        try:
            config_file = Path.home() / '.shadowscan' / 'config.json'
            if config_file.exists():
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    api_key = config.get('api_key', '')
                    if api_key:
                        self.api_entry.insert(0, api_key)
        except Exception:
            pass
    
    # ========================================================================
    # SEARCH TAB
    # ========================================================================
    
    def create_search_tab(self):
        """Create search tab"""
        search_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(search_frame, text='🔍 Search')
        
        # Top controls
        controls_frame = tk.Frame(search_frame, bg=self.colors['bg_dark'])
        controls_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Search entry
        tk.Label(
            controls_frame,
            text="QUERY:",
            font=('Consolas', 10, 'bold'),
            fg=self.colors['accent_cyan'],
            bg=self.colors['bg_dark']
        ).grid(row=0, column=0, sticky='w', padx=5)
        
        self.search_entry = tk.Entry(
            controls_frame,
            font=('Consolas', 11),
            bg=self.colors['entry_bg'],
            fg=self.colors['text_primary'],
            insertbackground=self.colors['accent_green'],
            relief=tk.FLAT,
            width=50
        )
        self.search_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        self.search_entry.bind('<Return>', lambda e: self.execute_search())
        
        # Quick filters
        tk.Label(
            controls_frame,
            text="FILTER:",
            font=('Consolas', 10, 'bold'),
            fg=self.colors['accent_cyan'],
            bg=self.colors['bg_dark']
        ).grid(row=0, column=2, sticky='w', padx=(20, 5))
        
        self.filter_var = tk.StringVar(value=QUICK_FILTERS[0])
        self.filter_combo = ttk.Combobox(
            controls_frame,
            textvariable=self.filter_var,
            values=QUICK_FILTERS,
            width=25,
            state='readonly'
        )
        self.filter_combo.grid(row=0, column=3, padx=5)
        self.filter_combo.bind('<<ComboboxSelected>>', self.apply_quick_filter)
        
        # Second row - additional filters
        tk.Label(
            controls_frame,
            text="COUNTRY:",
            font=('Consolas', 10, 'bold'),
            fg=self.colors['accent_cyan'],
            bg=self.colors['bg_dark']
        ).grid(row=1, column=0, sticky='w', padx=5, pady=5)
        
        self.country_var = tk.StringVar()
        self.country_combo = ttk.Combobox(
            controls_frame,
            textvariable=self.country_var,
            values=COUNTRY_CODES,
            width=10
        )
        self.country_combo.grid(row=1, column=1, sticky='w', padx=5)
        
        tk.Label(
            controls_frame,
            text="PORT:",
            font=('Consolas', 10, 'bold'),
            fg=self.colors['accent_cyan'],
            bg=self.colors['bg_dark']
        ).grid(row=1, column=2, sticky='w', padx=(20, 5))
        
        self.port_entry = tk.Entry(
            controls_frame,
            font=('Consolas', 11),
            bg=self.colors['entry_bg'],
            fg=self.colors['text_primary'],
            relief=tk.FLAT,
            width=10
        )
        self.port_entry.grid(row=1, column=3, sticky='w', padx=5)
        
        # Search button
        search_btn = tk.Button(
            controls_frame,
            text="🔍 SEARCH",
            font=('Consolas', 11, 'bold'),
            bg=self.colors['accent_green'],
            fg=self.colors['bg_dark'],
            relief=tk.FLAT,
            width=15,
            command=self.execute_search
        )
        search_btn.grid(row=0, column=4, rowspan=2, padx=20, pady=5)
        
        controls_frame.columnconfigure(1, weight=1)
        
        # Results pane
        results_pane = tk.PanedWindow(
            search_frame,
            orient=tk.HORIZONTAL,
            bg=self.colors['bg_dark'],
            sashwidth=5,
            sashrelief=tk.FLAT
        )
        results_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Results treeview
        tree_frame = tk.Frame(results_pane, bg=self.colors['bg_dark'])
        
        columns = ('IP', 'Port', 'Protocol', 'Product', 'Version', 'Country', 'Org')
        self.search_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show='headings',
            style='Dark.Treeview'
        )
        
        # Configure columns
        self.search_tree.heading('IP', text='IP Address')
        self.search_tree.heading('Port', text='Port')
        self.search_tree.heading('Protocol', text='Proto')
        self.search_tree.heading('Product', text='Product')
        self.search_tree.heading('Version', text='Version')
        self.search_tree.heading('Country', text='Country')
        self.search_tree.heading('Org', text='Organization')
        
        self.search_tree.column('IP', width=120)
        self.search_tree.column('Port', width=60)
        self.search_tree.column('Protocol', width=50)
        self.search_tree.column('Product', width=100)
        self.search_tree.column('Version', width=80)
        self.search_tree.column('Country', width=60)
        self.search_tree.column('Org', width=150)
        
        # Scrollbars
        tree_scrolly = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.search_tree.yview)
        tree_scrollx = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.search_tree.xview)
        self.search_tree.configure(yscrollcommand=tree_scrolly.set, xscrollcommand=tree_scrollx.set)
        
        self.search_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scrolly.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection
        self.search_tree.bind('<<TreeviewSelect>>', self.on_search_select)
        
        results_pane.add(tree_frame, width=600)
        
        # Details panel
        details_frame = tk.Frame(results_pane, bg=self.colors['bg_dark'])
        
        tk.Label(
            details_frame,
            text="═══ HOST DETAILS ═══",
            font=('Consolas', 11, 'bold'),
            fg=self.colors['accent_cyan'],
            bg=self.colors['bg_dark']
        ).pack(pady=5)
        
        self.search_details = scrolledtext.ScrolledText(
            details_frame,
            font=('Consolas', 9),
            bg=self.colors['bg_darkest'],
            fg=self.colors['text_primary'],
            relief=tk.FLAT,
            wrap=tk.WORD
        )
        self.search_details.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure tags for details
        self.search_details.tag_configure('header', foreground=self.colors['accent_cyan'], font=('Consolas', 10, 'bold'))
        self.search_details.tag_configure('key', foreground=self.colors['accent_yellow'])
        self.search_details.tag_configure('value', foreground=self.colors['text_primary'])
        self.search_details.tag_configure('vuln', foreground=self.colors['accent_red'])
        self.search_details.tag_configure('port', foreground=self.colors['accent_orange'])
        
        results_pane.add(details_frame, width=400)
    
    def apply_quick_filter(self, event=None):
        """Apply quick filter to search"""
        selected = self.filter_var.get()
        if selected and not selected.startswith('--'):
            current = self.search_entry.get().strip()
            if current:
                self.search_entry.delete(0, tk.END)
                self.search_entry.insert(0, f"{current} {selected}")
            else:
                self.search_entry.delete(0, tk.END)
                self.search_entry.insert(0, selected)
    
    def execute_search(self):
        """Execute Shodan search"""
        if not self.connected:
            messagebox.showwarning("Warning", "Please connect to API first")
            return
        
        query = self.search_entry.get().strip()
        if not query:
            messagebox.showwarning("Warning", "Please enter a search query")
            return
        
        # Add filters
        country = self.country_var.get()
        port = self.port_entry.get().strip()
        
        if country:
            query += f" country:{country}"
        if port:
            query += f" port:{port}"
        
        self.start_loading("Searching...")
        self.update_status(f"Searching: {query}")
        
        # Clear previous results
        for item in self.search_tree.get_children():
            self.search_tree.delete(item)
        self.search_results = []
        
        def search_thread():
            try:
                results = self.api.search(query)
                
                self.search_results = results.get('matches', [])
                total = results.get('total', 0)
                
                # Update tree
                for match in self.search_results:
                    ip = match.get('ip_str', '')
                    port = match.get('port', '')
                    proto = match.get('transport', 'tcp')
                    product = match.get('product', 'unknown')
                    version = match.get('version', '')
                    country = match.get('location', {}).get('country_code', '')
                    org = match.get('org', '')[:30]
                    
                    self.root.after(0, lambda i=ip, p=port, pr=proto, pd=product, v=version, c=country, o=org:
                        self.search_tree.insert('', tk.END, values=(i, p, pr, pd, v, c, o))
                    )
                
                self.root.after(0, lambda: self.update_status(
                    f"Found {total} results ({len(self.search_results)} displayed)",
                    self.colors['accent_green']
                ))
                
            except shodan.APIError as e:
                self.root.after(0, lambda: self.update_status(f"Search Error: {str(e)}", self.colors['accent_red']))
                self.root.after(0, lambda: messagebox.showerror("Search Error", str(e)))
            except Exception as e:
                self.root.after(0, lambda: self.update_status(f"Error: {str(e)}", self.colors['accent_red']))
            finally:
                self.root.after(0, self.stop_loading)
        
        threading.Thread(target=search_thread, daemon=True).start()
    
    def on_search_select(self, event):
        """Handle search result selection"""
        selection = self.search_tree.selection()
        if not selection:
            return
        
        item = self.search_tree.item(selection[0])
        ip = item['values'][0]
        
        # Find matching result
        for match in self.search_results:
            if match.get('ip_str') == ip and match.get('port') == item['values'][1]:
                self.display_search_details(match)
                break
    
    def display_search_details(self, match):
        """Display host details in search tab"""
        self.search_details.delete('1.0', tk.END)
        
        self.search_details.insert(tk.END, "═══════════ HOST INFORMATION ═══════════\n", 'header')
        
        self.search_details.insert(tk.END, "\nIP: ", 'key')
        self.search_details.insert(tk.END, f"{match.get('ip_str', 'N/A')}\n", 'value')
        
        self.search_details.insert(tk.END, "Port: ", 'key')
        self.search_details.insert(tk.END, f"{match.get('port', 'N/A')}\n", 'port')
        
        self.search_details.insert(tk.END, "Protocol: ", 'key')
        self.search_details.insert(tk.END, f"{match.get('transport', 'N/A')}\n", 'value')
        
        self.search_details.insert(tk.END, "Product: ", 'key')
        self.search_details.insert(tk.END, f"{match.get('product', 'N/A')}\n", 'value')
        
        self.search_details.insert(tk.END, "Version: ", 'key')
        self.search_details.insert(tk.END, f"{match.get('version', 'N/A')}\n", 'value')
        
        self.search_details.insert(tk.END, "Organization: ", 'key')
        self.search_details.insert(tk.END, f"{match.get('org', 'N/A')}\n", 'value')
        
        self.search_details.insert(tk.END, "ISP: ", 'key')
        self.search_details.insert(tk.END, f"{match.get('isp', 'N/A')}\n", 'value')
        
        self.search_details.insert(tk.END, "ASN: ", 'key')
        self.search_details.insert(tk.END, f"{match.get('asn', 'N/A')}\n", 'value')
        
        # Location
        location = match.get('location', {})
        self.search_details.insert(tk.END, "\n═══════════ LOCATION ═══════════\n", 'header')
        
        self.search_details.insert(tk.END, "Country: ", 'key')
        self.search_details.insert(tk.END, f"{location.get('country_name', 'N/A')} ({location.get('country_code', '')})\n", 'value')
        
        self.search_details.insert(tk.END, "City: ", 'key')
        self.search_details.insert(tk.END, f"{location.get('city', 'N/A')}\n", 'value')
        
        self.search_details.insert(tk.END, "Coordinates: ", 'key')
        self.search_details.insert(tk.END, f"{location.get('latitude', 'N/A')}, {location.get('longitude', 'N/A')}\n", 'value')
        
        # Hostnames
        hostnames = match.get('hostnames', [])
        if hostnames:
            self.search_details.insert(tk.END, "\n═══════════ HOSTNAMES ═══════════\n", 'header')
            for hostname in hostnames:
                self.search_details.insert(tk.END, f"  • {hostname}\n", 'value')
        
        # Vulnerabilities
        vulns = match.get('vulns', [])
        if vulns:
            self.search_details.insert(tk.END, "\n═══════════ VULNERABILITIES ═══════════\n", 'header')
            for vuln in sorted(vulns):
                self.search_details.insert(tk.END, f"  [!] {vuln}\n", 'vuln')
        
        # Banner
        banner = match.get('data', '')
        if banner:
            self.search_details.insert(tk.END, "\n═══════════ BANNER ═══════════\n", 'header')
            # Truncate long banners
            if len(banner) > 2000:
                banner = banner[:2000] + "\n... (truncated)"
            self.search_details.insert(tk.END, banner, 'value')
    
    # ========================================================================
    # HOST TAB
    # ========================================================================
    
    def create_host_tab(self):
        """Create host lookup tab"""
        host_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(host_frame, text='🖥️ Host Lookup')
        
        # Controls
        controls_frame = tk.Frame(host_frame, bg=self.colors['bg_dark'])
        controls_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(
            controls_frame,
            text="IP ADDRESS:",
            font=('Consolas', 10, 'bold'),
            fg=self.colors['accent_cyan'],
            bg=self.colors['bg_dark']
        ).pack(side=tk.LEFT, padx=5)
        
        self.host_entry = tk.Entry(
            controls_frame,
            font=('Consolas', 11),
            bg=self.colors['entry_bg'],
            fg=self.colors['text_primary'],
            insertbackground=self.colors['accent_green'],
            relief=tk.FLAT,
            width=20
        )
        self.host_entry.pack(side=tk.LEFT, padx=5)
        self.host_entry.bind('<Return>', lambda e: self.lookup_host())
        
        # History checkbox
        self.host_history_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            controls_frame,
            text="Include History",
            variable=self.host_history_var,
            font=('Consolas', 9),
            fg=self.colors['accent_green'],
            bg=self.colors['bg_dark'],
            selectcolor=self.colors['bg_medium'],
            activebackground=self.colors['bg_dark']
        ).pack(side=tk.LEFT, padx=15)
        
        tk.Button(
            controls_frame,
            text="🔍 LOOKUP",
            font=('Consolas', 10, 'bold'),
            bg=self.colors['accent_green'],
            fg=self.colors['bg_dark'],
            relief=tk.FLAT,
            width=12,
            command=self.lookup_host
        ).pack(side=tk.LEFT, padx=10)
        
        # Results
        self.host_text = scrolledtext.ScrolledText(
            host_frame,
            font=('Consolas', 10),
            bg=self.colors['bg_darkest'],
            fg=self.colors['text_primary'],
            relief=tk.FLAT,
            wrap=tk.WORD
        )
        self.host_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Configure tags
        self.host_text.tag_configure('header', foreground=self.colors['accent_cyan'], font=('Consolas', 11, 'bold'))
        self.host_text.tag_configure('key', foreground=self.colors['accent_yellow'])
        self.host_text.tag_configure('value', foreground=self.colors['text_primary'])
        self.host_text.tag_configure('vuln', foreground=self.colors['accent_red'])
        self.host_text.tag_configure('port', foreground=self.colors['accent_orange'])
        self.host_text.tag_configure('banner', foreground=self.colors['text_secondary'])
    
    def lookup_host(self):
        """Lookup host information"""
        if not self.connected:
            messagebox.showwarning("Warning", "Please connect to API first")
            return
        
        ip = self.host_entry.get().strip()
        if not ip:
            messagebox.showwarning("Warning", "Please enter an IP address")
            return
        
        self.start_loading("Looking up host...")
        self.update_status(f"Looking up: {ip}")
        self.host_text.delete('1.0', tk.END)
        
        def lookup_thread():
            try:
                history = self.host_history_var.get()
                host = self.api.host(ip, history=history)
                self.current_host = host
                
                self.root.after(0, lambda: self.display_host_info(host))
                self.root.after(0, lambda: self.update_status(f"Host lookup complete: {ip}", self.colors['accent_green']))
                
            except shodan.APIError as e:
                self.root.after(0, lambda: self.update_status(f"Lookup Error: {str(e)}", self.colors['accent_red']))
                self.root.after(0, lambda: messagebox.showerror("Lookup Error", str(e)))
            except Exception as e:
                self.root.after(0, lambda: self.update_status(f"Error: {str(e)}", self.colors['accent_red']))
            finally:
                self.root.after(0, self.stop_loading)
        
        threading.Thread(target=lookup_thread, daemon=True).start()
    
    def display_host_info(self, host):
        """Display host information"""
        self.host_text.delete('1.0', tk.END)
        
        self.host_text.insert(tk.END, "╔══════════════════════════════════════════════════════════╗\n", 'header')
        self.host_text.insert(tk.END, "║                    HOST INFORMATION                       ║\n", 'header')
        self.host_text.insert(tk.END, "╚══════════════════════════════════════════════════════════╝\n", 'header')
        
        # Basic info
        self.host_text.insert(tk.END, "\n[BASIC INFO]\n", 'header')
        self.host_text.insert(tk.END, "  IP Address:    ", 'key')
        self.host_text.insert(tk.END, f"{host.get('ip_str', 'N/A')}\n", 'value')
        
        self.host_text.insert(tk.END, "  Organization:  ", 'key')
        self.host_text.insert(tk.END, f"{host.get('org', 'N/A')}\n", 'value')
        
        self.host_text.insert(tk.END, "  ISP:           ", 'key')
        self.host_text.insert(tk.END, f"{host.get('isp', 'N/A')}\n", 'value')
        
        self.host_text.insert(tk.END, "  ASN:           ", 'key')
        self.host_text.insert(tk.END, f"{host.get('asn', 'N/A')}\n", 'value')
        
        self.host_text.insert(tk.END, "  Last Update:   ", 'key')
        self.host_text.insert(tk.END, f"{host.get('last_update', 'N/A')}\n", 'value')
        
        # Location
        self.host_text.insert(tk.END, "\n[LOCATION]\n", 'header')
        location = host.get('location', {})
        
        self.host_text.insert(tk.END, "  Country:       ", 'key')
        self.host_text.insert(tk.END, f"{location.get('country_name', 'N/A')} ({location.get('country_code', '')})\n", 'value')
        
        self.host_text.insert(tk.END, "  City:          ", 'key')
        self.host_text.insert(tk.END, f"{location.get('city', 'N/A')}\n", 'value')
        
        self.host_text.insert(tk.END, "  Region:        ", 'key')
        self.host_text.insert(tk.END, f"{location.get('region_code', 'N/A')}\n", 'value')
        
        self.host_text.insert(tk.END, "  Coordinates:   ", 'key')
        self.host_text.insert(tk.END, f"{location.get('latitude', 'N/A')}, {location.get('longitude', 'N/A')}\n", 'value')
        
        # Hostnames
        hostnames = host.get('hostnames', [])
        if hostnames:
            self.host_text.insert(tk.END, "\n[HOSTNAMES]\n", 'header')
            for hostname in hostnames:
                self.host_text.insert(tk.END, f"  • {hostname}\n", 'value')
        
        # Ports
        ports = host.get('ports', [])
        if ports:
            self.host_text.insert(tk.END, "\n[OPEN PORTS]\n", 'header')
            self.host_text.insert(tk.END, f"  {', '.join(map(str, sorted(ports)))}\n", 'port')
        
        # Vulnerabilities
        vulns = host.get('vulns', [])
        if vulns:
            self.host_text.insert(tk.END, "\n[VULNERABILITIES]\n", 'header')
            for vuln in sorted(vulns):
                self.host_text.insert(tk.END, f"  [!] {vuln}\n", 'vuln')
        
        # Services
        data = host.get('data', [])
        if data:
            self.host_text.insert(tk.END, "\n[SERVICES]\n", 'header')
            for service in data:
                port = service.get('port', '')
                product = service.get('product', 'unknown')
                version = service.get('version', '')
                transport = service.get('transport', 'tcp')
                
                self.host_text.insert(tk.END, f"\n  ──── Port {port}/{transport} ────\n", 'port')
                self.host_text.insert(tk.END, f"  Product: ", 'key')
                self.host_text.insert(tk.END, f"{product} {version}\n", 'value')
                
                # Banner snippet
                banner = service.get('data', '')
                if banner:
                    banner_preview = banner[:500].strip()
                    if len(banner) > 500:
                        banner_preview += "\n  ... (truncated)"
                    self.host_text.insert(tk.END, f"  Banner:\n{banner_preview}\n", 'banner')
    
    # ========================================================================
    # DNS TAB
    # ========================================================================
    
    def create_dns_tab(self):
        """Create DNS lookup tab"""
        dns_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(dns_frame, text='🌐 DNS')
        
        # Controls
        controls_frame = tk.Frame(dns_frame, bg=self.colors['bg_dark'])
        controls_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(
            controls_frame,
            text="DOMAIN/IP:",
            font=('Consolas', 10, 'bold'),
            fg=self.colors['accent_cyan'],
            bg=self.colors['bg_dark']
        ).pack(side=tk.LEFT, padx=5)
        
        self.dns_entry = tk.Entry(
            controls_frame,
            font=('Consolas', 11),
            bg=self.colors['entry_bg'],
            fg=self.colors['text_primary'],
            insertbackground=self.colors['accent_green'],
            relief=tk.FLAT,
            width=30
        )
        self.dns_entry.pack(side=tk.LEFT, padx=5)
        self.dns_entry.bind('<Return>', lambda e: self.dns_resolve())
        
        tk.Button(
            controls_frame,
            text="DNS RESOLVE",
            font=('Consolas', 10, 'bold'),
            bg=self.colors['accent_green'],
            fg=self.colors['bg_dark'],
            relief=tk.FLAT,
            width=12,
            command=self.dns_resolve
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            controls_frame,
            text="REVERSE DNS",
            font=('Consolas', 10, 'bold'),
            bg=self.colors['accent_cyan'],
            fg=self.colors['bg_dark'],
            relief=tk.FLAT,
            width=12,
            command=self.dns_reverse
        ).pack(side=tk.LEFT, padx=5)
        
        # Results
        self.dns_text = scrolledtext.ScrolledText(
            dns_frame,
            font=('Consolas', 10),
            bg=self.colors['bg_darkest'],
            fg=self.colors['text_primary'],
            relief=tk.FLAT,
            wrap=tk.WORD
        )
        self.dns_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.dns_text.tag_configure('header', foreground=self.colors['accent_cyan'], font=('Consolas', 11, 'bold'))
        self.dns_text.tag_configure('key', foreground=self.colors['accent_yellow'])
        self.dns_text.tag_configure('value', foreground=self.colors['text_primary'])
    
    def dns_resolve(self):
        """Resolve domain to IP"""
        if not self.connected:
            messagebox.showwarning("Warning", "Please connect to API first")
            return
        
        domain = self.dns_entry.get().strip()
        if not domain:
            messagebox.showwarning("Warning", "Please enter a domain name")
            return
        
        self.start_loading("Resolving...")
        self.update_status(f"Resolving: {domain}")
        
        def resolve_thread():
            try:
                results = self.api.dns.resolve([domain])
                
                self.root.after(0, lambda: self.dns_text.delete('1.0', tk.END))
                self.root.after(0, lambda: self.dns_text.insert(tk.END, "[DNS RESOLUTION]\n\n", 'header'))
                
                for hostname, ip in results.items():
                    self.root.after(0, lambda h=hostname, i=ip: self.dns_text.insert(tk.END, f"  {h}  →  {i}\n", 'value'))
                
                self.root.after(0, lambda: self.update_status(f"Resolved {domain}", self.colors['accent_green']))
                
            except shodan.APIError as e:
                self.root.after(0, lambda: self.update_status(f"DNS Error: {str(e)}", self.colors['accent_red']))
                self.root.after(0, lambda: messagebox.showerror("DNS Error", str(e)))
            except Exception as e:
                self.root.after(0, lambda: self.update_status(f"Error: {str(e)}", self.colors['accent_red']))
            finally:
                self.root.after(0, self.stop_loading)
        
        threading.Thread(target=resolve_thread, daemon=True).start()
    
    def dns_reverse(self):
        """Reverse DNS lookup"""
        if not self.connected:
            messagebox.showwarning("Warning", "Please connect to API first")
            return
        
        ip = self.dns_entry.get().strip()
        if not ip:
            messagebox.showwarning("Warning", "Please enter an IP address")
            return
        
        self.start_loading("Reverse lookup...")
        self.update_status(f"Reverse DNS: {ip}")
        
        def reverse_thread():
            try:
                results = self.api.dns.reverse([ip])
                
                self.root.after(0, lambda: self.dns_text.delete('1.0', tk.END))
                self.root.after(0, lambda: self.dns_text.insert(tk.END, "[REVERSE DNS]\n\n", 'header'))
                
                for ip_addr, hostnames in results.items():
                    self.root.after(0, lambda i=ip_addr: self.dns_text.insert(tk.END, f"  IP: {i}\n", 'key'))
                    if hostnames:
                        for hostname in hostnames:
                            self.root.after(0, lambda h=hostname: self.dns_text.insert(tk.END, f"    → {h}\n", 'value'))
                    else:
                        self.root.after(0, lambda: self.dns_text.insert(tk.END, "    → No hostnames found\n", 'value'))
                
                self.root.after(0, lambda: self.update_status(f"Reverse lookup complete: {ip}", self.colors['accent_green']))
                
            except shodan.APIError as e:
                self.root.after(0, lambda: self.update_status(f"DNS Error: {str(e)}", self.colors['accent_red']))
                self.root.after(0, lambda: messagebox.showerror("DNS Error", str(e)))
            except Exception as e:
                self.root.after(0, lambda: self.update_status(f"Error: {str(e)}", self.colors['accent_red']))
            finally:
                self.root.after(0, self.stop_loading)
        
        threading.Thread(target=reverse_thread, daemon=True).start()
    
    # ========================================================================
    # EXPLOITS TAB
    # ========================================================================
    
    def create_exploits_tab(self):
        """Create exploits search tab"""
        exploits_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(exploits_frame, text='💥 Exploits')
        
        # Controls
        controls_frame = tk.Frame(exploits_frame, bg=self.colors['bg_dark'])
        controls_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(
            controls_frame,
            text="SEARCH:",
            font=('Consolas', 10, 'bold'),
            fg=self.colors['accent_cyan'],
            bg=self.colors['bg_dark']
        ).pack(side=tk.LEFT, padx=5)
        
        self.exploit_entry = tk.Entry(
            controls_frame,
            font=('Consolas', 11),
            bg=self.colors['entry_bg'],
            fg=self.colors['text_primary'],
            insertbackground=self.colors['accent_green'],
            relief=tk.FLAT,
            width=40
        )
        self.exploit_entry.pack(side=tk.LEFT, padx=5)
        self.exploit_entry.insert(0, "apache")
        self.exploit_entry.bind('<Return>', lambda e: self.search_exploits())
        
        tk.Button(
            controls_frame,
            text="🔍 SEARCH EXPLOITS",
            font=('Consolas', 10, 'bold'),
            bg=self.colors['accent_red'],
            fg=self.colors['text_white'],
            relief=tk.FLAT,
            width=18,
            command=self.search_exploits
        ).pack(side=tk.LEFT, padx=10)
        
        # Results treeview
        tree_frame = tk.Frame(exploits_frame, bg=self.colors['bg_dark'])
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ('CVE', 'Description', 'Type', 'Platform', 'Source')
        self.exploits_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show='headings',
            style='Dark.Treeview'
        )
        
        self.exploits_tree.heading('CVE', text='CVE/ID')
        self.exploits_tree.heading('Description', text='Description')
        self.exploits_tree.heading('Type', text='Type')
        self.exploits_tree.heading('Platform', text='Platform')
        self.exploits_tree.heading('Source', text='Source')
        
        self.exploits_tree.column('CVE', width=120)
        self.exploits_tree.column('Description', width=400)
        self.exploits_tree.column('Type', width=100)
        self.exploits_tree.column('Platform', width=100)
        self.exploits_tree.column('Source', width=100)
        
        scrolly = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.exploits_tree.yview)
        self.exploits_tree.configure(yscrollcommand=scrolly.set)
        
        self.exploits_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrolly.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Exploit details
        self.exploit_details = scrolledtext.ScrolledText(
            exploits_frame,
            font=('Consolas', 9),
            bg=self.colors['bg_darkest'],
            fg=self.colors['text_primary'],
            relief=tk.FLAT,
            wrap=tk.WORD,
            height=10
        )
        self.exploit_details.pack(fill=tk.X, padx=10, pady=5)
        
        self.exploits_tree.bind('<<TreeviewSelect>>', self.on_exploit_select)
        self.exploit_results = []
    
    def search_exploits(self):
        """Search for exploits"""
        if not self.connected:
            messagebox.showwarning("Warning", "Please connect to API first")
            return
        
        query = self.exploit_entry.get().strip()
        if not query:
            messagebox.showwarning("Warning", "Please enter a search query")
            return
        
        self.start_loading("Searching exploits...")
        self.update_status(f"Searching exploits: {query}")
        
        # Clear previous
        for item in self.exploits_tree.get_children():
            self.exploits_tree.delete(item)
        self.exploit_results = []
        
        def search_thread():
            try:
                results = self.api.exploits.search(query, limit=100)
                self.exploit_results = results.get('matches', [])
                total = results.get('total', 0)
                
                for exploit in self.exploit_results:
                    cve = exploit.get('cve', [])
                    cve_str = cve[0] if cve else exploit.get('_id', 'N/A')
                    desc = exploit.get('description', '')[:80]
                    etype = exploit.get('type', 'N/A')
                    platform = exploit.get('platform', 'N/A')
                    source = exploit.get('source', 'N/A')
                    
                    self.root.after(0, lambda c=cve_str, d=desc, t=etype, p=platform, s=source:
                        self.exploits_tree.insert('', tk.END, values=(c, d, t, p, s))
                    )
                
                self.root.after(0, lambda: self.update_status(
                    f"Found {total} exploits ({len(self.exploit_results)} displayed)",
                    self.colors['accent_green']
                ))
                
            except shodan.APIError as e:
                self.root.after(0, lambda: self.update_status(f"Exploit Error: {str(e)}", self.colors['accent_red']))
                self.root.after(0, lambda: messagebox.showerror("Exploit Error", str(e)))
            except Exception as e:
                self.root.after(0, lambda: self.update_status(f"Error: {str(e)}", self.colors['accent_red']))
            finally:
                self.root.after(0, self.stop_loading)
        
        threading.Thread(target=search_thread, daemon=True).start()
    
    def on_exploit_select(self, event):
        """Handle exploit selection"""
        selection = self.exploits_tree.selection()
        if not selection:
            return
        
        item = self.exploits_tree.item(selection[0])
        exploit_id = item['values'][0]
        
        for exploit in self.exploit_results:
            cve = exploit.get('cve', [])
            eid = cve[0] if cve else exploit.get('_id', '')
            if eid == exploit_id:
                self.exploit_details.delete('1.0', tk.END)
                self.exploit_
