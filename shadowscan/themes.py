"""
ShadowScan Theme Configuration
"""

import tkinter as tk
from tkinter import ttk
from shadowscan.constants import COLORS


class DarkTheme:
    """Dark hacker theme for ShadowScan"""
    
    COLORS = COLORS
    
    @classmethod
    def apply(cls, root):
        """Apply dark theme to root window and ttk styles"""
        root.configure(bg=cls.COLORS['bg_dark'])
        
        style = ttk.Style()
        
        # Try to use clam theme as base
        try:
            style.theme_use('clam')
        except:
            pass
        
        # Configure Notebook
        style.configure(
            'Dark.TNotebook',
            background=cls.COLORS['bg_dark'],
            borderwidth=0,
            tabmargins=[2, 5, 2, 0]
        )
        
        style.configure(
            'Dark.TNotebook.Tab',
            background=cls.COLORS['bg_medium'],
            foreground=cls.COLORS['accent_green'],
            padding=[15, 8],
            font=('Consolas', 10, 'bold'),
            borderwidth=0
        )
        
        style.map(
            'Dark.TNotebook.Tab',
            background=[
                ('selected', cls.COLORS['bg_light']),
                ('active', cls.COLORS['bg_lighter'])
            ],
            foreground=[
                ('selected', cls.COLORS['accent_green']),
                ('active', cls.COLORS['accent_cyan'])
            ],
            expand=[('selected', [1, 1, 1, 0])]
        )
        
        # Configure Treeview
        style.configure(
            'Dark.Treeview',
            background=cls.COLORS['bg_dark'],
            foreground=cls.COLORS['text_primary'],
            fieldbackground=cls.COLORS['bg_dark'],
            borderwidth=0,
            font=('Consolas', 9),
            rowheight=25
        )
        
        style.configure(
            'Dark.Treeview.Heading',
            background=cls.COLORS['bg_medium'],
            foreground=cls.COLORS['accent_cyan'],
            font=('Consolas', 9, 'bold'),
            borderwidth=1,
            relief='flat'
        )
        
        style.map(
            'Dark.Treeview',
            background=[('selected', cls.COLORS['bg_light'])],
            foreground=[('selected', cls.COLORS['accent_green'])]
        )
        
        style.map(
            'Dark.Treeview.Heading',
            background=[('active', cls.COLORS['bg_light'])]
        )
        
        # Configure Frames
        style.configure(
            'Dark.TFrame',
            background=cls.COLORS['bg_dark']
        )
        
        style.configure(
            'DarkMedium.TFrame',
            background=cls.COLORS['bg_medium']
        )
        
        # Configure LabelFrame
        style.configure(
            'Dark.TLabelframe',
            background=cls.COLORS['bg_dark'],
            foreground=cls.COLORS['accent_green'],
            borderwidth=2,
            relief='groove'
        )
        
        style.configure(
            'Dark.TLabelframe.Label',
            background=cls.COLORS['bg_dark'],
            foreground=cls.COLORS['accent_cyan'],
            font=('Consolas', 10, 'bold')
        )
        
        # Configure Scrollbar
        style.configure(
            'Dark.Vertical.TScrollbar',
            background=cls.COLORS['bg_light'],
            troughcolor=cls.COLORS['bg_dark'],
            borderwidth=0,
            arrowcolor=cls.COLORS['accent_green']
        )
        
        style.map(
            'Dark.Vertical.TScrollbar',
            background=[('active', cls.COLORS['accent_green_dark'])]
        )
        
        # Configure Combobox
        style.configure(
            'Dark.TCombobox',
            background=cls.COLORS['entry_bg'],
            foreground=cls.COLORS['text_primary'],
            fieldbackground=cls.COLORS['entry_bg'],
            selectbackground=cls.COLORS['bg_light'],
            selectforeground=cls.COLORS['accent_green']
        )
        
        style.map(
            'Dark.TCombobox',
            fieldbackground=[('readonly', cls.COLORS['entry_bg'])],
            selectbackground=[('readonly', cls.COLORS['bg_light'])]
        )
        
        # Configure Progressbar
        style.configure(
            'Dark.Horizontal.TProgressbar',
            background=cls.COLORS['accent_green'],
            troughcolor=cls.COLORS['bg_dark'],
            borderwidth=0
        )
        
        # Configure Button
        style.configure(
            'Dark.TButton',
            background=cls.COLORS['bg_light'],
            foreground=cls.COLORS['text_primary'],
            font=('Consolas', 10),
            borderwidth=0,
            padding=[10, 5]
        )
        
        style.map(
            'Dark.TButton',
            background=[
                ('active', cls.COLORS['accent_green_dark']),
                ('pressed', cls.COLORS['accent_green'])
            ],
            foreground=[
                ('active', cls.COLORS['bg_dark']),
                ('pressed', cls.COLORS['bg_dark'])
            ]
        )
        
        # Configure Entry
        style.configure(
            'Dark.TEntry',
            fieldbackground=cls.COLORS['entry_bg'],
            foreground=cls.COLORS['text_primary'],
            insertcolor=cls.COLORS['accent_green'],
            borderwidth=0
        )
        
        # Configure Checkbutton
        style.configure(
            'Dark.TCheckbutton',
            background=cls.COLORS['bg_dark'],
            foreground=cls.COLORS['text_primary'],
            font=('Consolas', 9)
        )
        
        style.map(
            'Dark.TCheckbutton',
            background=[('active', cls.COLORS['bg_dark'])],
            foreground=[('active', cls.COLORS['accent_green'])]
        )
        
        # Configure Radiobutton
        style.configure(
            'Dark.TRadiobutton',
            background=cls.COLORS['bg_dark'],
            foreground=cls.COLORS['text_primary'],
            font=('Consolas', 9)
        )
        
        style.map(
            'Dark.TRadiobutton',
            background=[('active', cls.COLORS['bg_dark'])],
            foreground=[('active', cls.COLORS['accent_green'])]
        )
        
        # Configure Separator
        style.configure(
            'Dark.TSeparator',
            background=cls.COLORS['border']
        )
        
        return style
    
    @classmethod
    def create_styled_button(cls, parent, text, command=None, style='default'):
        """Create a styled button"""
        styles = {
            'default': {
                'bg': cls.COLORS['bg_light'],
                'fg': cls.COLORS['text_primary'],
                'active_bg': cls.COLORS['bg_lighter']
            },
            'primary': {
                'bg': cls.COLORS['accent_green'],
                'fg': cls.COLORS['bg_dark'],
                'active_bg': cls.COLORS['accent_green_dark']
            },
            'danger': {
                'bg': cls.COLORS['accent_red'],
                'fg': cls.COLORS['text_white'],
                'active_bg': cls.COLORS['accent_red_dark']
            },
            'info': {
                'bg': cls.COLORS['accent_cyan'],
                'fg': cls.COLORS['bg_dark'],
                'active_bg': cls.COLORS['accent_cyan_dark']
            }
        }
        
        s = styles.get(style, styles['default'])
        
        btn = tk.Button(
            parent,
            text=text,
            font=('Consolas', 10, 'bold'),
            bg=s['bg'],
            fg=s['fg'],
            activebackground=s['active_bg'],
            activeforeground=s['fg'],
            relief=tk.FLAT,
            cursor='hand2',
            command=command
        )
        
        return btn
    
    @classmethod
    def create_styled_entry(cls, parent, **kwargs):
        """Create a styled entry widget"""
        entry = tk.Entry(
            parent,
            font=kwargs.get('font', ('Consolas', 11)),
            bg=cls.COLORS['entry_bg'],
            fg=cls.COLORS['text_primary'],
            insertbackground=cls.COLORS['accent_green'],
            selectbackground=cls.COLORS['bg_light'],
            selectforeground=cls.COLORS['accent_green'],
            relief=tk.FLAT,
            bd=2,
            **{k: v for k, v in kwargs.items() if k not in ['font']}
        )
        return entry
    
    @classmethod
    def create_styled_text(cls, parent, **kwargs):
        """Create a styled text widget"""
        from tkinter import scrolledtext
        
        text = scrolledtext.ScrolledText(
            parent,
            font=kwargs.get('font', ('Consolas', 10)),
            bg=cls.COLORS['bg_darkest'],
            fg=cls.COLORS['text_primary'],
            insertbackground=cls.COLORS['accent_green'],
            selectbackground=cls.COLORS['bg_light'],
            selectforeground=cls.COLORS['accent_green'],
            relief=tk.FLAT,
            wrap=tk.WORD,
            **{k: v for k, v in kwargs.items() if k not in ['font']}
        )
        
        # Configure standard tags
        text.tag_configure('header', foreground=cls.COLORS['accent_cyan'], font=('Consolas', 11, 'bold'))
        text.tag_configure('subheader', foreground=cls.COLORS['accent_yellow'], font=('Consolas', 10, 'bold'))
        text.tag_configure('key', foreground=cls.COLORS['accent_yellow'])
        text.tag_configure('value', foreground=cls.COLORS['text_primary'])
        text.tag_configure('success', foreground=cls.COLORS['success'])
        text.tag_configure('warning', foreground=cls.COLORS['warning'])
        text.tag_configure('error', foreground=cls.COLORS['error'])
        text.tag_configure('info', foreground=cls.COLORS['info'])
        text.tag_configure('dim', foreground=cls.COLORS['text_dim'])
        text.tag_configure('port', foreground=cls.COLORS['accent_orange'])
        text.tag_configure('vuln', foreground=cls.COLORS['accent_red'], font=('Consolas', 10, 'bold'))
        text.tag_configure('banner', foreground=cls.COLORS['text_secondary'])
        
        return text
