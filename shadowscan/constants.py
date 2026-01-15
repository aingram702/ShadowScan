"""
ShadowScan Constants and Configuration
"""

# Application Info
APP_NAME = "ShadowScan"
APP_VERSION = "1.0.0"
APP_TITLE = "ShadowScan - Shodan Intelligence Platform"

# ASCII Banner
BANNER = """
███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""

MINI_BANNER = "◢◤ SHADOWSCAN v1.0 ◢◤"

# Color Scheme
COLORS = {
    'bg_darkest': '#050505',
    'bg_dark': '#0a0a0a',
    'bg_medium': '#1a1a1a',
    'bg_light': '#2a2a2a',
    'bg_lighter': '#3a3a3a',
    'accent_green': '#00ff41',
    'accent_green_dark': '#00cc33',
    'accent_green_dim': '#00aa22',
    'accent_red': '#ff0040',
    'accent_red_dark': '#cc0033',
    'accent_cyan': '#00ffff',
    'accent_cyan_dark': '#00cccc',
    'accent_yellow': '#ffff00',
    'accent_orange': '#ff8c00',
    'accent_purple': '#ff00ff',
    'text_primary': '#00ff41',
    'text_secondary': '#808080',
    'text_dim': '#505050',
    'text_white': '#ffffff',
    'text_bright': '#e0e0e0',
    'entry_bg': '#0f0f0f',
    'border': '#333333',
    'success': '#00ff41',
    'warning': '#ffff00',
    'error': '#ff0040',
    'info': '#00ffff',
}

# Quick Filters for Search
QUICK_FILTERS = [
    "-- Select Filter --",
    "───── DATABASES ─────",
    "product:mysql",
    "product:mongodb",
    "product:postgresql",
    "product:redis",
    "product:elasticsearch",
    "product:memcached",
    "product:couchdb",
    "product:cassandra",
    "product:mariadb",
    "product:oracle",
    "product:mssql",
    "───── WEB SERVERS ─────",
    "product:apache",
    "product:nginx",
    "product:iis",
    "product:tomcat",
    "product:lighttpd",
    "product:caddy",
    "product:litespeed",
    "───── NETWORK DEVICES ─────",
    "cisco",
    "mikrotik",
    "netgear",
    "fortinet",
    "paloalto",
    "juniper",
    "ubiquiti",
    "sonicwall",
    "watchguard",
    "───── INDUSTRIAL/SCADA ─────",
    "port:502 modbus",
    "port:102 s7",
    "port:44818 ethernet/ip",
    "port:47808 bacnet",
    "port:20000 dnp3",
    "port:1911 niagara",
    "\"Siemens\"",
    "\"Schneider\"",
    "\"Allen-Bradley\"",
    "───── CAMERAS/IOT ─────",
    "webcam",
    "netcam",
    "hikvision",
    "dahua",
    "\"axis camera\"",
    "\"IP Camera\"",
    "\"network camera\"",
    "\"DVRDVS\"",
    "───── REMOTE ACCESS ─────",
    "port:3389 rdp",
    "port:22 ssh",
    "port:23 telnet",
    "port:5900 vnc",
    "port:5985 winrm",
    "port:5986 winrm",
    "\"Remote Desktop\"",
    "───── VULNERABILITIES ─────",
    "vuln:CVE-2021-44228",
    "vuln:CVE-2021-26855",
    "vuln:CVE-2020-1472",
    "vuln:CVE-2019-0708",
    "vuln:CVE-2017-0144",
    "vuln:CVE-2014-0160",
    "vuln:CVE-2021-34473",
    "───── MISCONFIGURED ─────",
    "\"default password\"",
    "\"authentication disabled\"",
    "\"anonymous access\"",
    "http.title:\"Index of /\"",
    "http.title:\"Dashboard\"",
    "http.title:\"phpMyAdmin\"",
    "http.title:\"admin\"",
    "http.title:\"login\"",
    "───── CLOUD SERVICES ─────",
    "org:\"Amazon\"",
    "org:\"Microsoft Azure\"",
    "org:\"Google Cloud\"",
    "org:\"DigitalOcean\"",
    "org:\"Linode\"",
]

# Country Codes
COUNTRY_CODES = [
    "",  # Empty for no filter
    "US", "GB", "DE", "FR", "CN", "RU", "JP", "KR", "BR", "IN",
    "AU", "CA", "IT", "ES", "NL", "SE", "CH", "PL", "UA", "TR",
    "MX", "ID", "TH", "VN", "PH", "MY", "SG", "HK", "TW", "ZA",
    "NG", "EG", "AE", "SA", "IL", "AR", "CL", "CO", "PE", "NZ",
    "IE", "BE", "AT", "NO", "DK", "FI", "CZ", "RO", "HU", "GR",
    "PT", "PK", "BD", "IR", "IQ", "KZ", "UZ", "BY", "LT", "LV",
]

# Common Ports
COMMON_PORTS = [
    "", "21", "22", "23", "25", "53", "80", "110", "143", "443",
    "445", "993", "995", "1433", "1521", "3306", "3389", "5432",
    "5900", "6379", "8080", "8443", "9200", "27017", "502", "102",
]

# Protocol Searches
PROTOCOL_SEARCHES = {
    "HTTP": "port:80,8080,8000,8888",
    "HTTPS": "port:443,8443,4443",
    "SSH": "port:22 ssh",
    "FTP": "port:21 ftp",
    "FTPS": "port:990 ftps",
    "Telnet": "port:23 telnet",
    "SMTP": "port:25,465,587 smtp",
    "POP3": "port:110,995",
    "IMAP": "port:143,993",
    "DNS": "port:53 dns",
    "RDP": "port:3389 rdp",
    "VNC": "port:5900,5901,5902 vnc",
    "SMB": "port:445,139 smb",
    "MySQL": "port:3306 mysql",
    "PostgreSQL": "port:5432 postgresql",
    "MSSQL": "port:1433 mssql",
    "Oracle": "port:1521 oracle",
    "MongoDB": "port:27017 mongodb",
    "Redis": "port:6379 redis",
    "Elasticsearch": "port:9200,9300 elasticsearch",
    "Memcached": "port:11211 memcached",
    "CouchDB": "port:5984 couchdb",
    "Cassandra": "port:9042 cassandra",
    "LDAP": "port:389,636 ldap",
    "Kerberos": "port:88 kerberos",
    "NTP": "port:123 ntp",
    "SNMP": "port:161,162 snmp",
    "RTSP": "port:554 rtsp",
    "SIP": "port:5060,5061 sip",
    "Modbus": "port:502 modbus",
    "BACnet": "port:47808 bacnet",
    "DNP3": "port:20000 dnp3",
    "S7": "port:102 s7",
    "EtherNet/IP": "port:44818",
    "MQTT": "port:1883,8883 mqtt",
    "CoAP": "port:5683 coap",
    "Docker": "port:2375,2376 docker",
    "Kubernetes": "port:6443,10250 kubernetes",
    "Jenkins": "port:8080 jenkins",
    "Grafana": "port:3000 grafana",
    "Kibana": "port:5601 kibana",
}

# Search Help Text
SEARCH_HELP = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                         SHODAN SEARCH SYNTAX GUIDE                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  BASIC FILTERS:                                                              ║
║  ─────────────────────────────────────────────────────────────────────────── ║
║  hostname:example.com     Search by hostname                                 ║
║  ip:1.2.3.4               Search by IP address                               ║
║  net:192.168.0.0/24       Search by CIDR block                               ║
║  port:22                  Search by port number                              ║
║  os:"Windows 10"          Search by operating system                         ║
║  country:US               Filter by country code                             ║
║  city:"New York"          Filter by city name                                ║
║  org:"Google"             Filter by organization                             ║
║  asn:AS15169              Filter by ASN                                      ║
║  isp:"Comcast"            Filter by ISP                                      ║
║                                                                              ║
║  PRODUCT/SERVICE FILTERS:                                                    ║
║  ─────────────────────────────────────────────────────────────────────────── ║
║  product:nginx            Search by product name                             ║
║  version:1.0              Search by version                                  ║
║  http.title:"Dashboard"   Search by HTTP title                               ║
║  http.status:200          Search by HTTP status code                         ║
║  http.html:"login"        Search by HTML content                             ║
║  ssl:"Let's Encrypt"      Search by SSL certificate                          ║
║  ssl.cert.subject.cn:*    Search by certificate CN                           ║
║                                                                              ║
║  VULNERABILITY FILTERS:                                                      ║
║  ─────────────────────────────────────────────────────────────────────────── ║
║  vuln:CVE-2021-44228      Search for specific CVE                            ║
║  has_vuln:true            Find hosts with any vulnerability                  ║
║                                                                              ║
║  SPECIAL FILTERS:                                                            ║
║  ─────────────────────────────────────────────────────────────────────────── ║
║  before:01/01/2023        Results before date                                ║
║  after:01/01/2023         Results after date                                 ║
║  has_screenshot:true      Has screenshot                                     ║
║  has_ssl:true             Has SSL certificate                                ║
║                                                                              ║
║  BOOLEAN OPERATORS:                                                          ║
║  ─────────────────────────────────────────────────────────────────────────── ║
║  apache nginx             AND (implicit)                                     ║
║  apache OR nginx          OR operator                                        ║
║  apache -nginx            NOT operator                                       ║
║  "exact phrase"           Exact phrase match                                 ║
║                                                                              ║
║  EXAMPLES:                                                                   ║
║  ─────────────────────────────────────────────────────────────────────────── ║
║  apache country:US port:80                                                   ║
║  product:mysql has_vuln:true                                                 ║
║  http.title:"Index of /" country:DE                                          ║
║  webcam has_screenshot:true                                                  ║
║  ssl.cert.expired:true org:"Amazon"                                          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# Honeypot Score Interpretation
HONEYPOT_SCORES = {
    (0.0, 0.2): ("Very Low", "accent_green", "Likely legitimate system"),
    (0.2, 0.4): ("Low", "accent_green_dim", "Probably legitimate"),
    (0.4, 0.6): ("Medium", "accent_yellow", "Inconclusive - use caution"),
    (0.6, 0.8): ("High", "accent_orange", "Likely a honeypot"),
    (0.8, 1.0): ("Very High", "accent_red", "Almost certainly a honeypot"),
}

# File Export Formats
EXPORT_FORMATS = {
    'JSON': '.json',
    'CSV': '.csv',
    'TXT': '.txt',
    'HTML': '.html',
}
