"""
ShadowScan Utility Functions
"""

import re
import json
import csv
import os
from datetime import datetime
from pathlib import Path


def is_valid_ip(ip_string):
    """Validate IPv4 address"""
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, ip_string))


def is_valid_ipv6(ip_string):
    """Validate IPv6 address"""
    pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    return bool(re.match(pattern, ip_string))


def is_valid_domain(domain):
    """Validate domain name"""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def is_valid_cidr(cidr):
    """Validate CIDR notation"""
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:3[0-2]|[12]?[0-9])$'
    return bool(re.match(pattern, cidr))


def format_timestamp(timestamp_str):
    """Format timestamp string"""
    try:
        if isinstance(timestamp_str, datetime):
            return timestamp_str.strftime('%Y-%m-%d %H:%M:%S')
        
        # Try parsing various formats
        formats = [
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d',
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                continue
        
        return str(timestamp_str)
    except:
        return str(timestamp_str)


def get_honeypot_score_color(score):
    """Get color based on honeypot score"""
    from shadowscan.constants import COLORS
    
    if score < 0.2:
        return COLORS['accent_green']
    elif score < 0.4:
        return COLORS['accent_green_dim']
    elif score < 0.6:
        return COLORS['accent_yellow']
    elif score < 0.8:
        return COLORS['accent_orange']
    else:
        return COLORS['accent_red']


def get_honeypot_rating(score):
    """Get honeypot rating text"""
    if score < 0.2:
        return "Very Low", "Likely legitimate system"
    elif score < 0.4:
        return "Low", "Probably legitimate"
    elif score < 0.6:
        return "Medium", "Inconclusive - exercise caution"
    elif score < 0.8:
        return "High", "Likely a honeypot"
    else:
        return "Very High", "Almost certainly a honeypot"


def build_search_query(base_query, country=None, city=None, port=None, 
                       org=None, product=None, version=None, os_filter=None):
    """Build Shodan search query with filters"""
    query_parts = [base_query] if base_query else []
    
    if country:
        query_parts.append(f'country:{country}')
    if city:
        query_parts.append(f'city:"{city}"')
    if port:
        query_parts.append(f'port:{port}')
    if org:
        query_parts.append(f'org:"{org}"')
    if product:
        query_parts.append(f'product:{product}')
    if version:
        query_parts.append(f'version:{version}')
    if os_filter:
        query_parts.append(f'os:"{os_filter}"')
    
    return ' '.join(query_parts)


def extract_cves(host_data):
    """Extract CVEs from host data"""
    cves = set()
    
    # Check vulns field
    if 'vulns' in host_data:
        cves.update(host_data['vulns'])
    
    # Check service data
    for service in host_data.get('data', []):
        if 'vulns' in service:
            cves.update(service['vulns'].keys() if isinstance(service['vulns'], dict) else service['vulns'])
    
    return sorted(list(cves))


def parse_banner(banner_text, max_length=500):
    """Parse and truncate banner text"""
    if not banner_text:
        return ""
    
    # Clean up banner
    banner = banner_text.strip()
    
    # Truncate if too long
    if len(banner) > max_length:
        banner = banner[:max_length] + "\n... [truncated]"
    
    return banner


def export_to_json(data, filepath):
    """Export data to JSON file"""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        return True, f"Exported to {filepath}"
    except Exception as e:
        return False, f"Export failed: {str(e)}"


def export_to_csv(data, filepath, fieldnames=None):
    """Export data to CSV file"""
    try:
        if not data:
            return False, "No data to export"
        
        # Determine fieldnames from first item if not provided
        if not fieldnames:
            if isinstance(data[0], dict):
                fieldnames = list(data[0].keys())
            else:
                return False, "Cannot determine CSV columns"
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            
            for item in data:
                if isinstance(item, dict):
                    writer.writerow(item)
        
        return True, f"Exported to {filepath}"
    except Exception as e:
        return False, f"Export failed: {str(e)}"


def export_to_txt(data, filepath):
    """Export data to text file"""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            if isinstance(data, str):
                f.write(data)
            elif isinstance(data, list):
                for item in data:
                    f.write(str(item) + '\n')
            elif isinstance(data, dict):
                f.write(json.dumps(data, indent=2, default=str))
            else:
                f.write(str(data))
        return True, f"Exported to {filepath}"
    except Exception as e:
        return False, f"Export failed: {str(e)}"


def get_config_dir():
    """Get configuration directory"""
    config_dir = Path.home() / '.shadowscan'
    config_dir.mkdir(exist_ok=True)
    return config_dir


def save_config(config_data):
    """Save configuration to file"""
    try:
        config_file = get_config_dir() / 'config.json'
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=2)
        return True
    except:
        return False


def load_config():
    """Load configuration from file"""
    try:
        config_file = get_config_dir() / 'config.json'
        if config_file.exists():
            with open(config_file, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}


def format_ports(ports_list):
    """Format list of ports for display"""
    if not ports_list:
        return "None"
    return ', '.join(map(str, sorted(ports_list)))


def format_bytes(size_bytes):
    """Format bytes to human readable string"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def sanitize_filename(filename):
    """Sanitize filename for safe saving"""
    # Remove invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename


def generate_report_header(title="ShadowScan Report"):
    """Generate report header"""
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return f"""
{'=' * 80}
{title.center(80)}
{'=' * 80}
Generated: {now}
{'=' * 80}

"""


def format_host_summary(host_data):
    """Format host data for summary display"""
    summary = []
    
    summary.append(f"IP: {host_data.get('ip_str', 'N/A')}")
    summary.append(f"Org: {host_data.get('org', 'N/A')}")
    
    location = host_data.get('location', {})
    if location:
        summary.append(f"Location: {location.get('city', 'N/A')}, {location.get('country_name', 'N/A')}")
    
    ports = host_data.get('ports', [])
    if ports:
        summary.append(f"Ports: {format_ports(ports)}")
    
    vulns = host_data.get('vulns', [])
    if vulns:
        summary.append(f"Vulnerabilities: {len(vulns)}")
    
    return '\n'.join(summary)
