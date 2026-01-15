"""
ShadowScan Security Utilities
Provides input validation, sanitization, and secure API key storage
"""

import re
import base64
import os
from pathlib import Path
from cryptography.fernet import Fernet
import keyring


class SecurityUtils:
    """Security utilities for ShadowScan"""
    
    SERVICE_NAME = "ShadowScan"
    KEY_NAME = "api_encryption_key"
    
    @staticmethod
    def validate_ip(ip_string):
        """Validate IPv4 address"""
        if not ip_string:
            return False
        
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(pattern, ip_string))
    
    @staticmethod
    def validate_ipv6(ip_string):
        """Validate IPv6 address"""
        if not ip_string:
            return False
        
        pattern = r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
        return bool(re.match(pattern, ip_string))
    
    @staticmethod
    def validate_domain(domain):
        """Validate domain name"""
        if not domain or len(domain) > 253:
            return False
        
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    @staticmethod
    def validate_port(port_string):
        """Validate port number"""
        try:
            port = int(port_string)
            return 1 <= port <= 65535
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def sanitize_query(query):
        """Sanitize search query to prevent injection"""
        if not query:
            return ""
        
        # Remove potentially dangerous characters
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\\n', '\\r']
        sanitized = query
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Limit length
        max_length = 1000
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized.strip()
    
    @staticmethod
    def get_encryption_key():
        """Get or create encryption key for API key storage"""
        try:
            # Try to get existing key from keyring
            key_str = keyring.get_password(SecurityUtils.SERVICE_NAME, SecurityUtils.KEY_NAME)
            
            if key_str:
                return key_str.encode()
            
            # Generate new key
            key = Fernet.generate_key()
            keyring.set_password(SecurityUtils.SERVICE_NAME, SecurityUtils.KEY_NAME, key.decode())
            return key
            
        except Exception as e:
            print(f"Keyring error: {e}")
            # Fallback to file-based key (less secure but works)
            return SecurityUtils._get_file_based_key()
    
    @staticmethod
    def _get_file_based_key():
        """Fallback: Get or create file-based encryption key"""
        config_dir = Path.home() / '.shadowscan'
        config_dir.mkdir(exist_ok=True)
        key_file = config_dir / '.key'
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        
        # Generate new key
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        
        # Set restrictive permissions on Unix-like systems
        try:
            os.chmod(key_file, 0o600)
        except:
            pass
        
        return key
    
    @staticmethod
    def encrypt_api_key(api_key):
        """Encrypt API key for secure storage"""
        if not api_key:
            return None
        
        try:
            key = SecurityUtils.get_encryption_key()
            f = Fernet(key)
            encrypted = f.encrypt(api_key.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            print(f"Encryption error: {e}")
            return None
    
    @staticmethod
    def decrypt_api_key(encrypted_key):
        """Decrypt API key from secure storage"""
        if not encrypted_key:
            return None
        
        try:
            key = SecurityUtils.get_encryption_key()
            f = Fernet(key)
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_key.encode())
            decrypted = f.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return None


class InputValidator:
    """Input validation for all user inputs"""
    
    @staticmethod
    def validate_and_clean_ip(ip_input):
        """Validate and clean IP address input"""
        if not ip_input:
            return None, "IP address is required"
        
        ip_clean = ip_input.strip()
        
        if SecurityUtils.validate_ip(ip_clean):
            return ip_clean, None
        elif SecurityUtils.validate_ipv6(ip_clean):
            return ip_clean, None
        else:
            return None, "Invalid IP address format"
    
    @staticmethod
    def validate_and_clean_domain(domain_input):
        """Validate and clean domain input"""
        if not domain_input:
            return None, "Domain is required"
        
        domain_clean = domain_input.strip().lower()
        
        if SecurityUtils.validate_domain(domain_clean):
            return domain_clean, None
        else:
            return None, "Invalid domain format"
    
    @staticmethod
    def validate_and_clean_port(port_input):
        """Validate and clean port input"""
        if not port_input:
            return None, "Port is required"
        
        port_clean = port_input.strip()
        
        if SecurityUtils.validate_port(port_clean):
            return int(port_clean), None
        else:
            return None, "Invalid port (must be 1-65535)"
    
    @staticmethod
    def validate_and_clean_query(query_input):
        """Validate and clean search query"""
        if not query_input:
            return None, "Search query is required"
        
        sanitized = SecurityUtils.sanitize_query(query_input)
        
        if not sanitized:
            return None, "Invalid query after sanitization"
        
        return sanitized, None
