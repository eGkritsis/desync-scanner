# DESYNC-HTTP Scanner - Complete Documentation

PROJECT: Academic HTTP Request Smuggling Detection
STATUS: Production Ready
LICENSE: Research Use Only

## QUICK START

# Single target (local lab)
```bash
python3 desyn-scanner.py -u http://localhost:8080 --no-tor
```

# Single target with Tor
```bash
python3 desyn-scanner.py -u http://target.local
```

# Batch scanning with file
```bash
  python3 desyn-scanner.py --target target.txt
```
# Save results
```bash
python3 desyn-scanner.py -u http://localhost:8080 --no-tor -o results.json
```

## FULL CLI REFERENCE

Required Arguments:
  -u, --url URL                   Target URL (e.g., http://target:8080)

Optional Arguments:
  --no-tor                        Use direct connection instead of Tor
  --tor-host HOST                 Tor SOCKS5 host (default: 127.0.0.1)
  --tor-port PORT                 Tor SOCKS5 port (default: 9050)
  --delay SECONDS                 Delay between requests (default: 1.0)
  --timeout SECONDS               Request timeout (default: 8.0)
  -v, --verbose                   Enable verbose logging
  -o, --output FILE               Save JSON results to file
  -h, --help                      Show help message


## DETECTION TECHNIQUES IMPLEMENTED (v7)

**✓ 1. CL.TE (Content-Length vs Transfer-Encoding)**
    - Basic: Frontend sees CL, Backend sees TE
    - With chunk extensions (0;x=y)
    - Methodology: Send CL too short, expect TIMEOUT on backend
    - Confirmation: Send correct CL, expect 200 OK

**✓ 2. TE.CL (Transfer-Encoding vs Content-Length)**
    - Basic: Frontend sees TE, Backend sees CL
    - Space obfuscation (chunked + space)
    - Tab obfuscation (chunked + tab)
    - Methodology: Add extra data after chunked terminator
    - Confirmation: Correct payload returns 200 OK

**✓ 3. TE.TE (Transfer-Encoding Obfuscation)**
    - Case mutations (transfer-encoding vs Transfer-Encoding)
    - Space before value (TE:  chunked)
    - Identity + chunked combinations
    - Quoted values ("chunked")
    - Methodology: Both parsers see TE but interpret differently
    - Result: Can cause desync when parsers disagree on encoding

**✓ 4. CL.CL (Duplicate Content-Length)**
    - Two Content-Length headers with conflicting values
    - Server picks first vs. last
    - Methodology: Frontend uses value 1, Backend uses value 2
    - Result: Body length mismatch causes desync

**✓ 5. Chunk Size Variants (TERM.EXT, EXT.TERM, ONE.TWO, TWO.ONE)**
    - Line terminator parsing in chunk extensions/bodies
    - Different length calculations
    - Newline vs CRLF handling
    - Methodology: Exploit difference in how parsers count bytes
    - Result: Frontend reads less data than backend expects

**✓ 6. Hidden Headers (Parser Discrepancies)**
    - Space before colon (Content-Length : 0)
    - Line wrapping in headers (Content-Length:\r\n 0)
    - Tab in header names
    - Methodology: Hide headers from one parser but not the other
    - Result: Different content forwarding

**✓ 7. Smuggled Requests (Cache Poisoning)**
    - Inject crafted request into next request's body
    - Detect via response reflection or status codes
    - Methodology: Smuggle admin request
    - Result: Cache/application confusion

**✓ 8. Client-Side Desync (Browser attacks)**
    - Connection state attacks
    - Pause-based desync
    - Methodology: Single request split into two responses
    - Result: Browser handles malformed response

**✓ 9. HTTP/2 Variants**
    - H2.TE: HTTP/2 request with TE header to HTTP/1.1 backend
    - H2.CL: Content-Length confusion in HTTP/2
    - Methodology: Leverage protocol version mismatch


## DETECTION METHODOLOGY

For each technique, scanner performs:

PHASE 1: BASELINE (Connectivity Test)
  → Send normal, well-formed request
  → Expected: 200 OK, quick response
  → If TIMEOUT: Server unresponsive, skip

PHASE 2: ATTACK (Malformed Payload)
  → Send crafted payload designed to cause desync
  → Expected on vulnerable: TIMEOUT (backend waits for data)
  → Expected on safe: 200 OK (both parsers agree)

PHASE 3: CONFIRMATION (Repeat Attack)
  → Re-send attack payload to confirm behavior is consistent
  → Expected on vulnerable: TIMEOUT again
  → Expected on safe: Either 200 OK or connection close

PHASE 4: VALIDATION (Control Test)
  → Send correct, complete payload
  → Expected on all servers: 200 OK
  → Confirms vulnerability is specific to malformed payload


## INTERPRETING RESULTS

CONFIRMED VULNERABILITIES:
  Output shows:
    [!!!] CL.TE-basic DETECTED!
    [!!!] CL.TE-basic confirmed on retry

  What it means:
    - Attack payload caused TIMEOUT
    - Normal payload returned 200 OK
    - Retry confirmed behavior is repeatable
    - Server is vulnerable to request smuggling

  What you can do:
    1. Use Burp Suite HTTP Request Smuggler for exploitation
    2. Test cache poisoning via request reflection
    3. Attempt to access unauthorized resources (/admin)
    4. Document the CDN/WAF/Framework being used

NOT VULNERABLE:
  Output shows:
    [+] CL.TE-basic: Safe

  What it means:
    - Attack payload returned 200 OK (not timeout)
    - Normal payload also returned 200 OK
    - Server treats both as valid
    - Likely uses compatible parsers


## EXAMPLE USAGE

**SCENARIO 1: Local Lab Testing**

```bash
$ python3 desyn-scanner.py -u http://localhost:8080 --no-tor

[*] Direct mode (no Tor)
[*] 
[*] ======================================================================
[*] DESYNC Scanner v7.0 - Production Release
[*] Target: http://localhost:8080
[*] Scan ID: a1b2c3d4e5f6g7h8
[*] IP: 127.0.0.1
[*] ======================================================================
[*] Testing CL.TE variants...
[!!!] CL.TE-basic DETECTED!
[+] CL.TE-basic confirmed on retry
[*] Testing TE.CL variants...
[+] TE.CL-basic: Safe
[+] TE.CL-space: Safe
[+] TE.CL-tab: Safe
...
[===] SCAN COMPLETE - Production Results
[===]
Payloads tested: 45
Techniques checked: 9 major (30+ variants)
Detections: 1
Confirmed: 1
CONFIRMED VULNERABILITIES:
  ★ CL.TE-basic
RISK: CRITICAL
Exploitation recommendations:
  1. Use Burp Suite HTTP Request Smuggler for PoC
  2. Test cache poisoning via request reflection
  3. Attempt to access restricted resources (/admin)
  4. Document affected CDN/WAF/Framework
```

**SCENARIO 2: Tor-Routed Scanning (Authorized)**

```bash
$ python3 desyn-scanner.py -u http://target.local --delay 2.0

[*] Tor connected
[*] Target: http://target.local
[*] IP: 1.2.3.4 (Tor exit node)
(... scan runs with 2-second delay between requests ...)
SCENARIO 3: Batch Scanning with Results
───────────────────────────────────────────────────────────────────────────────
$ for target in $(cat targets.txt); do
    python3 desyn-scanner.py -u "http://$target" --no-tor -o "results_$target.json"
  done
$ ls results_*.json
results_target1.json
results_target2.json
results_target3.json

$ cat results_target1.json
{
  "scan_id": "xyz123",
  "timestamp": "2026-06-05T12:00:00",
  "target": "http://target1:8080",
  "detections": ["CL.TE-basic", "TE.CL-space"],
  "confirmed": ["CL.TE-basic"],
  "payloads_tested": 45
}
```

## PAYLOAD REFERENCE

### CL.TE BASIC:

**Attack (CL too short):**

```bash
  POST / HTTP/1.1\r\n
  Host: target\r\n
  Content-Length: 4\r\n
  Transfer-Encoding: chunked\r\n
  Connection: keep-alive\r\n
  \r\n
  1\r\nZ\r\n0\r\n\r\n
```
**Normal (CL correct):**
```bash
  POST / HTTP/1.1\r\n
  Host: target\r\n
  Content-Length: 11\r\n
  Transfer-Encoding: chunked\r\n
  Connection: keep-alive\r\n
  \r\n
  1\r\nZ\r\n0\r\n\r\n
```

**Why it works:**
  - Frontend (with CL priority) reads first 4 bytes of body: "1\r\nZ"
  - Backend (with TE priority) reads chunked: 1 byte "Z", then final chunk "0"
  - Frontend sends only "1\r\nZ", backend waits for rest of chunked data
  - Timeout occurs because backend is waiting for final chunk marker


### TE.CL BASIC:

```bash 
Attack (CL mismatches):
  POST / HTTP/1.1\r\n
  Host: target\r\n
  Transfer-Encoding: chunked\r\n
  Content-Length: 6\r\n
  Connection: keep-alive\r\n
  \r\n
  0\r\n\r\nX

Normal (CL correct):
  POST / HTTP/1.1\r\n
  Host: target\r\n
  Transfer-Encoding: chunked\r\n
  Content-Length: 5\r\n
  Connection: keep-alive\r\n
  \r\n
  0\r\n\r\n
```

**Why it works:**
  - Frontend (TE priority) reads chunked: "0" = final chunk, stops
  - Backend (CL priority) expects 6 bytes but gets 5
  - Backend waits for 6th byte "X" that was never sent in complete form
  - Timeout occurs on backend



## TROUBLESHOOTING


**ISSUE: "Tor failed, falling back to direct mode"**

CAUSE: Tor service not running or not accessible
FIX:
  $ torctl start        # Start Tor service
  $ netstat -tuln | grep 9050  # Check if listening
  
Or just use --no-tor for local testing


**ISSUE: "Connection died - no client-side desync"**

CAUSE: Server closes connection after attack
MEANING: Server is actively rejecting malformed requests
FIX: Not an issue - server is defending correctly


**ISSUE: All payloads return 200 OK**

CAUSE: Server may use compatible parsers or have mitigations
MEANING: Likely NOT vulnerable
VERIFY: Try with different delay: --delay 0.5 or --delay 2.0


**ISSUE: Random timeout on normal request**

CAUSE: Network instability or server slowness
FIX: Increase timeout: --timeout 15.0
HINT: If only happening on specific payloads, server may be vulnerable



## ADVANCED CONFIGURATION


**FINE-TUNING FOR DIFFERENT TARGETS:**

Slow CDN (Cloudflare, Akamai):
```bash
python3 desyn-scanner.py -u http://target.com --delay 3.0 --timeout 15.0
```

Fast internal network:
```bash
python3 desyn-scanner.py -u http://internal:8080 --no-tor --delay 0.5
```

High-latency (Tor or satellite):
```bash
python3 desyn-scanner.py -u http://target --delay 5.0 --timeout 30.0 --tor-port 9050
```

WAF-protected target:
```bash
python3 desyn-scanner.py -u http://target --delay 2.0 --verbose
```

## LEGAL CONSIDERATIONS

### RISK DISCLAIMER:
  This tool sends crafted HTTP requests that may:
  - Cause temporary unresponsiveness
  - Trigger WAF/IDS alerts
  - Generate security logs
  - Be detected as attack attempts
  
  **Use only in authorized environments with network owner permission.**

