# DESYNC HTTP Smuggling Scanner

A high-performance asynchronous security research tool for detecting HTTP request smuggling and desynchronization vulnerabilities (CL.TE / TE.CL / TE.TE techniques), inspired by PortSwigger research.

> This tool is intended for authorized security testing and research only. Do not use it against systems you do not own or have explicit permission to test.

---

## Features

- Detection of HTTP Request Smuggling vectors
- Asynchronous multi-target scanning engine
- Thread-isolated scanner execution per target
- Optional Tor support for anonymized scanning
- Optional crawler for endpoint discovery
- Bulk target scanning via `targets.txt`
- Structured JSON reporting
- PortSwigger-inspired test payload system
- Modular architecture for research extension

---

## Supported Techniques

- TE.CL (Transfer-Encoding vs Content-Length confusion)
- CL.TE
- TE.TE obfuscation variants
- Method confusion tests (GPOST-style cases)
- Header manipulation fuzzing
- Trailing whitespace / tab injection
- Line wrapping payloads

---

## Installation

```bash
git clone https://github.com/eGkritsis/desync-scanner.git
cd desync-scanner

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

## Usage

Single Target Scan
```bash
python desync-scanner.py -u http://target.com
```

Multi-Target Scan
```bash
python desync-scanner.py --targets targets.txt
```

Async High-Speed Mode
```bash
python desync-scanner.py --targets targets.txt --threads 10
```

Crawling Mode
Automatically discover endpoints before scanning:
```bash
python desync-scanner.py -u http://target.com --crawl --depth 3
```

Tor Mode
```bash
python desync-scanner.py -u http://target.onion --tor-port 9050
```

## Architecture
```bash
targets → async engine → isolated scanner workers → results → JSON report
```

