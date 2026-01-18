
Session hijacking - control of valid TCP communication session

Most authentications only occur at the start of TCP session

Valid session ID is stolen to authenticate with the server

Why session hijacking is successful:
- Absence of account lockout or invalid session IDs
- Weak session-ID generation algorithm of small session IDs
- Insecure handling of session IDs
- Indefinite session timeout
- Most computes using TCP/IP are vulnerable
- Most countermeasures do not work without encryption

Session hijacking phases:
- Tracking the connection - sniffer to track victim, Nmap to find easy predictable TCP sequence.
- Desynchronizing connection - must change sequence number SEQ/ACK of the server. Null data is sent. Can send reset flag/
- Injecting attackers packet - inject data into network or participate as MITM.

Packet analysis of local session hijack: needs to know next sequence number (NSN)

Passive session hijacking - only observe and record traffic, capture IDs and passwords.

Active session hijacking - takes active session by breaking the connection or by actively participating. Example is MITM - guess sequence number before target responds to server. On most sequence number guessing doesnt work cause they are generated at random.

Spoofing - pretend to be another user or machine. Initiates new session using stolen credentials
Hijacking - seizing control of existing active session, relies on user making the connection first


Application level Hijacking
--------------------------------------

- Stealing - different techniques to steal session IDs
- Guessing - try to guess session ID by observing session variables
- Brute forcing - all possible permutations of session ID

Session sniffing: header of HTTP requisition (cookie) or body of HTTP requisition

Predicting session token:
- sequential tokens
- Timestamp based tokens
- small token space 01-55 etc
- Weak random number generators PRNG, lack of rate limiting

Using MITM - split TCP connection into two connections:
- client to attacker
- attacker to server
- attacker can modify and insert into intercepted communication
- in case of http transaction the TCP connection becomes the target

Man in the browser/Manipulator in the browser
1. trojan infects computers software
2. trojan installs malicious code
3. after browser restart code loads
4. handler is registered for every visit to a webpage
5. when page is loaded extension matches URL with knows sites targeted for this attack
6. User logs into site
7. extension registers event handler
8. extension extracts DOM field values and modifies them
9. browser sends values to server
10. server receives values 
11. receipt is granted
12. browser receives receipt for modified transaction
13. browser displays receipt with original details
14. user doesnt know anything

Compromising session ID using Client side attacks
----------------------------------------------------------------------

Cross site scripting (XSS) - session token compromise using malicious code or programs. ##`<SCRIPT>alert (document.cookie);</`SCRIPT`>` , executes in victims browser, webapp does not properly sanitize input, 

Malicious JS codes

Trojans

Cross site request forgery - one click session riding.  Exploits trust in users session. User is already authenticated, browser automatically includes cookies/session tokens, apllication does not verify request origin. Needs anti-csrf tokens

Session replay attacks - listens to conversation between user and server and captures authentication token. Then replays request to the server with captured authentication token.

Compromising session id's using fixation - attacker fixes the session ID in advance. Gets session id, user opens link and enters creds, thus validating session

Session hijacking using proxy servers - uses proxy server as site, then replays token

Session hijacking using CRIME attack - Compression ratio Leak made easy, client side attack that exploits vulnerabilities in data-compression of SSL/TLS, SPDY and HTTPS

Session hijacking using forbidden attack - MITM, exploits reuse of cryptographic nonce, during TLS handshake. After hijacking HTTP session attackers inject malicious code and forged content. AES-GCM

Session donation attack - attacker logs in, victim clicks link then attacker can login and get victims info

Memorization:
CODE      → XSS, Malicious JS
TRUST     → CSRF, Session Donation
REUSE     → Replay, Fixation
NETWORK   → Proxy, CRIME
CRYPTO    → FREAK / Forbidden

| Attack                                | Core Idea (1-liner)                   | How It Works                                                              | Key Requirement            | CEH Exam Keyword                      | Prevention                                          |
| ------------------------------------- | ------------------------------------- | ------------------------------------------------------------------------- | -------------------------- | ------------------------------------- | --------------------------------------------------- |
| **Cross-Site Scripting (XSS)**        | Inject JS to steal session cookies    | Malicious script executes in victim’s browser and reads `document.cookie` | Poor input sanitization    | **Client-side code execution**        | Input validation, output encoding, HttpOnly cookies |
| **Malicious JavaScript**              | JS payload steals or forwards tokens  | JS captures session ID and sends it to attacker                           | Script injection vector    | **Session token exfiltration**        | CSP, sanitization, HttpOnly                         |
| **Trojan**                            | Malware steals session data           | Trojan reads browser memory or cookies                                    | Victim system infected     | **Client compromise**                 | AV, endpoint security                               |
| **Cross-Site Request Forgery (CSRF)** | Abuse authenticated session           | Victim clicks link → browser sends valid cookies automatically            | User already logged in     | **One-click attack / Session riding** | Anti-CSRF tokens, SameSite cookies                  |
| **Session Replay Attack**             | Capture & reuse auth token            | Attacker sniffs traffic and replays captured request                      | Token reuse allowed        | **Replay authentication**             | TLS, nonce, token expiration                        |
| **Session Fixation**                  | Attacker sets session ID in advance   | Victim logs in using attacker-known session ID                            | Session ID not regenerated | **Pre-authentication session ID**     | Regenerate session ID after login                   |
| **Proxy-based Session Hijacking**     | Steal session via fake proxy          | Victim connects through attacker-controlled proxy                         | User trusts proxy          | **Man-in-the-Browser**                | HTTPS, certificate validation                       |
| **CRIME Attack**                      | Leak secrets via compression          | Exploits TLS/HTTP compression ratio to infer cookies                      | TLS compression enabled    | **Compression side-channel**          | Disable TLS compression                             |
| **FREAK / Forbidden Attack**          | Break TLS crypto                      | MITM forces weak crypto or nonce reuse (AES-GCM)                          | Weak TLS config            | **TLS downgrade / nonce reuse**       | Strong ciphers, TLS hardening                       |
| Session Donation Attack               | Victim authenticates attacker session | Attacker logs in → victim clicks link → attacker gains access             | Shared or reused session   | **Session misbinding**                | Bind session to user/IP/device                      |


Network level session hijacking
--------------------------------------------
**Exploits vulnerabilities in three way handshake**

**TCP/IP Hijacking**:
- sniff victim connection and send spoofed packet with predicted packet number
- receiver processes packet and increments sequence number
- victims machine ignores ack packet and off sequence number count
- receiver receives packets with incorrect sequence number
- attacker forces victims connection with machine into desynchronized state
- tracks sequence numbers and continiously spoofs packets that originate from victims ip address
- attacker communicates while victims connection hangs

**IP Spoofing: Source routed packets**:
1. gaining access with help of trusted hosts IP
2. Attacker spoofs IP so that the server managing session accepts packets from attacker
3. attacker injects forged packets before host responds to server
4. original packet is lost and server receives packet with sequence number already used by the attacker
5. packets are source-routed with destination IP specified by attacker

**RST Hijacking:**
- Injecting authentic-looking reset RST packet using spoofed source address
- attacker can reset victims connection if he uses accurate acknowledgement number
- victim would believe that source sent packer and would reset the connection
- RST hijacking could be done using packet crafting tool llike Colasoft packet builder tool and tcpdump

**Blind hijacking**:
- attacker can inject malicious data or commands in TCP session even if source-routing is disabled
- attacker can send data but has no access to see the response

**UDP Hijacking**:
- attacker sends forged server reply to victims UDP request
- then uses MITM to intercept servers response

**MiTM using forged ICMP**:
- ICMP packets are forged to redirect traffic between client and host trough hijackers host, packets send error messages, this fools server into routing trough attacker.

**ARP spoofing**:
- Broadcasting ARP request and changing its ARP tables by sending forged replies.

**PetitPotam hijacking**:
- Domain controller is forced to initiate authentication to attackers server
- attacker uses MS encrypting file system remote protocol (MS-EFSRPC) API for authentication session hijacking
- attacker relays NTLM authentication shared by domain controller to AD certificate services to get admin privileges

TCP Sequence Abuse → TCP/IP Hijacking, Blind Hijacking, RST Hijacking
Trust Abuse        → IP Spoofing, PetitPotam
Stateless Abuse    → UDP Hijacking
Routing Abuse      → ICMP Forgery
LAN Poisoning      → ARP Spoofing


| Attack | Core Idea (1-liner) | How the Attack Works (Condensed Flow) | Key Requirement | CEH Exam Keywords |
|------|------------------|---------------------------------------|----------------|------------------|
| **TCP/IP Hijacking** | Take over an active TCP session by desynchronizing sequence numbers | Sniffs connection → sends spoofed packet with predicted seq → receiver increments seq → victim ignores ACK → connection desync → attacker keeps spoofing packets as victim | Ability to sniff or predict TCP sequence numbers | Sequence number prediction, desynchronization |
| **IP Spoofing (Source Routing)** | Impersonate trusted host using spoofed IP | Attacker spoofs trusted IP → injects forged packets before real host responds → server accepts attacker packets → source-routed packets control path | Source routing enabled + trusted IP | Trusted host abuse, source routing |
| **RST Hijacking** | Forcibly terminate a TCP session | Attacker injects spoofed TCP packet with RST flag + valid ACK → victim believes peer reset connection → session drops | Accurate sequence/ACK number | TCP RST flag, forced reset |
| **Blind Hijacking** | Inject data without seeing responses | Attacker cannot sniff traffic → predicts sequence numbers → injects data → cannot see replies | Predictable sequence numbers | Blind injection, no sniffing |
| **UDP Hijacking** | Inject or replace UDP communication | Attacker sends forged UDP reply → races or MITMs real server response → victim accepts fake data | Stateless UDP communication | Packet spoofing, connectionless |
| **MITM using Forged ICMP** | Redirect traffic using fake ICMP errors | Attacker forges ICMP error messages → client/server reroute traffic through attacker → MITM achieved | Trust in ICMP routing messages | ICMP redirect, traffic rerouting |
| **ARP Spoofing** | Poison ARP cache to intercept traffic | Attacker sends forged ARP replies → victims update ARP tables → traffic routed to attacker | Local network access | ARP poisoning, MAC spoofing |
| **PetitPotam Hijacking** | Force DC authentication and relay it | Attacker abuses MS-EFSRPC → forces DC to authenticate → relays NTLM auth to AD CS → gains admin privileges | NTLM enabled + AD CS | Authentication coercion, NTLM relay |



**Session hijacking tools:**
- Hetty - MITM proxy, HTTP client for manually creating requests and replaying proxied requests
- Caido - security auditing toolkit
- bettercap - written in GO

**Session hijack detection tools:**
- USM Anywhere
- Wireshark


**Preventing session hijacking:**
- HTTP strict transport security (HSTS)
- Token Binding 
- Tools: Checkmarx one SAST, Fiddler, 

**Prevent MITM:**
- DNS over HTTPS (DoH)
- WPA3
- VPN
- 2FA
- PW manager
- Zero-trust
- PKI
- Network segmentation

**IPsec**
Modes:
- transport - encrypts only payload of IP packet
- tunnel mode - IPsec encapsulates entire IP packet