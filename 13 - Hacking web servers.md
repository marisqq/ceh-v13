

Apache
---------------
Apache = middleman
1. Accepts requests from users.
2. Applies rules and security logic
3. Servers content itself or forwards requests
If request static Apache servers itself, if dynamic sends request to application server
mod_ssl - enables SSL/TLS encryption
mod_auth - controls authentication and authorization
mod_rewrite - rewrite url's dynamically
mod_proxy - allows to act as proxy or gateway forwarding requests to other servers.

Apache dangerous if modules are misconfigued

BMMTM Extensible agent - monitor and collect transaction data

Application server - runs backend code

Apache vulnerabilities:
HTTP response splitting - Apache improperly validates input
SQL injection in apache components - improperly neutralize SQL elements
Code injection/ env variable injection - mainpulate code or variables
Memory exhaustion - DoS HTTP/2, memory exhaustion trough endless continuation frames

HTTP response splitting - improper input validation that allows to inject malicious headers

IIS Web server architecture:
-------------------------------------------------------
Internet information services IIS, MS web server platform

Supported protocols:
HTTP/HTTPS
FTP/FTPS
SNMP
NNTP

How it works:
1. Client sends request
2. HTTP.sys - kernel mode driver, listens for requests
3. Windows activation service (WAS) - reads config data, decides which app pool should handle request. Starts worker process if they are not already running
WAS reads ApplicationHost.config which is main ISS config file
4. WWW service - uses config info. web publishing service
5. Worker process w3wp.exe - runs in user mode, requests are processed, authentication happens, application codeis executed, logs are written, response is generated.
6. Response goes back

HTTP.sys handles traffic in kernel mode
w3wp.exe handlesexecution in user mode
WAS coordinates everything using config files

Vulnerabilities:
- Authentication & authorization failures
- Trust boundary violation - fails to properly separate privilege levels
- File and directory access problems
- Privilege escalation - IIS improperly handles user requests, total compromise
- input handling and injection issues - XSS CRLF
- TYPO3 XSS - PATH_INFO, unfiltered env variables
- XSS in password manager - when user controllable input is improperly neutralized allowing script injection
- Credential exposure - CCURE if IIS logs sensitive creds improperly
- Mail-related vulnerability - mail users upload files in public directories leading to code execution, Auxillary services+ poor sanitation = RCE

Nginx
------------
High performance web server, reverse proxy and load balancer
Uses single-threaded, event-driven, non blocking I/O
- extremely fast
- memory efficient
- popular for high traffic environments

Process:
1. Client connects - single thread, keeps connections open using event loop
2. Worker processes - single threaded, non blocking I/O, can handle thousands of connections
3. Request handling path - one worker accepts it
4. Backend interaction  - HTTP, FastCGI , PHP-FPM, memcatche
5. Response+catching - sends response to client, stores response in proxy cache
Other components:
- web server - HTTP requests, static content, routes dynamic requests
- Application server - processes server side scripts and generates dynamic content
- memcache - key-value store 

Dangers of Nginx:
- config errors affect all workers
- exposed admin interfaces are dangerous
- catching can leak sensitive data
- event-driven model amplifies DoS impact

Vulnerabilities:
- Memory and protocol handling issues - NULL pointer dereferance in HTTP/3 
- server-side request forgery - SSRF, manipulate backend handling
- RCE and command injection - misconfigured Nginx-UI settings
- Cryptography & certificate handling - improper certificate validation
- Injection vulnerabilities - SQL injection, XSS
- Access control failures - unauthenticated private keys access, default file permissions. Nginx does not support .httacess


DNS server hijacking
------------------------------------------

Attacker compromises DNS server and changes DNS mapping settings.
1. Attack compromises target DNS server and modifies DNS config settings
2. User attempts to access legitimate website by entering correct URL
3. request sent to compromised server
4. redirects user to malicious website

Key characteristics:
- attacki s done to DNS server config, not user side
- redirect happens before HTTP communication begins
- users are unaware because URL appears to belegit

DNS amplicifactio nattack
-----------------------------------------------------
DDoS that exploits recursive DNS queries

Generating large DNS responses using small spoofed requests

uses IP spoofing
exploits recursive behaviour
small request -> large response
result is DNS service unavailability

usually UDP (stateless)

Directory traversal attacks
-----------------------------------------------------
Attacker exploits improper input validation

usually ../
Server resolves manipulated path outside web root directory

targets file system structure


Web server misconfiguration
------------------------------------------------------------

Configuration weakness in web infrastructure
Common issues:
- verbose debug or error messages
- default creds
- sample configs and script
- remote admin functions
- unnecessary services enabled
- SSL problems

<Location "/server-status">
  SetHandler server-status
  Require host example.com
</Location>

Verbose php messages
display_error = On
log_errors = On
error_log = syslog
ignore_repeated_errors = Off

directory browsing in IIS

HTTP response splitting attack
---------------------------------------------------------------

web based attack where input fields are manipulated to inject new line characters into HTTP response headers
 Exploits improper input validation - cross site scripting (XSS) cross site request forgery (CSRF) SQL injection

Requires CRLF injection
happens at HTTP header level
Enables catche poisoning and XSS
Browser discards extra responses

WEB cache poisoning attack
---
targets integrity and reliability of intermediate web cache

users unknowingly receive poisoned content

Exploits HTTP response splitting flaws
affects multiple users
persistent until cache expiration

Affects catched content

SSH brute force
-------------------------------

TCP 22

nmap - identify
Ncrack - for ssh brute
THX Hydra - common 

precede lateral movement

HTTP/2 continuation flood attack
-----------------------

DoS exploits handling of HTTP/2 continuation frames

HTTP/2 large headers are split into:
- one headers frame
- multiple continuation frames
Server expects when END_HEADERS flag is set, but in this attack its never set

impact:
memory exhaustion
cpu exhaustion
DoS

Frontjacking 
------
attacker injects or manipulates front end components of web application to hijack user interactions

Targets misconfigured Nginx reverse poxy servers

CRLF injection
HTTP request header injection
XSS

improper sanitization $uri and $document_uri

