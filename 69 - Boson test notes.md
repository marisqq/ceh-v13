 
IntentFuzzer - targets android inter-process communication (IPC)

URLFuzzer - uses fuzzing to seek hidden files

Robotioum - open-source test automation framework

Flowmon - company that prowides network based monitoring solutions

Scareware - a popup, social engineering

Spimming - instant messaging

HMI based attack - human machine interface attack, hmi is monitor, touchscreen, usually in OT environments

--
**Cloud consumer** - uses services of cloud provider
Cloud provider - offer SaaS, deploy, configure maintain software applications for cloud consumer.
Cloud carrier - provides connectivity and transport of cloud services between cloud consumers and cloud providers.
Cloud broker - negotiates relationships between providers and consumers
Cloud auditor - independent assessment of cloud provider


--
SMTP connection initiation: EHL0 (servers that support EHLO, if doen not support it will be HELO)

RCPT TO - indicate sender

VRFY - to verify existence of mailbox

EXPN - request request recipients of mailing list

--
SQL injection - spacing to avoid IDS or WAF
spacing - SELECT * FROM 'mydb'.'users' 'WHERE' role='1'

normal - SELECT * FROM users WHERE role='1';

--
WEP - OLd and broken, uses RC4, replaced by WPA, attacks: IV reuse, Aircrack-ng, replay, chop-chop.

WPA- created to replase WEP, adds TKIP, still weak

WPA2 - uses AES-CCMP, 4 way handshake, most widely deployed. attacks: KRACK, PSK when weak passwords

WPA3 - uses SAE Dragonfly handshake, harder to brute force. Attacks: dragonblood

|Standard|Cipher / Handshake|Notes|
|---|---|---|
|**WEP**|RC4 + 24-bit IV|Totally broken|
|**WPA**|RC4 + TKIP|Patch, still weak|
|**WPA2**|AES-CCMP + 4-way|Strong, widely used|
|**WPA3**|**SAE / Dragonfly**|Dragonblood vuln|

KRACK - exploits WPA2 4-way handshake

--
DROWN attack - disable SSLv2
SSLv2 - extremely broken, should use TLS 1.2 or 1.3

--
Mimikatz to steal kerberos TGT - pass the ticket

--
To hijack session for mailserver with IP for authentication - canceling connection as soon as response received to get Initial serquence number (ISN) 

--
Blowfish- symetric 64-block cypher 32-448bits

standard is IDEA 64-block cypher with 128-bit key. Used by PGP

--

![[Pasted image 20251231090133.png]]

--

Maimon scan - FIN/ACK probes are sent nmap -sM

FIN scan - if discarded by TCP port open, if RST sent closed nmap -sF

XMAs - sends FIN, PSH and URG

ACK scan - determines if port is filtered or unfiltered -sA

--

Cross site scripting (XSS) - mittigated by setting HttpOnly flag in cookies. Occurs when attacker tries injecting code into webpage to harvest session cookies.

Cross site request forgery (CSRF) - sends unintended authenticated requests

server side request forgery - make application to get sending request to other domains

--
APT (Advanced persistent threat)
1. Preperation - identify and research
2. Initial intrusion - infiltrate target enviroment, deploys malware
3. expansion - attempts to expand access, obtain administrative access
4. Persistence - create additional footholds, creates C2
5. Cleanup - evading detection, removing evidence

--

side-channel attack - attempt to break encryption by monitoring something external to the algorithm

--

Tactical threat intelligence - TOOLs, Techniques and procedures (TTP's) + vulnerabilities

Strategic threat intelligence - overview of threat landscape, not very technical

Technical threat intelligence - clues of attack, indicators of compromise (IOC's), malware sapmles, phising samples, URLS etc.

Operational threat intelligance - gathers information from online discussions, social media, chat rooms etc.

--

In ACK scan if port is unfiltered you get RST, nmap -sA, if filtered you get no reply.

--

Emotet malware modules (banking trojan):

NetPass.exe - use legitimate tool to retrieve all passwords (nirsoft)
OutlookScraper - collects contact information from victims outlook
MailPassView - collects passwords and account information from MS outlook, Firefox, gnmail etc.
Credential enumerator - packaged in RAR, brute forces SMB (can use WebBrowserPassView to pass the information)


--

to find btlejack connection - btlejack -s

--

Zoominfo - get info about companies ceos, ctos etc.

--

semi-unthethered jailbreak - sideloaded app can jailbreak it even after reboot

--


slowloris attack - DDoS, opens many HTTPS connections

--

TCP ACK ping nmap -sn -PA - to detect active devices behind firewall

--

PaaS - platform as a service

--

Zombie attack - nmap -sI

--

FREAK, POODLE, WPA3 transition mode- suseptible to downgrade security attacks

--

MSFVenom LHOST specifies ip address of attacker
LPORT - specifies listening port/ by default 4444 is used

--

aLTEr - layer2 meta-information to determine wich sites user visits

spearphone - using phones loudspaker and accelometer 

--

STP attack - rogue switch with low priority
double tagged 802.1 Q frames - packet injection.



--

DDoS with catching and IDS detection avoudance - HULK (HTTP Unbearable Load King)

MEDUSA - osint tool for social media

hootsuite - social media management platform

--
watering hole - infecting site users are likely to visit


--
Evilginx - MITM that spoofs website

--
MITC - man in the cloud attack, can avoid by install CASB, cloud access security broker

--

implicit FTPS - ports 989 and 990, without requiring FTP client to request security from server

--

cisco VPN file type - pcf, google dork filetype:pcf

--
WS-security - provide integrity and confidentiality for SOAP messages


--

AES - 128bit block size regardless the key lenght

--

nmap -D - decoy scan, spoofed source IP address

--

ARP poisoning - assiciates MAC with IP

--

spimming - instant messaging

smishing - over sms

--

RIPE NCC - europe regional internet registry (RIR)

--

hping3 -c 1 - sends single icmp echo request, will not work on windows, it drops icmp echo packets that are not directed to devices ip address

--

Linux TTL - 64

windows ttl - 128

network devices ttl - 255

--

XXE (XML external entity) injection - XML injection targets XML libraries <!DOCTYPE>

--

polymorphic virus - mutates while retaining original functionality

--

cyber kill chain:
Actions & objectives - system destruction phase

--

syhunt hybrid - web app vulnerability scanner, also for ios and android apps

--

SOX - to disclose financial information

--

robots.txt - locations of restricted files and directories

--

LDAPS - TCP 636

LDAP - 389

POP3 - TCP 110 

POP3 over ssl - 995

SMB - 445

--

Docker daemon - processes API requests and handles Docker objects

--

brute force with rainbox table - to mitigae use salt value

rainbow table - hash comparison to list of known hashes

--

SOAP - older API messaging protocol that uses HTTP and XML (cannot use JSON)

--

nmap -sI - idle scan, IPID retuned by zombie host to check open/closed ports.

nmap -sF - FIN scan

--

nmap -g - spoof port number, alternate --source-port. Only for SYN UDP scans

nmap -A - aggressive scan

nmap -D - decoy scan or spoofed source address scan

nmap -f - fragmented ip packets to avoid IDSs

--
wash -i mon0 - scan WPS enables access points from linux. 

Trident - monitor iphone calls, needs to nbe jailbroken remotely

--

clickjacking - fake iframe

VAWTRAK - email disguised as package delivery notification. Trojan

--

Serpent - symmetric 128-bit block size with key lenght of 128, 192 or 256 bits

--

tactical threat intelligence - TTP's and vulnerabilities

--

trustjacking - compromised host with itunes to control iphone over wireless network

--

DHCP starvation - impersonation of DHCP clients

--

IDOR vulnerability - 


--

nmap -pp