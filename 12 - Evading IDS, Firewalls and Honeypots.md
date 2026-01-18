
IDS
-------
**Main function:**
- gathers and analyzes information within computer or network to identify unauthorized access and misuse
- IDS = Packet sniffer which intercepts packets, usually TCP/IP
- Packets are analyzed then captured
- Evaluates traffic and raises alarm

**Where resides in network:**
- Near firewall (outside/inside)
- When placed inside ideal location near DMZ
- Best practice to have one outside FW and one inside near DMZ

**How IDS works:**
- IDS have sensors to detect malicious signatures, advanced IDS include behavioral activity
- If signature matches IDS performs predefined actions
- when signature matches anomaly detection will be skipped
- When packets pass all tests the IDS will forward to the network

**How IDS detects intrusion**
- Signature recognition - misuse detection
- Anomaly detection - intrusion based fixed on behavioral characteristics 
- Protocol anomaly detection - deviations from established protocol standards
Intrusion prevention system (IPS)

**Network based IDS (NIDS)** 
- Black box that is placed on network in promiscuous mode, listening for patterns
- Detects stuff like DDoS

**Host based intrusion detection systems (HIDS)**
- Installed on specific host
- not common, eat lots resources
- Can detect more than NIDS, stuff like file modification

Types of IDS alerts

| Type           | Action              | Explanation                                             |
| -------------- | ------------------- | ------------------------------------------------------- |
| True positive  | Attack->Alert       | IDS raises alarm when legit attack occurs               |
| False positive | No attack->Alert    | IDS raises alarm when there's no attack                 |
| False negative | Attack->No Alert    | IDS doesn't rise alarm when there's attack              |
| True Negative  | No attack->No Alert | IDS does not raise alarm when no attack has taken place |

Intrusion prevention system (IPS)
--------------------------------------------------------------------
IPS is considered active IDS, they have capabilities not only detecting but also preventing them

- Generates alerts if abnormal traffic is detected\
- record real-time logs
- Block and filter malicous traffic
- detect and eliminate threats quickly
- identify threats accurately without generating false psoitives
Classification of IPS
- Host based
- Network based


Firewall
----------------
- Designed to prevent unauthorized access
- Placed at the junction or gateway between two networks
- Examine all messages entering and leaving the internet

**FW architecture:**

- Bastion host:
	- Designed for defending network against attacks. Mediator between inside and outside attacks
	- Two interfaces - public directly to internet, private connected to internet
- Screened subnet (DMZ):
	- created with two or three homed firewall behind screening firewall
		- Multi homed firewall - node with multiple nic's that connects to seperate network segments.
- Demilitarized zone (DMZ):
	- placed in neutral zone between internal and untrusted external network. DMZ serves as buffer between secure internal network and the insecure internet

- **Types of firewalls**
	- Based on configuration:
		- Network based firewall - placed at the perimeter if network to inspect packet headers and enforce security rules. Cisco secure firewall ASA, PA7500, Fortigate 7121F (wtf)
		- Host based firewall - on individual PC's or servers, providing security against unauthorized access, trojans, worms etc. MS defender, Comodo firewall, norton firewall
	- Based on working mechanism
		- Packet filtering firewall - compare packets to set of criteria before its forwarded - source IP, Destination IP, source TCP/UDP port, destination TCP/UDP port, TCP flag bits, protocol in use, direction, interface.
		- Circuit-level gateway firewall - validates TCP three way handshake, works at session layer, gives controlled access to network services and host requests. Allow or prevent data streams.
		- Application level firewall - focus on application layer, analyze application information, proxy based, can permit or deny traffic
		- Stateful multi-layer inspection firewall -  can remember packets passed troughm combine best features of packet filtering and application based, CISCO PIX firewalls are stateful.
		- Application proxy - useful for logging, reduce load on network, perform user-level authentication, protect weak or faulty IP implementations
		- Network address translation (NAT) 
		- VPN firewall - used to connect WAN. Encrypts traffic, checks for integrity protection, checks integrity, decrypts traffic eventually. 
		- Next-generation firewalls - deep packet inspection, application awareness, control, integrated IPS, cloud based threat intelligence. Operate at various layers of OSI. 



| Firewall Type | OSI Layer | How It Works | CEH Keywords |
|--------------|----------|-------------|-------------|
| Packet-Filtering Firewall | L3 / L4 | Filters based on IP, port, protocol | Stateless filtering |
| Stateful Firewall | L3 / L4 | Tracks connection state | Session awareness |
| Circuit-Level Gateway | L5 | Validates TCP handshakes | Session validation |
| Application-Level Firewall (Proxy) | L7 | Inspects application data | Deep packet inspection |
| Next-Generation Firewall (NGFW) | L3–L7 | DPI + IDS/IPS + app awareness | Application awareness |

**Intrusion detection using YARA rules**
Yara is malware research tool using rule-based approach. 
- condition - when result will b e true against a file
- strings - defines all strings that need to be searched within the files
- Metadata - is part of YARA rule that includes general information. 
- Tools - yarGen

**IDS tools:**
- Snort - traffic analysis and packet logging
- protocol analysis and content searching/matching
- uses flexible rules language
- suricata - reeal-time IDS, inline IPS, network security monitoring, offline pcap processing.

**IPS tools:**
- Trellix IPS - find botnets, worms and reconnaissance attacks
- Check point quantum IPS
- McAfee - wtf

IDS and Firewall evasion techniques
--------------------------------------------------------------------------

**Identification:**
- Port scanning
- Firewalking - uses TTL values to determine gateway ACL filters and map networks by analyzing IP packet response. Probes same way as traceroute. Packet has TTL value one hop greater than firewall.
- Banner grabbing - banners are service announcements. 

**IP address spoofing, source routing and fragmentation**
- IP address spoofing - altering source IP, creating packets with forged source addresses, Hping for packet creation
- Source routing - packets are routed trough less designated, less structured, less monitored or alternate segments where firewall solutions are partially or not entirely installed.
- Tiny fragments - attackers create tiny fragments of outgoing packets, forcing some of TCP packets header information into next fragment.

**Bypassing FW/IDS using a proxy server**
- From device to your FW. Simply add proxy settings to pc

**ICMP tunneling**
- install ICMPTX
- insert malicious client commands or payloads into data portion of ICMP exho requests.
- IDS assuming its legit lets them pass
**Bypassing IDS/Firewall trough ACK tunneling**
-  Many firewalls do not filter ACK packets cause they come from already established connection. 
	- Attacker establishes legit connection
	- using Hping crafts ACK packet
	- firewall allows them trough
**HTTP tunneling**
- Tunnel traffic via TCP port 80 using tool like Chisel
- HTTP tunneling usually hides identity, surf bloxked sites, sharing resources securely over HTTP
**SSH tunneling**
- use of OpenSSH to encrypt and tunnel traffic.
- LPF local port forwading to access internal resources
- Remote port forwarding
- dynamic port forwarding SOCKS proxy trough ssh Bitvise SSH client
**DNS tunneling**
- using UDP 255 byte limit on outbound queries
- malicious data can be embedded in DNs packets, DNSSEC cannot detect
- used for malware to avoid IDS and maintain connection to C2
- tools: iodione and dnscat2
**External system**
- user works from home and has his laptop that can access system.
- attacker steals user traffic, session ID or cookies
- attacker can access corporate network
- attacker issues openURL() command
- users browser is redirected to attackers web server
- malicious code is donwloaded and execurted
**MITM attacks**
- attackers performs DNS server poisoning
- user sends facebook.com request 
- user accesses malicious server
- attacker tunnels users http traffic
**Bypassing trough content**
- Sends content containing malicious code
- macro bypass exploit
- exe, com, bat etc.
**XSS attack**
- XSS occurs processing input parameters
- inject malicious HTML code
- can use ASCII values
- using HEX encoding
- using obfuscation
**Bypassing WAF**
- HTTP header spoofing - spoofed headers and syntaxes
- Blacklist detection - identify blacklisted keywords (SQL)
- fuzzing/brute forcing - assetnote wordlists
- abusing ssl/tls ciphers - sslscan2
**HTML smuggling**
- HTML5 attachment
- Via Javascript
- URL lure
**Windows bits**
- Background intelligent transfer service that is used to distribute windows automatic updates
- bitsadmin can create job to transfer malicious file
- create persistance

**Other evasion techniques**
- insertion attack - confusing IDS by forcing it read invalid packets.
- Evasion - IDS discards packets, but the host they are meant to accepts them. Occurs at the IP layer. TCP connection must be in opened state with a handshake.
- DoS - creating state in which all resources are consumed, causes device to lock up and not investigate all alarms.
- Obfuscating - only destination can decode, not the IDS
- False positive generation - IDS generates alarm when no condition is present. Packets are constructed to generate large amount of false reports and hides real attack inbetween.
- Session splicing - exploits fact that IDS do not reconstruct sessions before pattern matching data. Network evasion method to bypass IDS where an attacker splits traffic in excessive number of packets such that no packet triggers IDS. IDS cannot handle excessive number of small packets. Attackers can use Nessus for session splicing
- Unicode evasion technique - In UTF-16, the character “/” can be represented as “%u2215” and “e” as “%u00e9”; in UTF-8, “©” can be represented as “%c2%a9” and “≠” as “%e2%89%a0.” With unicode proble is that there are multiple representations of single character.
- Fragmentation attack - if MTU is exceeded packets are split into multiple.
- Time to live attacks (TTL) - when TTL reaches TTL of 0 its dropped. Require knowledge of victims network topology.
- Urgency flag -  TCP ignores all data before the URG pointer. IDs do not considet TCP's urgency feature and process all packets.
- Invalid RST packets - TCP 16-bit checksums are used. RST packet is sent with invalid checksum.
- Polymorphic shellcode - NIDS identifies attack by matching attack signatures, polymorphic attack includes multiple signatures.
- ASCII shellcode - only characters from ASCII standard
- Application layer attacks - by media files - images, audios and videos. Using flaws in compressed data attacks are performed.
- Desynchronization - pre connection SYN is performed by sending initial SYN before real connection is established, but with invalid checksum. Post connection SYN with divergent sequence numbers but otherwise is normal packet. 
- Domain generation algorithms - DGA is software to generate new domain names and execute malware code.  Helps change domains frequently.

**NAC and endpoint security evasion techniques**
Network access control (NAC) techniques:
- VLAN hopping - gain access to dynamic trunking protocol (DTP), switch mode is changed by attacker to dynamic auto to dynamic desirable. Tools: VLANPWN
- Using pre-authenticated device - Gain access to authenticated device, device is used to log into network and then smuggle packages, usually Raspberry Pi is used. Tools: nac_bypass_setup.ch and FENRIR 

**Bypass endpoint security**
- Ghostwriting - modifying structure of malware without affecting functionality so that it can bypass antivirus by utilizing binary deconstruction, insertion of arbitrary assembly code and reconstruction. Ghostwriting.sh
- Application whitelisting - security feature in windows. DLL hijacking is performed to place malicious DLL with legitimate name that application is looking for.
- Dechaining macros - Spawning trough ShellCOM, attackers reference any object associated with COM trough VBA script. Spawning using XMLDOM, download and run code inside an Office process
- Clearing memory hooks: attackers find DLLs associated with functions and syscalls exported. x64dbg is used to identify syscalls stored in memory. Then payload is created that can overwrite these hooks by restoring exact bytes of data. Can be done by reloading right application
- Process injection - malware in memory space of running process. Attackers maintain persistence, escalate privileges. Can be performed via API functions such as VirtualAllocEx() WriteProcessMemory() and CreateRemoteThread()
- LoL bins- living off the land binaries, tools pre installed on system, configure Deimos C2 to communicate over HTTPS, run command to download remote file, execute custom shell.
-  Control panel side loading - mimics original CPL applet functionality to hide itself, use CPLResourceRunner
- Metasploit templates - msfvenom and then test with VirusTotal the detection rate.
- AMSI - powershell downgrade-> downgrade to 2.0 to evade AMSI detection, use obfuscation, force an error, hijack memory
- Hosting phishing sites
- Passing encoded commands
- Fast flux DNS method - change both IP addresses and DNs names rapidly, helps circumvent blacklists and hide C&C
- Timing based evasion - sleep patching, delay APIs and time bombs.
- Single binary proxy execution - rundll32
- Shellcode encryption
- Reducing entropyt - manipulate binary characteristics
- Escaping local AV sandbox 
- Disabling event tracing for windows
- Spoofing thread call stack
- In-memory encryption of beacon

**IDS/Firewall evading tools**
- Traffic IQ professional
- Colasoft packet builder


Honeypots
----------------------
- log port access
- monitor keystrokes
- early warnings

**Types of honeypots**
- Low-interaction - emulate limited number of services and apps. Tiny-ssh-honeypot, KFSensor and honeytrap
- Medium interaction - simulate real operating system, application and services
- High interaction - simulate all services and application of target network
- Pure honeypot - emulate real production network
- Production honeypots - deployed inside prod. capture only limited amount of information. low interaction.
- Research honeypots - deployed by research institutes
- Malware honeypots - used to trap malware campaigns. Simulated with outdated APIs, vulnerable SMBv1 protocols etc.
- Database honeypots 
- Spam honeypots - open mail relays and open proxies
- Email honeypots - fake email addresses
- Spider honeypots - designed to trap web crawlers and spiders
- Honeynets - network of honeypots 
**Tools:**
- HoneyBOT - medium interaction
- Blumira
- NeroSwarm

**Detecting honeypots:**
- Fingerprinting running service - using nmap -sV -p 80 ip
- Analyze response time - measure latency responses nmap -p -scan-delay 1s max-retries 5 ip
- Examine MAC addresses to identify irregularities. arp-scan -interface=eth0 -localnet, unusual OUI
- Enumerating unexpected open ports - nmap -p ip, default configs, outdated banners, discrepancies in system information
- Analyzing system configuration and metadata - summarize configuration settings, default configs etc.

**Detecting and defeating honeypots**
- Layer 7 tar pits - similar to honeypots, slow down unauthorized attempts. Detected by latencty of response
- Layer 4 tar pits - manipulate TCP/IP stack and slow down spreading of worms, backdoors etc. IP tables switch to zero-window size blozking further data
- Layer 2 tar pits - protect from attacks on same network
- Honeypots running on VMware - by analyzing MAC address
- Honeyd honeypot - honeypot daemon, creates fake SMTP responses. Can identify with time-based TCP fingerprinting. SYN proxy behavior.
- user-mode UML linux - analyze files in /proc/mounts, proc/interrupts, proc/cmdline
- snort_inline - capable of packet manipulation. Can rewrite rules in iptables and mainly used in Gen 2 honeynets.
- bait and switch - redirect all traffic to honeypot
Honeypot detection tools:
- send safe honeypot hunter