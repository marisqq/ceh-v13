
TCP/IP Networking
----------------------------------

- Using switched networks reduces number of received frames  that are not addressed to your system
- UDP - connectionless
- ![[Pasted image 20250929104437.png]]

- UDP most used protocols - TFTP, DNS, DHCP 
- TCP segment structure:
- ![[Pasted image 20250930110332.png]]
- SYN (Synchronize)- initial communication, negotiation of parameters and sequence numbers
- ACK (Acknowledgement)- as an acknowledgement of SYN flags. Set on all segments after initial SYN flag
- RST (Reset) - forces termination of connection in both directions
- FIN(finish) - Closes communications
- URG (Urgent) - indicates that data inside is being sent out of band, for example canceling message midstream.
SYN sequence number is random and increments with each packet sent, helps maintain legitimacy and uniqueness of this session. Plenty of attacks that can guess the sequence number.

**Memorize three way handshake and TCP flags for exam**

![[Pasted image 20250930111156.png]]

Packet crafting tools:
	NetScanTools, 
	Ostinato
	packETH,
	LANforge FIRE.
	Colasoft PAcket Builder
SYN, SYN/ACK, ACK, FIN

IANA maintains service name transport protocol port number registry which is official list of all port number reservations

Footprinting/reconnaissance
------------------------
Types of reconnaissance
	**Passive** - without direct interaction, osint, databases, intelligance sharing
	**Active** - DNS interrogation, social engineering, port scanning etc

Google advanced search operators:
	

| Search operator | Purpose                                                                |
| --------------- | ---------------------------------------------------------------------- |
| [catche:]       | Displays webpages in google catche                                     |
| [link:]         | Lists web pages that have links to specified web page                  |
| [related:]      | Lists web pages that are similar to specified web page                 |
| [info]          | Presents some information that google has about a particular webpage   |
| [site:]         | Restricts results to given domain                                      |
| [allintitle:]   | Restricts results to websites containing all search keywords in title  |
| [intitle:]      | Restricts results to documents containing all search keywords in title |
| [allinurl:]     | Restricts to results in URL                                            |
| [inurl:]        | Documents containing keyword in URL                                    |
| [location:]     | Find information for specific location                                 |

Meta search engines - Starpage, Metagear, etools.ch | hides users ip address
FTP search engines - NAPALM FTP indexer, FreewareWeb, Mamont, globalfilesearch.com

searching scada and IoT - shodan, censys, zoomeye

top level domains and sub-domains- netcraft, DNSdumpster, pentest-tools, sublist3r

photon- retrieve archived url's

People search services - spokeo

Os detection - netcraft, censys

Competitive intelligence gathering - edgar database, D&B hoovers (sales intelligence), LexisNexis, BusinessWire, Factiva, marketwatch, the wall street transcipt, euromonitor, experian, the search monitor, uspto, abi inform global, similarweb, SeRanking

Public source code repos - ReconNG

Social networks - TheHarvester, 
-theHarvester -d microsoft -l 200 -b linkedin
		-d specifies domain
		-b specifies linkedin data source
		
harvesting email lists - theharvester -l 200 (limits to 200 results)

Analyzing social media presence - BuzzSumo

Footpringing social networking sites - sherlock, social searcher, 


Whois, DNS footprinting
------------------------------

WHOIS
Types of whois - 
	Thick whois - stores complete whois info
	Thin whois - stores only name of whois server
	Decentralized whois - complete info and managed by independent entities
	
Regional internet Registries
	ARIN - America
	AFRINIC - africa
	APNIC - Asia pacific network
	RIPE - Europe
	LACNIC - latin america and caribbieans

![[Pasted image 20251228210853.png]]

Geolocation - IP2Location

DNS

DNS Record types


| Record type | Label               | Description                                                                                               |
| ----------- | ------------------- | --------------------------------------------------------------------------------------------------------- |
| A           | Address record      | Maps hostname to ipv4                                                                                     |
| AAAA        | IPv6 address record | Maps hostname to ipv6                                                                                     |
| MX          | Mail exchange       | Identifies mail server for domain                                                                         |
| NS          | Name server         | Identifies authoritative name servers                                                                     |
| CNAME       | Canonical name      | Map alias to true hostname                                                                                |
| SOA         | Start of Authority  | Defines authority for DNS zone (contains name of server responsible for all DNS records within namespace) |
| SRV         | Service record      | specifies service location (LDAP, SIP)                                                                    |
| PTR         | Pointer record      | Reverse lookup - maps IP address to a hostname (usually associated with email servers)                    |
| RP          | Responsible person  | Lists admin/owner of domain                                                                               |
| HINFO       | Host information    | Stores hardware type and operating system                                                                 |
| TXT         | Text Record         | Stores text data for DKIM and SPF                                                                         |

Tools
	Fierce - finds subdomains, dns misconfigurations, ip ranges, hostnames, internal naming patterns.
	DNSRecon - DNS enumeration, discover hosts and subdomains
	mxtoolbox - 


Traceroute:
Tools:
	NetscanToolsPro
	PingPlotter
Email tracking tools:
	eMailTrackerPro
	IP2Location

Social engineering
----------------------------
Evesdropping - listening of conversations
Shoulder surfing - observing the target secretly
Dumpster diving - yes
Impersonation - Pretending to be legitimate or authorized person

Automating footprinting tasks
-------------------------------------------
Maltego - determine relationships and real world links
Recon-ng - web reconnaissance framework, open-source
FOCA - tool to find metadata and hidden information in scanned documents
subfinder - subdomain discovery
Osint framework
Recon-dog - uses API's to collect information about target system
BillCipher - various things, dns lookup, whois, port scanning, zone transfer etc.
Ports etc.
--------------------------

**Well known ports: 0-1023**
**Registered ports 1024-49,151**
**Dynamic ports 49,152-65,535**

Important port numbers:

| Port number | Protocol | Transport protocol |
| ----------- | -------- | ------------------ |
| 20/21       | FTP      | TCP                |
| 22          | SSH      | TCP                |
| 23          | Telnet   | TCP                |
| 25          | SMTP     | TCP                |
| 53          | DNS      | TCP and UDP        |
| 67          | DHCP     | UDP                |
| 69          | TFTP     | UDP                |
| 80          | HTTP     | TCP                |
| 88          | Kerberos | TCP                |
| 110         | POP3     | TCP                |
| 123         | NTP      | UDP                |
| 135         | MS RPC   | TCP                |
| 137-139     | NetBIOS  | TCP/UDP            |
| 143         | IMAP     | TCP                |
| 161/162     | SNMP     | UDP                |
| 178         | RTSP     | TCP/UDP            |
| 389         | LDAP     | TCP/UDP            |
| 443         | HTTPS    | TCP                |
| 445         | SMB      | TCP                |
| 514         | Syslog   | UDP/TCP            |

**CurrPorts** - Displays all open ports on your PC

Port states:
CLOSE_WAIT - remote side of connection has closed closed the connection
TIME_WAIT - your side has closed connection

netstat - an displays all connections and listening ports
netstat -b shows executable tied to the open port

IPV4 - unicast, multicast and broadcast


ICMP - internet control message protocol (Network layer)
ICMP message codes:
0: Echo Reply
3: Destination unreachable:
	0- Destination network unreachable
	1- Destination host unreachable
	6- Network unknown
	9-Network administratively prohibited
	13- Communication administratively prohibited 
4: Source quench 
5: redirect
8: Echo request
11: Time exceeded

Ping sweep - best way to find active machines on network, very noisy
Tools: 
	Angry IP scanner
	SolarWinds engineers toolset
	Network Ping,
	OpUtils,
	Superscan,
	Advanced IP scanner,
	Pinkie

Nmap scan trough TOR

ARP:
Ties IP to MAC address in network
ARP scan in NMAP nmam -sn -PR 192.168.1.69

Port scanners work by manipulating TCP flags to indentify active hosts and scan their ports.

Port scan types:
	Full connect - TCP connect or full open scan, this runs trough three way handshake on ports, tearing it down with RST at the end. Easiest to detect, but possibly most reliable. Open ports will respond with SYN/ACK and closed ones with RST.

	Stealth - half open scan or SYN scan. Only SYN packets are sent. Less noticable cause no connection takes plase

	Inverse TCP flag - Uses FIN, URG or PSH flags to check system ports. If port is open there will be no response, if its closed RST/ACK wil be sent.

	Christmas scan (XMAS) - All flags are turned on, port responses are same as for inverse TCP scan. Does not work against Microsoft machines.

	ACK flag probe - sends ACK flag and checks return header (TTL or Window fields) In TTL if RST is less than 64 port is open. In Window version if window size is anything less than zero port is open.
(Can also be used to check for firewalll, if RST comes back there is no firewall)
	
IDLE scan - spoffing an ip, needs an idle machine


NMAP

Nmap without any options runs SYN scan, nmap remeber switches
 NetScanTools
 Hping3
 224

MIB info - need to check
