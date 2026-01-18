

Techniques of enumeration:
 - Extracting usernames using Email id
 - Default passwd
 - Brute force AD
 - DNS zone transfer -dig
 - Extract user groups from Windows
 - Extract user names using SNMP
 - Extract network resources and topology using SNMP

Services and ports to enumerate:

- TCP/UDP 53: DNS Zone tranfer
- TCP/UDP 134: MS RCP endpoint Mapper
- UDP 137: NetBIOS Name Service (NBNS)
- TCP 139: NetBios Session Service (SMB over NetBIOS)
- TCP/UDP 445: SMB over TCP (Direct Host) ((SMB = printers))
- UDP 161: SNMP
- TCP/UDP 389: LDAP
- TCP 2049: NFS Network file System
- TCP 25: Simple Mail Transfer Protocol (SMTP)
- TCP/UDP 162: SNMP Trap
- UDP 500: Internet security association key management protocol ISAKMP/Internet Key exchange (IKE)
- TCP 22: Secure Shell (SSH)/SFTP
- TCPUDP 3268: Global catalog Service
- TCP/UDP 5060, 5061: Session initiation protocol SIP
- TCP 20/21: FTP
- TCP 23: Telnet
- UDP 69: TFTP
- TCP 179 BGP

**NetBIOS enumeration**:
Ports:
	137 UDP Name service
	138 UDP Datagram service
	139 TCP Session service
*Does not work on ipv6

| Name      | NetBIOS Code | Type   | Information obtained                         |
| --------- | ------------ | ------ | -------------------------------------------- |
| host name | <00>         | UNIQUE | Hostname                                     |
| domain    | <00>         | Group  | Domain name                                  |
| host name | <03>         | UNIQUE | Messenger service                            |
| username  | <03>         | UNIQUE | Messenger service running for logged in user |
| host name | <20>         | UNIQUE | Server service running                       |
| domain    | 1B           | UNIQUE | Domain Master browser name                   |
| domain    | 1E           | Group  | Browser service elections                    |

Tools:
	nbstat -m for local table
	nbstat -A 10.10.10.10 for remote system table
	nbastat -c for remote catche
	PsExec - enumerate user accounts
	PsFile 

Enumerate shared resources:
	net view \\computername
	net view \\domain

**SNMP enumeration:**
Ports:
	UDP 161 SNMP Agent
	UDP 162 SNMP Trap
Versions:
	v1 - no security, plaintext security strings
	v2c - no security byt faster, still plaintext
	v3 - auth + encryption, secure and recommended
Tools:
	SNMPCheck
	Engineers toolset
	SNMP Scanner,
	OpUtils 5
	SNScan
	snmpwalk -v1 -c public - view all OIDs 
	snmp-check
	SoftPerfect Network Scanner
	
Management information base MIB
	DHCP.MIB - monitors network traffic between DHCP servers
	HOSTMIB.MIB - monitors and manages host resources
	LNMIB2.MIB contains object types for workstation and server services
	MIB_II.MIB - Manages TCP/IP-based internet using simple architecture and system
	WINS.MIB: For windows internet name service WINS

- 🟢 **MIB-II = TCP/IP networking**
    
- 🟡 **HOSTMIB = hardware & system stats**
    
- 🔵 **LMMIB2 = Windows LAN Manager services**
    
- 🟣 **WINS.MIB = NetBIOS name database**
    
- 🟠 **DHCP.MIB = DHCP service only**

**Ldap enumeration**
Ports:
	TCP 389 LDAP
	TCP 636 Secure LDAP
(Lightweight directory access protocol)
Tools:
	ldapsearch
	AD Explorer
	Softerra LDAP Adminstrator
	nmap ldap-brute NSE script

**NTP and NFS enumeration**

NTP Ports:
	UDP 123
Tools: 
	ntptrace
	ntpdc
	ntpq
NFS Ports:
	2049
Toools:
	rpcinfo -p for open port
	showmount
	rpc-scan
	SuperEnum


**SMTP and DNS enumeration**

Ports:
	TCP 25
Tools:
	Telnet:
	SMTP VRFY  - Check if address exists for user
	SMTP EXPN - request or expand mailing list into individual recipients
	SMTP RCPT TO - Specifies recipient of message
	Telnet <email server> 
	Nmap
	Metasploit
	NetScanTools Pro
	smtp-user-enum
DNS enumeration using zone transfer:
	UDP 53
Tools:
	dig ns - retrieves all DNS name servers
	nslookup - windows hosts, name servers, mail etc.
	DNSRecon -t axfr -d -
	

DNS catche snooping

nonrecursive method - responds with root.hints dig +norecursive
recursive method - TTL is examined
	
DNSSEC zone Walking:
enumerating DNSSSEC zone
Tools:
	LDNS
	DNSRecon
	Knock
	Raccoon
	Turbolist3r
OWASP AMASS
	amass enum -d
	

IPSec enumeration:

nmap -sU -p 500

ike-scan -M

VoIP enumeration:
Svmap

RPC enumeration:
 nmap -sR
 nmap -T4 -A

Unix/Linux user enumeration

rusers -a, -l, -u, -i
rwho -a
finger -s 

SMB enumeration:
 nmap -p 445 -A
 nmap -p 445 --script smb-protocols
 nmap -p 139 --script smb-protocols
 
