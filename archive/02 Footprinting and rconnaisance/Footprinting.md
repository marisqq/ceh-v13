https://www.exploit-db.com/google-hacking-database

![[Pasted image 20250819201029.png]]![[Pasted image 20250819201110.png]]
FTP search engines - NAPALM FTP indexer, FreewareWEB
Netcraft - identify fraudulent domains, malicious domains

Competitive intelligence - information that can be gathered freely an passively 

Website mirroring sites:
	HTTrack
	BlackWidow
	WebRipper
	Teleport Pro
	GNU Wget

Website watcher = monitor websites for changes, can send messages when site is updated

email header analysis = email tracker pro, infoga, politemail

DNS Port 53 - UDP, Zone transfers use TCP

Internet assigned numbers authority - shows all DNs root servers and who owns them
![[Pasted image 20250819220741.png]]


**EXAM - 100%:**
**SRV** - Service = Defines hostname and port number for servers such as directory services server

**SOA** - Start of authority = Identifies primary name server of the zone. Contains hostname of the DNS records withn the namespace, as well the basic properties of the domain

**PTR** - Pointer = Maps IP address to a hostname for reverse DNS lookups, usually associated with email server records, These respond to clients requests for name resolution.

**MX** - Mail Exchange = Identifies email servers within domain

**CNAME** Canoncial name = Record provides for domain name aliases, for example ftp service could be listed within the main DNS service

**A** - Address = Maps an IP address to hostname and is used for DNS lookups



All DNS records are managed by authoritative server - **SOA**

**DNS zone transfer**  AXFR- replicating DNS records

**DNS poisoning** - pointing servername to different ip address (To mitigate restrict time records can stay in cache before they're updated)

DNSSEC - Domain name security extensions = suite of internet Engineering Task Force (IETF) specifications, used to sign DNS data, adding data origin authentication and data integrity protection.

**SOA** record holods information of:
	**Source Host** - Primary DNS server for the zone and associated NS record
	**Contact email** - Responsible person for the zone file
	**Serial number** - Revision number for zone file, if zone file serial is higher than secondary server its time to update
	**Refresh time** - The amount of time secondary DNS server will ask for updates, default is one hour or 3,600 seconds
	**Retry time** - Amount of time secondary server will wait to retry if zone transfer fails, default is 600 seconds.
	**Expire time** - Time secondary server will wait to complete zone transfer, default is one day or 86,400
	** Time to live** - minimum time to live for all records in the zone, if not recorded by zone transfer records will perish, default is one hour



**ICANN** - Internet corporation for  Assigned names and numbers = Manages IP address allocation and host of other things 

**RIrs** - regional internet registries = 
	American Registry for internet numbers (ARIN)
	ASIA-Pacific Netfork information Center (APNIC)
	Reseaux IP Europeens Network coordination center (RIPE NCC)
	Latin America and Caribbean Network information Center

****SpoofCard**** - phone number spoofing service

Whois output - memorize

nslookup - options hostname | -server : Memorize for exam

	query=MX recrods of mailservers

ICMP ECHO - UDP
Traceroute tools:
	Path Analyzer Pro
	VisualRoute

OSRFramework - Python osint tool
	usufy.py - verifies if user exists in different platforms
	mailify.py - check where email is registered
	searchfy.py - search by using full names and other info in several platforms
	domainfy.py - verifies existence if given omain
	entify.py - looks for regular expressions
	SEF (social engineering framwork) - Maltego
	
	