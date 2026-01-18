
Packet sniffing - monitoring and capturing data packets passing trough a given network using software app or hardware device

Allows to observe and attack entire network from any given point.

Attacker switches NIC into promiscuous mode so that it listens to all data on its segment

Types of ethernet enviroments: 

- Shared ethernet - single bus connects all hosts to compete for bandwith. Hub -wtf? 

- Switched Ethernet - switch maintains ARP table, which mac is connected to which port, so that the machine sends packets to only the destined computer, so the process of putting NIC in promiscuous mode does not work, however there are other methods.

Sniffing methods for switched networks:

- ARP spoofing/poisoning - ARP is stateless. Machine can send ARP reply even without asking for it. 
	- Spoofing ARP - forged ARP messages that associate ther MAC with IP of another host, enabling MITM
	- MAC flooding - Layer 2, attacker send fake mac addresses until CAM table is full, then it starts acting as HUB, broadcasting all packets everywhere
	- Tools - arpspoof, Habu 
	- Defence - Dynamic ARP inspection
	- Detection - Capsa portable network analyzer, wireshark, OPUtils, netspionage

MAC spoofing/Duplicating - inpresonate mac to connect to switch port
- in windows settings  change mac
- Tool MAC address changer 
- Defence - DHCP snooping biding table. Dynamic arp inspecion and IP source guard

 ICMP router discovery protocol (IDPR) spoofing - allows host to discover IP of active routers on its subnet.  

VLAN hopping
- Switch spoofing - rogue switch to create trunk between legit and rogue. Only possible when interface is configured with "dynamic auto", 'dynamic desirable' or trunk mode
	-  Defence - configure ports as access ports and not to negotiate trunks

- Double tagging - add and modifies 802.1Q outer and inner tags in Ethernet frame, therefore allowing flow of traffic trough any VLAN in network. (attacker wants to reach inner tag)
	- Specify default VLAN, all VLANs on all trunks are changed to an unused VLAN ID, all VLAN ports explicitly tagged

- STP attack - rogue switch is introduced. STP is for removing loops in network. Rogue switch is with lower priority than any other switch in network. This makes it root bridge in network - all traffic flows trough it.
	- Defence - BPDU guard, Root guards, Loop guard, UDLD (unidirectional link detection)

Types of sniffing:
- Passive sniffing - involves sending no packets
- Active sniffing - Searching for traffic by actively injecting traffic into it
	- Mac flooding
	- DNS poisoning
	- ARP poisonong
	- DHCP attacks
	- Switch port stealing
	- Spoofing attack

Protocols vulnerable to sniffing:
- Telnet and Rlogin
- HTTP
- SNMP
- SMTP
- NNTP - network news transfer protocol
- POP
- FTP
- IMAP
- TFTP

Hardware protocol analyzers, sniffers- 
- Xgig 1000 32/128 G - inline, non intrusive capture, auto negotiation, link training, forward error correction
- SierraNet M1288 - fiber channel fabrics

SPAN port - 
- Switched port analyzer (SPAN) - Cisco feature, also known as port mirroring. If attacker is connected to span port he can compromise whole network

Wiretapping or telephone tapping:

- official/unofficial tapping of phone lines
- recording conversation
- direct line wiretap
- radio wiretap

Active tapping - MITM, inject or alter data
Passive tapping - snooping or eavesdropping.

Mac flooding - macof -i eth0

Switch port stealing - send forged ARP packets using victims MAC address

DHCP attacks:

DHCP starvation - sends large number of requests to DHCP server exausting address pool, dhcp server is unable to allocate configs to new clietns | Yersinia, dhcpStarvation.py, Metasploit. Hyenae | 
- Defense - enable port security, DHCP filtering

Rogue DHCP Server attack - MITM, introduces rogue DHCP server, packets reach rogue server first. May assign IP address that serves as clients default gateway. To mitigate - set connection between interface and rogue as unthrusted. Tools mitm6, ettercap, gobbler.

DNS poisoning techniques:
 - Intranet DNS spoofing - ARP poisoning
 - Internet DNS spoofing - rogue DNS with static IP, then sends Trojan that changes DNS entries on victims PC
 - Proxy server DNS poisoning - Trojan that changes proxy settings in IE or any browser.
 - DNS Cache poisoning - altering or adding forged DNS records to DNS resolver. SAD DNS attack - injecting harmful DNS in cache to divert traffic to their own servers. Exploiting Side channels, flaws in dnsmasq, unbound and BIN.
	 - Tools DerpNSpoof, deserter, PolarDNS, Ettercap, Evilgrade, DNS Goisoner
	 - Defend -  DNSSEC, SSL

DNS sniffing tools:
	Wireshark - uses WinPcap


| Monitoring specific ports                                              | tcp.port == 23<br>ip.addr == 192.168.1.100 machine<br>ip.addr == 192.168.1.,100 && tcp.port == 23 |     |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | --- |
| Filtering by Multiple addresses                                        | tcp.port == 23<br>ip.addr == 10.0.0.4 or ip.addr == 10.0.0.5                                      |     |
| Filter by ip address                                                   | ip.addr == 10.0.0.4                                                                               |     |
| Other filters                                                          | ip.dst == 10.0.1.50 && frame_len > 400                                                            |     |
| Display all TCP resets                                                 | tcp.flags.reset == 1                                                                              |     |
| Set filer for hex values                                               | udp.contains                                                                                      |     |
| http.request                                                           | Displays all HTTP GET requests                                                                    |     |
| tcp.analysis.retransmission                                            | Displays all re transmissions in the trace                                                        |     |
| tcp contains traffic                                                   | Displays all TCP packets that contian word traffic                                                |     |
| ! (arp or icmp or dns)                                                 | Masks out arp, icmp, dns or other prtotocols                                                      |     |
| Sets filter for any TCP packet with 4000 as source or destination port | tcp.port == 4000                                                                                  |     |
| tDisplays only SMTP (port 25) and ICMP traffic                         | tcp.port eq 25 or icmp                                                                            |     |
| displays traffic in LAN between workstations and servers               | ip.scr == 192.168.0.0/16 and ip.dst == 192.168.0.0/16                                             |     |
|                                                                        |                                                                                                   |     |

Sniffing tools:
- Capsa portable network analyzer
- OmniPeek


Sniffing countermeasures: 
- restrict physical access to network
- end to end encryption
- add MAC to ARP catche
- etc...


How to detect sniffing:
- IDS
- Devices running in promiscuous mode
- Run network tools
Ping method - ping with incorrect MAC
DNS method - increased network traffic, monitor reverse DNS lookups, send ICMP request to non-existing IP address
ARP method - send non-broadcast ARP to all nodes

Promiscuous detection methods - nmap --script=sniffer-detect, NetScanToolsPro
