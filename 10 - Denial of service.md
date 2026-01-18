
Botnets
----------
Botnet finding vulnerable machines:
- Random scanning - random machines for vulns
- Hit-list scanning - collects potentially vulnerable machines then creates zombie army
- Topological scanning - information from infected machine to find new machines
- Local subnet scanning - yes
- Permutation scanning - using pseudorandom permutation list of IP addresses of all machines. block cipher of 32 bits and preselected key

Malicious code propogation - Central source propogation, attracker places toolkit on central source and copy of attack toolkit. Central source- exploit-> copy code-> repeat
Back-chaining propogation -  TFTP, from attackers machine
Autonomous propogation - attacking host itself tranfers attack toolkit same time it breaks into system attacker -> victim-> victim


DDoS case study: HTTP/2 "Rapid reset" - attack on google cloud in 2023, used stream multiplexing - 100 live streams trough one TCP connection. 


DDoS
------

Volumetric attacks - exaust bandwith, usually target NTP and SSDP which are stateless.
- Flood attack - large volume of traffic
- amplification attack - transfer messages to a broadcast IP address

Protocol attack - other than bandwith, such as connection state tables.

Application layer attacks - flood web traffic with legit user traffic, blocking access by repeated invalid login attemtps, SQL queries: slowloris (half open HTTP connections - many)

DoS/DDos attack techniques:
- UDP flood attack - spoofed UDP packets are sent at very high rate on random ports.
- ICMP flood attack - large amountof ICMP echo requests
- Ping of death - malformed or oversized packets
- Smurf attack - spoofed source IP address sends ICMP ECHO
- Pulse wave DDoS - repetitive strain of packets as pulses every 10min. Recovery almost impossible.
- Zero day DDoS - using vulns without paches. No protection discovered
- NTP amplification attack - botnet is used to send UDP packets to a spoofed IP address, NTP has monlist enabled. nmap -sU -Pu:123 -Pn -n --script=ntp-monlist
- SYN flood attack - TCP SYN request sent with fake source ip, machine does not get response cause saurce ip is fake, takes advantage of TCP/IP three way handshake
- Fragmentation attack - stop victim from being able to re-assemble packets. Large number of 1500 byte packets to target web server, can bypass firewalls, IDS/IPS
- Spoofed session flood attack - fake spoofed TCP session with SYN, ACK and RST or FIN packets
- HTTP GET/POST - use of time delayed HTTP header to maintain HTTP connection (hold on to connection and exaust web resources)
- Slowloris - partial HTTP requests to target web server
- Multi vector ddos - volumetric + protocol + application layer attacks
- Peer-to-peer - uses DC++ network
- Permanent Denial-of-service attack - phlashing, causes irreversible damage to hardware, fraudulent updates sent to victims
- TCP SACK panic - Linux only by sending SACK packets with malformed maximum segment size (MSS) causing integer overflow in linux Socket buffer. packets set to lowest volume - 48 bytes leading to kernel panic
- Distributed reflection DRDoS - spoofed attack, use of multiple intermediary and secondary machines, multiple intermediary services are used
- Ransom ddos - yes

Attack toolkits
- ISB - i'm so bored, http, udp, tcp and icmp flood attacks
- UltraDDOS-v2
- HULK
- Slowloris
- UFO net


Countermeasures:
- Activity profiling - base lining average flows
- sequential change-point detection - filtered by ip addresses, flow vs time
- wavelet based signal analysis - analyzes network traffic of spectral components.

Evasion - Blumira honeypot software


