
Gaining access
--------------------

Windows
----------
How passwords are stored in Windows SAM:

	Windows security accounts manager (SAM) or AD database to manage accounts and passwords in hashed format (a one way hash). 
	
	Does not store passwords in plaintext - uses hash.
	SAM file is used as database registry file.
	
	It's not possbile to copy SAM file to another location while windows is on.

	It's possible to dumb on disk contents including SAM with various techniques.

	SAM uses SYSKEY function to partially encrypt password hashes.

How passwords are stored in SAM:
- Location: %System root%\system32\config\SAM -> in registry HKEY_LOCAL_MACHINE\SAM
- It stores LM or NTLM hashed passwords
	
NTLM authentication: (NTLMv2 reasonably secure -still weaker than kerberos)
	NT LAN (NTLM) 
- Default authentication scheme
- Does not rely on any official protocol specification there is no guarantee it works effectively every time
- Vista and later Windows distros have disabled LM hashing
- LM hash value is blank in later versions of windows. 
- Selecting option to remove LM hashes enables additional check 
Tools to extract password hashes:
- pwdump7 - main
- Mimikatz
- DSinternals
- hashcat
- PyCrack

NTLM authentication process 

Client request access -> Server sends challange -> client computes response -> Server verifies (AD or SAM)


Kerberos authentification:
- Uses secret key cryptography
- KDC - Key distribution center
- AS - Authentication server
- TGS - Ticket granting server
- Upgrade from NTLM

Kerberos authentication process:
Login and request ticket -> Receive Ticket-granting Ticket (TGT) -> Request access to service -> Receive Service ticket -> Access the service



Cracking options: 
- Dumping creds from memory
- Steal local copy of SAM database
- Steal copy of AD file ntds.dit
- Extract SYSKEY boot key
Intercept creds sent over network
- Passive sniffing
- MITM
- Plain text password
- LM, NTML, NTLMv2, Kerberos
Brute force network services:
- Logon/SMB/File and print server (TCP 139. 445)
- web servers (80, 443)
- MS Exchange (TCP 25, 110, 143)
- MSSQL (1433)
Brute force remote cotntrol services:
	RDP (TCP 3389)
	Telnet (23)


Password cracking
------------------------

Non electronic attacks - social engineering, dumpster diving etc.

Active online attacks - password guessing, dictionary and brute forcing, password spraying, mask attack, hash injection, LLMNR/NBT-NS poisoning, trojans/spyware/keyloggers, internal monologue attacks, markov-chain etc.
- Dictionary attack - dictionary file is loaded into cracking application that runs against user accounts
- Brute force attack - software uses every combination until password is cracked
- Rule-based attack - when u have some info about password. Hybrid: depends on dictiornary attack usding old password. Syllable attack- using dictionary  and other methinds. Password spraying targets multiple accounts simultaneously.
- Hash injection/Pass the hash (ptH) - inject compromised hash into local session to validate network resources, using logged in user hash to log into domain controller
- LLMNR/NBT-S poisoning - LLMNR/NBT-S two main elements of windows system used to perform name resolution for hosts present on same link (Tool - Responder) (Link local multicast name resolution LLMNR, NetBios name service)
- Cracking Kerberos password - AS-REP roasting attack targets users who do not have kerberos pre-atuhentications, ticket granting ticket is extracted to obtain user passwords
- Kerberosing- obtain and crack service account hashes, aims to access higher-privilage accounts and move laterally (hashcat)
- Pass the ticket attack - authetnication without using password using credential dumping tools. steals ST/TGT from user machine or server (Mimikatz)
- NTLM Relay attack - Interception and relay of NTLM authentication request (Responder and ntlmrelayx)

Passive online attacks - does not change system in any way, password is gained by passively monitoring data passing by.

Offline attacks - recover passwords from hash dump

Password spraying tools:
thc-hydra:

hydra -l - login -p password -L logins -P passwords
Metasploit,
Rubeus,
adfsbrute
CrackMapExec

Mask attack - brute-force recovers passwords from hashes using pattern of the password.
hascat -m to specify hash mode for example MD5
Tools for default passwords:
fortypoundhead.com
cirt.net

Internal monologue attack - uses security support provider interface SSPI from user mode application to calculate NetNTLM response

Kerberos cracking 
- AS-REP Roeasing - cracking TGT, need connectivity to DC, need domain account. Only on accounts without Kerberos preauthetication required
- Kerberosing - cracking TGS tool - RUBEUS
- Pass the ticket - using kerberos ticket without providing password - Mimikatz
- NTLM relay - intercepting NTLM auth requests responder -I eth0
- Fingerprint attack - password is broken in 'p' 'a' s' etc.
- PRINCE attack - Uses chains of combined words
- Markov chain attack - split password in two three characters syllables creating new alphabet

Passive attacks:
Wire sniffing - at data link layer

online attacks:
rainbow table attack - uses already calculated information stored in memory to crack encryption tools: rtgen

Distributed network attack - uses lots of machines in network  Tools Exterro password recovery toolkit

Password recovery tools:
	Elcomsoft distributed password recovery
	passware kit
	hashcat
	pcunlocker
	lazersoft
	passper winsenior
Password cracking tools:
	L0phtCrack - recovers lost MS passwords
	THC hydra
	RainbowCrack

Password salting - adding random string of characters before calculating hashes
	
Tools to detect llmnr/nbt-ns poisoning - Vindicate. Respounder - detects presence of responder
got-responded

Vulnerability exploitation
--------------------------------------

Steps involved:
1. Identify the vulnerability
2. Determine risk associated with vulnerability
3. Determine the capability of vulnerability
4. Develop an exploit
5. Select method for delivering - local or remote
6. Generate and deliver payload
7. Gain remote access
Exploi sites - 
exploitDB
vulnDB
OSV.dev - for open source projects
MITRE CVE
Windows exploit suggester - WES-NG

**Metasploit:**
- Exploit module:
	1. Configure an active exploit
	2. Verify exploit option
	3. Select target
	4. Select payload
	5. Launch the exploit
- Payload module:
	1. Establishes communications channel between metasploit and victim
	2. combines arbitrary code that is executed because of the sucess of an exploit
	3. to select payload: msf payload
	Module types:
		Singles: Self contained and completely standalone
		Stagers: Sets up network connection between attacker and victim
		Stages: Downloaded by stager modules
		Payload module can upload and download files, take screenshots and collect password hashes
- Auxiliary module:
	1. used for one time actions like ports canning, DoS and fuzzing
	2. Usage: use, exploit
	show auxiliary - list all modules
	exploit/run to launch the command
	
- NOPS module:
	1. Used to generate no-operation instruction used for bloxking buffers
	2. msf generate -t c 50 - generate 50-byte NOP sled

- Encoder modules:
	1. Used to hide/encode payloads to avoid detection by AC, IDS
	2. Obfuscation
	3. Bypassing signature detection
	4. Polymorphisim - changes payload each time it is generated
- Evasion modules:
	1. Used to modify behavior and characteristics of payloads and exploits to avoid detection.
	2. evasion/windows/windows_defender.exe
	3. evasion/windows/antivirus_disable
	4. evasion/unix/antivirus_disable
- Post-exploitation modules:
	1. used after successful system compromise
	2. allow to further interact with system after the hack
	3. post/windows/gather/enum_logged_on_users
	4. post/linux/gather/enum_configs
	5. post/windows/manage/portproxy

	
	AI-Powered vulnerability exploitation tools:
	Nebula
	DeepExploit - linked with Metasploit

Buffer overflow
----------------------
Buffer is an area of adjacent memory locations allocated to program or application to handle runtime data

Buffer overflow or overrun is common vulnerability in programs or apps that accepts more data than the allocated buffer

Vulnerability allows application to exceed the buffer while writing data and overwrite neighboring memory locations

Attackers exploit this to inject malicious code - damage files, modify data, access critical information, escalate privileges, gain shell access etc.

What programs and apps are vulnerable to buffer overflow?
- Boundary check are not performed
- Applications that use older programming language verisons
- Programs that use unsafe and vulnerable functions to validate buffer size
- no good programming practices
- no proper filtering and validation
- code execution in stack segment 
- improper memory allocation and sanitazation
- pointer use for accessing heap memory

Types of buffer overflow:

Stack-based overflow - stack is used for static memory allocation (Last-in-first-out LIFO)
- Two stack operations PUSH stores data and POP removes data
- If vulnerable attacker takes control of EIP register to replace return address and gain shell access
Stack based memory - 
- EBP extended base pointer (StackBase) stores address of first data element stored onto stack
- ESP extended stack pointer stores address of next instruction
- EIP extended instruction pointer stores address of next instruction to be executed
- ESI extended source index maintains source index for various string operations
- EDI extended destination index EDI maintains destination index for various string operations


Heap-based overflow - heap memory is dynamically allocated at runtime
- overflow occurs when block of memory is allocated to heap and data 
- vulnerability leads to overwriting object pointers
- heap overflows are inconsistent and have different exploit techniques

Windows buffer overflow:
- Spiking - crafted TCP and UDP packets to make it crash nc -nv ip port (establish connection) generate template using STATS function, generic_send_tcp ip port spike_script SKIPVAR SKIPSTR

- Fuzzing - sends large amount of data amd overwrites EIP register, helps identify number of bytes to crash the target server, helps determine location of EIP register for code injection. while loop[python script], use pattern_create Ruby tool to generate random bytes of data, then metasploit pattern_offset to find random bytes of data, obverwrite EIP register, configure netcat to liste to 4444 nc -nvlp 4444

- Identify the offset (Metasploit) pattern_create and pattern_offset rubytools to find where EIP register is being overwritten
-

Return oriented programming (ROP) attack
 Reuse of code snippets already existing in code usually in libc or kernel32.dll
Heap spraying - flood free space of process memory by writing multiple copies of malicious code

JIT (just in time) spraying - execute arbitrary code to victims sytem in JIT compilation feature in modern browsers, attacker uses JavaScript code containing malicious payload

Exploit chaining - combines various exploits and vulnerabilities

AD Domain mapping using bloodhound - 
JS web application

Post AD enumeration using PowerView - users. groups, domains


| Command                                          | Description                                                                             |
| ------------------------------------------------ | --------------------------------------------------------------------------------------- |
| Get-ADomain<br>Get-NetDomain                     | Retrieves information related to current doman icluding DC's                            |
| Get-DomainSID                                    | Retrieves security ID's                                                                 |
| Get-DomainPolicy                                 | Retrieves information related to the policy configurations of the domains system access |
| (Get-DomainPolicy). "SystemAccess"               | Retrieves information related to policy configs on domains system access                |
| (Get-DomainPolicy)."kerberospolicy"              | Retrieves information related to domain kerberos policy                                 |
| Get-NetDomainController                          | Retrieves information related to current domain controllet                              |
| Get-NetUser                                      | Info for current user                                                                   |
| Get-NetLoggedon - ComputerName                   | current active domain user                                                              |
| Get-UserProperty -Properties pwdlastset          | date and time password was last set for each domain user                                |
| Find-LocalAdminAccess Invoke-EnumerateLocalAdmin | Retrieves users having local administrative priviliges (requires admin)                 |
| Computer-NetSession -ComputerName                | Retrieves information to the current user logged in the machine                         |
|                                                  |                                                                                         |
Enumerating Domain trust forests
	One-way trust- unidirectional trust, allows users in trusted domain access resources of trusting domain
	Two-way trust - allows users to access another domain and vice versa

Identifying insecuritie using GhostPack Seatbelt - collects information including PowerShell, kerberos tickets and items in RecycleBin.

Buffer overflow detection tools
- OllyDog
- Veracode
- Flawfinder
- Kiuwan
- Splint
- Valgrind

Privilege Escalation
-----------------------------

Horizontal privilege escalation - tries to get acess to resources that belong to authorized user with similar permissions. Not really escalation same user level but from location that should be protected from access.

Vertical privilage escalation - unauthorized user tries to gain access to user with higher privileges. User executes code at higher privilege lever

Privilege escalation using DLL hijacking - placing malicious DLL in application library
 Tool - Spartacus

Privilege escalation by exploiting vulnerabilities - exploitDB

Privilege escalation using Dylib hijacking - dynamic library attacks. MacOS. Tools Dylib hijack scanner

Privilege escalation using spectre - found in processors, amd, apple, arm, intel etc.  tricks processor into exploiting speculative execution to read restricted data.

Meltdown vulnerability - all ARM, Intel deployed by apple - trick processors into accessing out of bounds memory.

Named Pipe impersonation - in windows pipes used to provide legitimate communication between running processes. Metasploit is used to perform named pipe impersonation

Unquoted service paths - executable path is enclosed in quotation marks "" so that system can easily locate application binary, attackers exploit services with unquoted paths to elevate privileges.

Service object permissions - misconfigured service permissions allow attacker to modify attributes associated with that service. They can add new users, hijack account and elevate privileges. Usually Zer-days

Pivoting - bypass firewall to pivot via compromised system to access other vulnerable systems

Privilege escalation using misconfigured NFS - port 2049 using RPC 
- nmap -sV ip check if NFS service is running
- sudo apt-get install nfs-common
- showmount -e
- mkdir /tmp/nfs
- sudo mount -t nfs
Privilege escalation by bypassing User account control UAC - Metasploit, via memory injection, FodHelper Registy key, trough eventvwr registry key, trough COM handler hijacking

Privilege escalation by abusing boot or login initialization steps: 
	Logon script (windows) - embedding script in registry key: HKEY_CURRENT_USER\enviroment\userinitMPRLogonScript
	Logon script (MAC) - known as login hooks 
	Network logon scripts- allocated using AD GPOs
	RC scripts (unix) - malicious binary shell or path in RC scripts such as rc.common or rc.local within unix
	Startupitems - attackers create malicious files or folders within the /Library/Startupitems - used to boot stage with root priveleges

Privilege escalation by modifying Domain Policy -
Group policy modification - modify ScheduledTasks.xml using scripts as New-GPOImmediateTask

Domain trust modification - use domain_trusts utility to collect information about trusted domains

Retrieving password hashes of other domain controllers using DCSync attack - attacker obtains priveleget account with domain replication rights. Then virtual DC is created similar to original AD. This enables attacker to get things like NTLM hashes, golden ticket attacks, Living off the land attacks etc.
Tools: mimikatz mimikatz "lsadump: :dcsync /domain: (domain name) /user:Adminstrator"

Privilege escalation by abusing Active directory Certificate Services (ADCS) - ADCS is for public key infrastructure. Can lead to critical vulnerabilities. Tools - Certipy

Other privilege escalation techniques: 
- Access Token maipulation - tokens used to determine security context of process
- Parent PID spoofing - parent process ID spoofing, svchost.exe or consent.exe
- Application shimming - application compability framework, can be used to bypass UAC and inject malicious DLLs
- Filesystem permission weakness
- Path interception - executing appication from path instead of real one
- Abusing accessibility features
- SID-History injection - windows security identifier (SID) attackers can inject SID of administrator
- COM hijacking - component object model (COM) - hijacking valid references and adding their own references to infect target system
- Scheduled tasks in windows
- Scheduled tasks in linux - cron and crond
- Launch Daemon - macOS launchd
- Plist midification - MacOS plist
- Setuid and Setgid - Linux and MacOS
- Web shell - allows access to web server
- Abusing sudo rights
- Abusing SUID SGID permissions - unix based systems
- Abusing '.' path
- Abusing elevation mechanism in macOS
- Process injection via Ptrace system calls
- Abusing microsoft software installer MSI
- Abusing windows filtering platform (WFP) - NoFilter attack

Privilege escalation tools:
	BeRoot- post exploitation
	pwncat
	PowerSploit
	Traitor
	PEASS-ng
	FullPowers

Defend agains DLL and Dylib hijacking
- Dependency Walker
- Dylib Hijack scanner

Maintaining access
--------------------------

Backdoors- deny or disrupt operation, gain unauthorized access to system resources

Crackers: cracking code or passwords

Keyloggers

Spyware: screenshots n stuff

Remote code execution techniques - 
- Exploitation for client execution 
	- Web-browser based exploitation- targed web browsers trough spear phishing
	- office-application based exploitaiton - MS office
	- Third part based apps exploitation
- Service execution
- Windows management instrumentation (WMI)
- Windows remote management (WinRM)
Dameware romeote support
Ninja
Pupy
PDQ Deploy
ManageEngine endpoint central
PsExec

Keylogger - software and hardware (Metasploit can create remote keylogger)
Windows keyloggers - REFOG
All in One keylogger
Revealer keylogger
NetBull
Spytector
MAC keyloggers - 
Hoverwatch


Spyware:
Spytech SpyAgent
Spyrix personal monitor

Types of spyware - desktop spyware, email spyware, internet spyware, child monitoring spyware, screen capturing spyware, USB spyware, audio spyware (theOneSpy, Snooper), Video spyware (iSpy, Perfect ip camera viewer, optiview VMS, eyelinevideo surveillance software), print spyware, cellphone spyware (mSpy, XNSPY, iKeyMonitor, ONESPY, Highster mobile), 

Rootkits - access computer without being detected
	hypervisor level rootkit
	hardware/firmware rootkit
	kernel level rootkit
	boot-loader rootkit
	Application level rootkit
	Library-level rootkit
	Memory rootkits
popular rootkits - 
FudModule Rootkit
Fire Chili rootkit - log4shell

Detecting rootkits:
	integrity-Based detection - signatures, tripwire or AIDE to baseline system
	analyzing memory dumps
	

Anti-Rootkits:
	GMER
	Stinger
	Avast One
	TDSSKiller

NTFS data stream - windows hidden stream
ADS - alternate data stream - fork data into existing files
ADS allows to inject malicious code in files

NTFS stream detector - 
	stream armor
	GMER
	ADS scanner
	Stream
	AlternateStreamView

Stenography - hiding secret message within ordinary message, utilizing graphic image as cover

Stenography tools -
	snow - in text
	OpenStego - images
	StegOnline - images
	Coagula - images
	SSuite Picsel - images
	CryptaPix - images
	StegoStick - documents
	StegJ - documents
	Office XML -documents
	SNOW - documents
	Data stash - documents
	OmniHide pro - video
	DeepSound - audio stenography
	GillSoft filel lock pro - folder stenography
	Spam mimic - email stenography
Stenography detection tools - zsteg, StegoVeritas, Stegextract, StegoHunt, Stenography studio, virtual stenographic laboratory.

Maintaining access by abusing boot logon autostart executions - custom configuration settings on compromised machine

Domain dominance trough different paths 

Malicious replication - creating exact copy of user data using admin credentials

Skeleton key attack - injecting false credentials, momory resident virus (mimikatz)

Golden ticket attack - post-exploitation, forge TGT by compromising key distribtion service account

Silver ticket attack - steal user credentials and create fake TGS ticket (mimikatz)

AdminSDHolder - protects accounts and groups with high privileges, attacker can abuse SDProp process

Maintaining persistence trough WMI Event subscription - PowerLurk

Overpass the hash attack - OPtH - extension of pass-the-ticket and pass-the-hash attack (mimikataz)

Linux post exploitation

Hiding evidence of compromise
------------------------------------------

1. Disable auditin
2. Clear logs - metasploit meterpreter
3. Maipulate logs
4. Cover tracks on the network/OS
5. Delete files/ hiding artifacts
6. Disable windows functionality

Delete files using cipher.exe
