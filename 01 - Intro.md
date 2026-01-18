-------
Elements of information security
--------------------------------------------
 - Confidentiality - accessible to those only with access
 - Integrity - preventing unauthorized changes so you can trust you data
 - Availability - resources available to authorized users
 - Authenticity - you can trust that everything including files, communication is genuine
 - Non-repudiation - A guarantee that sender cannot deny he sent anything
 - 
-------------------------------------

Risk analisys:
Risk matrix

ARO - annual rate of occurance,

SLE - single loss expectency

ALE = SLE xARO

BCP - business continuity plan



CIA =

Confidenyiality - Password, user ID, identity

Integrity - unauthorized alteration or revision / chanigng of data/ ensured via hash function

Availability - Dos,

IR - Incident Response

Preperation;

Recording and assignment;

Triage,

Notification,

Containment,

Evidence gathering,

Eradication,

Recovery,

Postincident activity.

Hacking methodology:

1: footprinting

Gathering evidence and information. Passive footprinting gathers info without direct interaction with the attacker. Active footprinting requires action.

2 and 3: Scanning and enumeration:

Scanning: identifying networks or hosts, discovering OS, architecture and vulnerabilities.

Enumeration: happens usually in intranet

4: Vulnerability analysis

5: **System hacking** 
	Gaining access - password cracking, sql injection
	Escalation of privileges - increase access, change password, delete files
	Maintain access - ensuring way back into machine
	Clearing logs - conceal success of hack and avoid detection by altering log files, hiding files within hidden attributes or directories or using tunneling to communicate with system
**SIEM** - security incident and event management. Splunk

**Cyber kill chain** - 
	1. Reconnaissance - Gathering data, identifying vulnerabilities
	2. Weaponization - Creating malicious payload using vulns, backdoors etc. (createing A weapon)
	3. Delivery - sending payload to target
	4. Exploitation - executing delivered code on target system
	5. Installation - installing malicious application on target 
	6. Command and control - creating C2 channel to send data back and fourth
	7. Actions and objectives - Performing actions to complete mission, carry out activities to steal or malform data, set up bot machines.
	![[Pasted image 20251221190622.png]]
Adversary behavioral identification - identifying attackers common methods.
TTPs - 
Tactics - how threat actor operates during different phases of an attack, APT
Techniques - important when analyzing efficiency, mostly depends on technical tools for privilege escalation
procedures - a sequence of actions

**ioc - indicator of compromise, clues left by hacker**
	email indicators, such as spcific senders, addrsses, subject lines and types of attachments
	Network indicators: urls, domains and ip addrs.
	host based indicators: speciic filenames, hashes registry keys
	behavioral indicators: powershell or remote command executions
	![[Pasted image 20251221191048.png]]
	
**Mitre ATT&CK framework**
	nonprofit free-to-use framework - systematically categorize adversary behavior
	can help and prepare to specific attack.
		**tactics** why hacker is performing the action
		**techniques** how hackers achieve goals
		**subtechniques** lover level description of adverserial behavior
		**procedures** specific or lower specific implementation or in the wild uses of techniques or subtechniques
	- Reconnaissance
    
- Resource Development
    
- Initial Access
    
- Execution
    
- Persistence
    
- Privilege Escalation
    
- Defense Evasion
    
- Credential Access
    
- Discovery
    
- Lateral Movement
    
- Collection
    
- Command and Control
    
- Exfiltration
    
- Impact
		
	Memorize[[https://oreil.ly/gQEcH]]m
	
**Diamond model**:
	Adversary - WHO, APT, cybercirminal group etc.
	Capability - WHAT, Malware, exploits, ransomware
	Infrastructure - WHERE, C2 servers, Malicious domains, IP addr.
	VIctim - WHO is targeted, Organization,

Information assurance (IA) - IA starts with policy, ends with people, and everything in between is risk management.
	Plan → Design → Find problems → Get resources → Plan fixes → Apply controls → Verify → Train people

Continual/Adaptive security strategy:
![[Pasted image 20251221194558.png]]

RISK = threats x vulnerabilities x impact
RISK = threat x vulnerability x asset value
Level of RISK = consequence x likelihood

Cyber threat intelligence - evidence-based knowledge about threats that helps organizations make better security decisions.
Types:
	Strategic intelligence - executives
	tactical intelligence - security teams
	operational intelligence - incident response
	technical intelligence - systems, siem, IDS etc
Lifecycle (CTI):
	Direction (what to know) -> Collection (gather data, logs, osint) -> processing (clean, normalize, enrich) -> Analyse (data to intelligence) -> Dissemination (Deliver intelligence to right people) -> Feedback
	
Threat modeling - process of identifying what can go wrong, how it can be attacked and how to mitigate.

Incident management - identify, prioritize, analyze, resolve, improve. OR detect, contain, recover, improve.
Incident response - Preparation, Recording and assignment, triage, notification, containment, evidence gathering, eradication, recovery and post incident activity.

***Laws and standards***
	PCI DSS - payment card industry standard
	ISO/IEC: 27001, framework for establishing, maintaining and improving information
	HIPAA - health insurance portability and accountability act (health information identifiable)
	SOX - consists of pcaob - protects investors, corporate disclosures 
	DMCA - USA copyright law . protects copyrighted digital content (DRM)
	FISMA - federal information security management act - u.s federal agencies, federal contractors, systems handling federal information, uses nist standards
	DPA 2018 - UK primary personal data protection law
	
	
	


**Hacking terminology**

White hat - ethical hackers
Black hats - bad guys
Gray hat - neither good or bad
sript kiddies - unskilled copy/paste
Cyber terrorists - religious or political beliefs
State sponsored - employed by nation state to carry out attacks usually against other nations
Hacktivists - motivated by political agenda, defecting disabling websites
hacker teams - skilled hackers with their own resources
Industrial spies - corporate espionage
insiders - trusted users carrying attacks from within
Criminal syndicates - organized crime init for the $
organized hackers - rented assets, gain money from victims



**Attack types**
Passive attack - monitoring efforts such as sniffing and evesdropping, nothing is altered
Active attack - active attempts to change, alter or delete data. Much higher risk of discovery
Close in attacks - physically close to target, shoulder surfing
insider attacks - Carried out by people who already have some form of access
distribution attacks - carried out before target system is delivered to customer

**Pen test phases**
Preparation - time period, scope, types of attacks allowed, people assigned
Assessment - actual pentest
Conclusion (postassesment) - report preperation, findings, recommendations



-
