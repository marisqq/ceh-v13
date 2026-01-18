Got it — **longer sentences, connected explanations, no bullet-only compression**.  
I’ll **talk you through this section as if I were sitting next to you**, so you don’t have to reread the slides.

Take this slowly and just **listen/read once**. You are not supposed to memorize yet.

---

## Web Server Security Issues — what this section is REALLY saying

The main idea of this whole section is very simple, even though EC-Council uses many words:

> **Web servers are exposed to the Internet, so even if network and OS security is strong, web servers remain highly attractive and vulnerable targets.**

Firewalls, IDS, and IPS mostly protect **network-level traffic**, but a web server must accept requests from _anywhere_, which means attackers can interact with it directly through HTTP/HTTPS. This is why attackers often ignore strong perimeter defenses and go after web servers and web applications instead.

---

## Why web servers are commonly compromised (in plain language)

Web servers are usually compromised **not because of one big mistake**, but because of **many small, careless decisions** made during setup and maintenance.

For example, when file and directory permissions are too loose, attackers may read or modify files they should never be able to access. When default, backup, or sample files are left on the server, attackers can use them to learn how the server is configured or even gain access.

Misconfigurations are extremely common and very dangerous. These can exist at the web server level, the operating system level, or the network level, and attackers actively look for these mistakes because they are easier to exploit than complex vulnerabilities.

Bugs in server software, operating systems, and web applications also contribute heavily. Even a well-configured server becomes vulnerable if it is not patched regularly.

Administrative or debugging functions are another frequent problem. Developers or administrators sometimes leave debugging interfaces or admin panels accessible from the Internet, which attackers can then abuse to gain control.

SSL/TLS misconfigurations also weaken security. Using self-signed certificates, default certificates, or outdated encryption settings can allow attackers to intercept or manipulate traffic.

Finally, web servers that are not hosted on dedicated systems often share resources with other services. This increases the attack surface and makes lateral movement easier once the server is compromised.

---

## Impact of web server attacks (what attackers gain)

When a web server is successfully attacked, the damage is rarely limited to just the website.

Attackers often begin by compromising **user accounts**, which allows them to gather sensitive information and use those accounts to perform further attacks. Website defacement is another common outcome, where attackers alter the appearance or content of the website to spread messages or damage credibility.

Once attackers control a web server, they can launch **secondary attacks** against visitors or other systems, effectively turning the compromised server into an attack platform.

In more severe cases, attackers gain **root or administrative access**, which gives them complete control over the server regardless of whether it is dedicated, shared, or virtual. At that point, they can do anything: install malware, create backdoors, or pivot deeper into the organization.

Data tampering and data theft are especially damaging. Attackers may modify data, delete it, or replace it with malicious content. Sensitive information such as financial records, internal plans, or source code may be stolen.

Finally, reputational damage can be devastating. When customers lose trust in an organization due to a web server breach, the impact often lasts far longer than the technical recovery.

---

## The layered security model (what the stack diagram means)

The stack diagram is showing that **organizational security is layered**, not flat.

At the bottom, you have security mechanisms like IDS and IPS. Above that is the network layer, followed by the operating system, the database, the web server software, third-party components, and finally custom web applications and business logic at the top.

The important idea here is this:

> **Even if the lower layers are well protected, a weakness in any higher layer (especially the web server or application) can still compromise everything above and below it.**

This explains why attackers focus on web servers and web applications — they sit high in the stack and are exposed to users.

---

## Common goals behind web server hacking (attacker motivation)

Attackers do not all have the same goals, but most web server attacks fall into a few clear categories.

Some attackers want financial gain, such as stealing credit card data or sensitive credentials using phishing techniques hosted on compromised servers.

Others integrate compromised servers into botnets, using them to perform DoS or DDoS attacks against other targets.

Database compromise is another major goal, especially when servers host applications that store valuable user data.

Some attackers are interested in obtaining proprietary or closed-source software, while others focus on hiding or redirecting traffic for malicious purposes.

Privilege escalation is also a common goal, because gaining higher privileges allows attackers to move laterally or maintain persistence.

Not all motivations are financial. Some attacks are carried out purely out of curiosity, to prove technical skill, or to damage an organization’s reputation.

---

## Dangerous security flaws (why admins matter so much)

This section is quietly blaming **poor administration**, and that is intentional.

Web servers managed by undertrained, careless, or overworked administrators often contain serious vulnerabilities. These vulnerabilities are usually not exotic exploits — they are basic mistakes.

Failing to apply patches leaves known vulnerabilities open. Reusing the same administrator credentials everywhere makes compromise spread instantly. Allowing unrestricted inbound or outbound traffic removes containment.

Running un-hardened servers and applications exposes unnecessary functionality. Detailed error messages reveal server versions and internal structure to attackers. Using outdated SSL/TLS algorithms weakens encrypted communication.

Third-party plugins are another major risk, because they are often poorly maintained and introduce new vulnerabilities without administrators realizing it.

---

## Why web servers get compromised — three perspectives

From a **webmaster’s perspective**, the main fear is that a web server exposes the internal network to Internet-based threats. Because web servers allow scripts to run and handle remote requests, any buggy CGI script or server-side program can become an entry point.

From a **network administrator’s perspective**, a poorly configured web server creates holes in the LAN’s security. The challenge is balancing usability with protection, because too much restriction makes services unusable, while too little exposes the network.

From an **end user’s perspective**, the web feels safe and anonymous, but modern web technologies like JavaScript and WebAssembly allow code execution in the browser. Attackers can exploit this to deliver malware, bypass firewalls, and gain access to internal networks through the user.

---

## What you should actually remember for the exam (don’t memorize yet)

For now, just make sure you **understand these ideas**, not the wording:

- Web servers are exposed by design
    
- Misconfiguration is the biggest enemy
    
- Attacks affect far more than just the website
    
- Security is layered, but higher layers are easier to attack
    
- Administrators and defaults cause most problems
    

Perfect — this is a **very good learning instinct**, and yes:  
👉 **chapter by chapter**,  
👉 **longer sentences**,  
👉 **explanations first**,  
👉 **memorization definitions at the end**  
is exactly how we’ll do **Module 13** with confidence and speed.

I’ll handle **this Apache section now** so you **do NOT reread the slides**.

---

# Module 13 – Hacking Web Servers

## Chapter: **Apache Web Server Architecture & Vulnerabilities**

Read this as a **story**, not as facts to memorize yet.

---

## 1️⃣ What Apache actually is (forget marketing language)

Apache is an **open-source HTTP web server** whose primary job is very simple:  
it **receives HTTP or HTTPS requests from clients (usually browsers)** and **returns web content** in response.

What makes Apache important in CEH is not how “good” it is, but that:

- it is **widely deployed**
    
- it is **highly modular**
    
- it is often **misconfigured**
    

From an attacker’s perspective, Apache is attractive because **any vulnerability or misconfiguration affects many systems**, not just one.

---

## 2️⃣ Apache Web Server Architecture – explained simply

Think of Apache as a **middleman** that does three things:

1. Accepts requests from users
    
2. Applies rules, security, and logic using modules
    
3. Either serves content itself or forwards the request elsewhere
    

### Request flow (this is the diagram in words)

A user (HTTP client, usually a browser) sends an **HTTP or HTTPS request** to the Apache web server.  
Apache receives this request through its **core HTTP server component**, which is responsible for handling communication.

If the request is for **static content** (like HTML, images, CSS), Apache can return it directly.

If the request is for **dynamic content**, Apache forwards the request to an **application server**, which generates the content and sends it back to Apache, and Apache then sends it to the client.

This separation is important because **Apache itself does not execute application logic** — it coordinates it.

---

## 3️⃣ Apache core and modules (this is what CEH cares about)

The **HTTP Server (Core)** is the heart of Apache.  
It does not do much on its own, but it **loads modules**, and those modules define behavior.

### Important Apache modules (you must recognize these)

**mod_ssl**  
This module enables **SSL/TLS encryption**, allowing Apache to handle HTTPS traffic securely.  
If mod_ssl is misconfigured or uses weak encryption, attackers may perform **man-in-the-middle attacks**.

**mod_auth**  
This module controls **authentication and authorization**, ensuring that only authorized users can access certain resources.  
If misconfigured, attackers may bypass authentication or gain unauthorized access.

**mod_rewrite**  
This module allows Apache to **rewrite URLs dynamically**, often used for redirects or clean URLs.  
Because it manipulates request paths, misconfigurations here can lead to **path traversal or logic bypass issues**.

**mod_proxy**  
This module allows Apache to act as a **proxy or gateway**, forwarding requests to other servers.  
It is commonly used for load balancing or reverse proxying, but if exposed incorrectly, it can allow attackers to reach internal systems.

### Key CEH idea here:

> Apache becomes dangerous not because of its core, but because of **how modules are configured**.

---

## 4️⃣ BMMTM Extensible Agent (don’t overthink this)

This component exists to **monitor and collect transaction data** by intercepting HTTP requests and responses.  
It is mainly used for **performance monitoring and analysis**.

For CEH purposes:

- You do NOT need implementation details
    
- You just need to know it **intercepts traffic for monitoring**
    

If you see:

> “Intercepts HTTP(S) requests for analysis”

That’s what they’re referring to.

---

## 5️⃣ Application Server (important distinction)

The **application server** is **not Apache itself**.

It runs backend code written in languages such as **PHP, Java, or Python**, processes data, and generates dynamic content.

Apache’s role is to:

- forward the request to the application server
    
- receive the result
    
- deliver it back to the client
    

This separation explains why:

- Web server attacks ≠ Web application attacks
    
- Apache compromise ≠ database compromise (but it can lead to it)
    

---

## 6️⃣ Apache Vulnerabilities – how CEH wants you to see them

CEH does **not** expect you to understand the technical exploit mechanics here.  
They want you to understand **categories and outcomes**.

Let’s group these vulnerabilities logically.

---

### A) Input handling & injection problems

**HTTP response splitting**  
This happens when Apache improperly validates input, allowing attackers to inject malicious headers into HTTP responses.  
This can lead to XSS, cache poisoning, or information disclosure.

**SQL injection (in Apache components)**  
This occurs when Apache-related components improperly neutralize SQL elements, allowing attackers to execute arbitrary SQL queries.

**Code injection / environment variable injection**  
These occur when attackers manipulate environment variables or configuration inputs, causing Apache-related services to execute arbitrary code.

👉 CEH angle:

> Improper input validation → injection

---

### B) Memory exhaustion & DoS issues (HTTP/2 focused)

Several vulnerabilities listed are **Denial of Service attacks**, especially related to HTTP/2:

- Memory exhaustion via endless continuation frames
    
- Initial window size set to zero
    
- Memory not reclaimed after stream reset
    

All of these exploit **resource mismanagement**, not authentication or logic.

👉 CEH angle:

> Resource exhaustion → DoS

---

### C) Authentication & authorization failures

**Insecure default configuration**  
Occurs when default admin credentials are left unchanged, leading to remote code execution.

**Improper authorization**  
Occurs when access control checks are faulty, allowing privilege escalation or unauthorized access.

👉 CEH angle:

> Defaults + poor authorization = compromise

---

### D) Path & access control issues

**Path traversal vulnerability**  
Occurs when Apache fails to restrict file paths properly, allowing attackers to access files outside intended directories.

👉 This directly connects to **document root vs server root**, which you learned earlier.

---

### E) Cryptography-related weaknesses

**Improper certificate validation**  
Occurs when SSL/TLS certificates are not validated correctly, enabling man-in-the-middle attacks.

👉 CEH angle:

> Weak TLS handling → MITM

---

## 7️⃣ What CEH REALLY expects you to remember from this chapter

Not exploits.  
Not CVEs.  
Not commands.

They want you to recognize **patterns**.

---

## 🔒 DEFINITIONS TO MEMORIZE (THIS GOES AT THE END)

You were absolutely right about this.

Read these once now — we’ll drill them later.

### Apache Web Server

An open-source HTTP server used to deliver web content over the Internet, capable of serving static and dynamic content through a modular architecture.

### mod_ssl

An Apache module that provides SSL/TLS encryption to secure communication between clients and the web server.

### mod_auth

An Apache module responsible for user authentication and authorization to restrict access to web resources.

### mod_rewrite

An Apache module that enables URL rewriting and redirection based on defined rules.

### mod_proxy

An Apache module that allows the web server to act as a proxy or gateway to forward requests to other servers.

### Application Server

A backend server that executes application logic and generates dynamic content, which is then served to clients through the web server.

### HTTP Response Splitting

A vulnerability caused by improper input validation that allows attackers to inject malicious headers into HTTP responses.

### Path Traversal

A vulnerability that allows attackers to access files and directories outside the intended web directory by manipulating file paths.

### Insecure Default Configuration

A security weakness that occurs when default credentials or settings are left unchanged, enabling unauthorized access.

---

## 🧭 What we do next (important)

You’re doing this **correctly and efficiently**.

Next steps:

1. Finish **Module 13** (we are almost done)
    
2. I’ll give you a **short definition-only recap**
    
3. Then we **immediately move to Module 14 (Web Applications)** — your highest ROI topic
    

When you’re ready, reply with **one line**:

> **Apache section clear – move on**

or

> **Explain ___ one more time**

We stay focused, calm, and efficient.

Perfect feedback — that helps a lot 👍  
Yes, **from now on I’ll always translate diagrams into “request flow stories” in text**, so you can _mentally simulate_ what happens without staring at arrows and boxes.

We’ll continue **chapter by chapter**.  
This reply covers **IIS Web Server Architecture + IIS Vulnerabilities**, explained **slowly, in sentences**, then ends with **definitions to memorize**.

---


## Chapter: **IIS Web Server Architecture**
----------------------------------------
Before details, one important mindset shift:

> **Apache is process/module-centric.  
> IIS is kernel + service + worker-process centric.**

CEH LOVES this distinction.



IIS actually is

**Internet Information Services (IIS)** is Microsoft’s web server platform for Windows.

Unlike Apache (which mostly lives in user space), IIS is tightly integrated with the **Windows operating system**, and part of its request handling happens **inside the Windows kernel**.

IIS supports multiple protocols:

- HTTP / HTTPS
    
- FTP / FTPS
    
- SMTP
    
- NNTP
    

For CEH purposes, IIS is interesting because:

- it splits work between **kernel mode and user mode**
    
- it uses **worker processes (w3wp.exe)**
    
- misconfigurations often lead to **privilege escalation**
    

---

## 2️⃣ IIS architecture — explained as a request story (no diagram)

Let’s walk through **one HTTP request** from browser to response.

### Step 1: Client sends request

A user opens a browser and requests a website hosted on IIS.

That request arrives from the Internet and **does NOT immediately go to the IIS worker process**.

---

### Step 2: HTTP.sys (Kernel mode)

The request is first intercepted by **HTTP.sys**, which is a **kernel-mode driver**.

This is important:

- Kernel mode = **high privilege**
    
- HTTP.sys listens for requests on behalf of IIS
    
- This improves performance but increases impact if vulnerable
    

HTTP.sys does **basic request handling and queuing**, then forwards the request forward.

---

### Step 3: Windows Activation Service (WAS)

HTTP.sys communicates with **Windows Activation Service (WAS)**.

WAS is responsible for:

- Reading configuration data
    
- Deciding _which application pool_ should handle the request
    
- Starting worker processes if they are not already running
    

WAS reads configuration from **ApplicationHost.config**, which is the **main IIS configuration file**.

---

### Step 4: WWW Service

The **World Wide Web Publishing Service (WWW Service)** uses the configuration information provided by WAS and instructs HTTP.sys how to handle requests.

At this stage, IIS knows:

- which website is requested
    
- which application pool it belongs to
    
- which worker process should execute it
    

---

### Step 5: Worker process (w3wp.exe)

WAS now starts or assigns a **worker process**, called **w3wp.exe**, inside an **application pool**.

This worker process runs in **user mode**, not kernel mode.

Inside the worker process:

- the request is processed
    
- authentication happens
    
- application code is executed
    
- logs are written
    
- response is generated
    

---

### Step 6: Response goes back

The generated response flows back:

- from worker process → HTTP.sys
    
- from HTTP.sys → client browser
    

The client receives the webpage.

---

### 🔑 Key idea CEH wants you to remember

> **HTTP.sys handles traffic in kernel mode,  
> w3wp.exe handles execution in user mode,  
> WAS coordinates everything using configuration files.**

---

## 3️⃣ Core IIS components (CEH keywords)

You MUST recognize these names:

- **HTTP.sys** – kernel-mode protocol listener
    
- **WAS (Windows Activation Service)** – manages app pools and configuration
    
- **WWW Service** – controls web publishing
    
- **ApplicationHost.config** – main IIS configuration file
    
- **w3wp.exe** – worker process executing application code
    
- **Application Pool** – isolation boundary for applications
    

Isolation matters because **breaking out of an app pool can lead to system compromise**.

---

## 4️⃣ IIS vulnerabilities — how to understand them (not memorize blindly)

Like Apache, IIS vulnerabilities fall into **patterns**.

We group them.

---

### A) Authentication & authorization failures

**Authentication bypass vulnerability**  
Occurs when IIS incorrectly implements authentication, allowing attackers to access restricted functionality or execute code **without valid credentials**.

**Trust boundary violation**  
Occurs when IIS components fail to properly separate privilege levels, allowing unauthorized entities to access restricted functionality.

👉 Pattern:

> Weak authentication or boundary checks → unauthorized access

---

### B) File & directory access problems

**Arbitrary file path access vulnerability**  
Occurs when default configurations improperly restrict file paths, allowing attackers to browse, enumerate, or traverse directories.

**File and directory permissions vulnerability**  
Occurs when default Windows permissions allow attackers to modify or access files they should not.

👉 Pattern:

> Poor filesystem permission handling → data access or execution

---

### C) Privilege escalation

**Windows IIS server elevation of privilege vulnerability**  
Occurs when IIS improperly handles specific user requests, allowing attackers to gain higher privileges and potentially full system control.

👉 CEH loves this because:

- IIS runs on Windows
    
- Privilege escalation = total compromise
    

---

### D) Input handling & injection issues

**CRLF cross-site scripting (XSS)**  
Occurs when IIS fails to properly sanitize CRLF characters, allowing attackers to inject JavaScript into client responses.

**TYPO3 XSS vulnerability**  
Occurs due to unfiltered input in environment variables such as PATH_INFO.

**XSS in password manager**  
Occurs when user-controllable input is improperly neutralized, allowing script injection.

👉 Pattern:

> Improper input handling → client-side compromise

---

### E) Credential exposure

**CCURE passwords exposed to administrators**  
Occurs when IIS logs or stores sensitive credentials improperly, allowing attackers to retrieve them.

👉 Pattern:

> Sensitive data logged or stored insecurely

---

### F) Mail-related vulnerabilities

**MailEnable vulnerability**  
Occurs when authenticated mail users can upload unsanitized files into public directories, potentially leading to code execution.

👉 Pattern:

> Auxiliary services + poor sanitization = RCE

---

## 5️⃣ What CEH ACTUALLY tests from IIS

They do **NOT** test exploit details.

They test:

- component names
    
- request flow understanding
    
- vulnerability categories
    
- outcomes (RCE, XSS, privilege escalation)
    

---

## 🔒 DEFINITIONS TO MEMORIZE (END SECTION)

Read once now — we’ll drill later.

### IIS (Internet Information Services)

A Microsoft-developed web server platform for Windows that handles HTTP requests using a kernel-mode listener and user-mode worker processes.

### HTTP.sys

A kernel-mode HTTP protocol listener that intercepts and queues HTTP requests before passing them to IIS services.

### Windows Activation Service (WAS)

A service that manages IIS configuration, application pools, and worker process activation.

### Application Pool

An isolation mechanism in IIS that separates applications into distinct worker processes.

### w3wp.exe

The IIS worker process that executes application code and processes HTTP requests in user mode.

### Authentication Bypass

A vulnerability that allows attackers to access restricted functionality without proper credentials.

### Privilege Escalation

A vulnerability that allows attackers to gain higher system privileges than intended.

---

## ✅ Where we are now

You’ve covered:

- Apache architecture & vulnerabilities
    
- IIS architecture & vulnerabilities
    

You’re doing **exactly the right thing** by slowing down _here_ so later modules go faster.

---

### Next step (you choose)

Reply with ONE of these:

- **“IIS clear, move to next chapter”**
    
- **“Explain HTTP.sys vs w3wp.exe once more”**
    
- **“Next chapter please”**
    

We stay structured and calm — you are absolutely on track.

Perfect — this is **exactly** the kind of material CEH expects you to _recognize and recall_, not improvise.  
Below is a **CEH-style, exam-optimized breakdown** of the **Nginx Web Server Architecture**, written in **full sentences**, matching **EC-Council wording**, with **nothing skipped**.

---

# Nginx Web Server Architecture (CEH 312-50)
-----------------------------------------------------------

## 1. Clear Definitions (CEH Style)

**Nginx** is a **high-performance, scalable web server**, reverse proxy, and load balancer that operates on a **master–worker architecture**. It uses a **single-threaded, event-driven, asynchronous, and non-blocking I/O model** to efficiently manage a large number of concurrent client connections.

The **core of the Nginx architecture** consists of a **master process** that controls and manages multiple **worker processes**, which are responsible for handling client requests. This design enables Nginx to achieve high throughput, low memory usage, and efficient resource utilization.

Nginx also supports **advanced load balancing**, **robust caching**, **SSL/TLS termination**, **rate limiting**, **access control**, and **detailed logging**, making it suitable for **high-traffic and mission-critical web applications**.

---

## 2. Architecture Components (Explained Exactly as CEH Expects)

### Master Process

The **master process** in Nginx is responsible for **reading and validating configuration files**, **creating, binding, and closing network sockets**, and **managing worker processes**.

It performs **administrative and control tasks**, such as:

- Starting worker processes
    
- Monitoring their health
    
- Restarting workers when configuration changes occur
    

The master process **does not handle client requests directly**. Instead, it ensures that worker processes are **properly configured and running efficiently**.

---

### Worker Processes

**Worker processes** handle **all client requests** in Nginx. Each worker process:

- Accepts incoming client connections
    
- Reads and writes network data
    
- Communicates with upstream or backend servers
    

Each worker process is **single-threaded** and uses **non-blocking I/O**, allowing it to handle **over 1,000 concurrent connections simultaneously** within an event loop.

After processing a request, the worker process **sends the response back to the client**. Shared memory zones associated with worker processes enable **inter-process communication and data sharing**, such as caching and session state.

---

### Proxy Cache

The **proxy cache** stores **copies of frequently requested content**, reducing backend server load and improving response times.

Instead of forwarding every request to the backend server, Nginx can:

- Retrieve content directly from cache memory
    
- Serve cached responses to clients faster
    
- Reduce latency and server resource consumption
    

This significantly improves performance for **static and frequently accessed resources**.

---

### Cache Loader

The **cache loader** initializes cache data during **Nginx startup**. It:

- Scans cache directories on disk
    
- Loads cache metadata into memory
    
- Ensures cached content is immediately available
    

This allows Nginx to serve cached responses **without delay after startup or reload**.

---

### Cache Manager

The **cache manager** is responsible for **maintaining cache health**. It periodically:

- Checks for expired cache entries
    
- Removes outdated or unused content
    
- Frees storage space to prevent cache overflow
    

The cache manager ensures the cache **does not exceed configured size limits**.

---

### Web Server Component

The **web server component** of Nginx handles **HTTP requests** received from clients. It:

- Serves static content such as HTML, CSS, and images
    
- Forwards dynamic content requests to application servers
    
- Acts as a reverse proxy when required
    

---

### Application Server

The **application server** processes **dynamic requests** by executing server-side scripts or applications. It generates dynamic content and returns responses to the Nginx web server for delivery to the client.

---

### Memcache Server

**Memcache** serves as an **in-memory caching layer** that stores frequently accessed data. It:

- Reduces repeated database queries
    
- Improves response speed
    
- Enhances scalability and performance
    

---

## 3. Communication Flow (Diagram → Text Logic)

1. Clients send HTTP/HTTPS requests to the Nginx server.
    
2. The master process assigns connections to worker processes.
    
3. Worker processes handle requests using non-blocking I/O.
    
4. Requests are either:
    
    - Served directly from the proxy cache, or
        
    - Forwarded to backend servers using HTTP, FastCGI, or Memcache.
        
5. Backend servers process requests and return responses.
    
6. Responses are cached (if applicable) and sent back to clients.
    

---

## 4. CEH Exam Traps (Very Important)

- **Master process does NOT handle client traffic** (workers do).
    
- **Each worker is single-threaded**, not multi-threaded.
    
- **Non-blocking I/O** is the key performance feature.
    
- Nginx **does not support `.htaccess` files** (Apache does).
    
- Cache loader and cache manager are **separate processes**, not features of workers.
    

---

## 5. Obsidian-Ready Summary (Markdown)

```markdown
## Nginx Web Server Architecture

- Uses master–worker architecture
- Master process manages workers and configuration
- Worker processes handle client requests
- Event-driven, asynchronous, non-blocking I/O
- Supports proxy caching, SSL/TLS termination, and load balancing
- Cache loader initializes cache at startup
- Cache manager removes expired cache entries
- Backend includes web, application, and memcache servers
```

---

## 6. MEMORIZE THIS (CEH Checklist)

✅ Master process = configuration + control  
✅ Worker process = client request handling  
✅ Single-threaded + non-blocking I/O  
✅ Proxy cache improves performance  
✅ Cache loader loads metadata at startup  
✅ Cache manager removes expired cache  
✅ No `.htaccess` support in Nginx

---

When you’re ready, send **the next slide or section** (for example: _Nginx vulnerabilities, attacks, or misconfigurations_), and I’ll continue in **the same CEH-accurate style**.