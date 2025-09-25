# CYBERSEC 590 – Master Program  
**Ethical Hacking in CyberSecurity Operations**  
CompTIA Pentest+  

⚠️ **Do not hack computer systems you are not authorized to use or use them in ways that are not authorized**  

Professor: *Ryan Linn*  

---

##  Useful Links

1. [Metasploit Console Commands – OffSec](https://www.offsec.com/metasploit-unleashed/msfconsole-commands/)  
2. [Comprehensive Guide on Dirb Tool – HackingArticles](https://www.hackingarticles.in/comprehensive-guide-on-dirb-tool/)  
3. [Nikto Cheat Sheet – HighOn.Coffee](https://highon.coffee/blog/nikto-cheat-sheet/)  
4. [Kali Linux](https://www.kali.org/)  
5. [Ettercap Project](https://www.ettercap-project.org/about.html)  
6. [Windows CMD Commands Cheat Sheet – Serverspace](https://serverspace.io/support/help/windows-cmd-commands-cheat-sheet/)  
7. [Linux Commands Cheat Sheet – LinuxTrainingAcademy](https://www.linuxtrainingacademy.com/linux-commands-cheat-sheet/)  
8. [DNS Hijacking](https://www.sentinelone.com/cybersecurity-101/threat-intelligence/dns-hijacking/)
9. [Reponder Sniffer](https://www.kali.org/tools/responder/)
10. [Burp - Intercept HTTP traffic](https://portswigger.net/burp/documentation/desktop/getting-started/intercepting-http-traffic)
11. [Windows Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
12. [Windows Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
13. [Enum4Linux](https://www.kali.org/tools/enum4linux/)
14. [SMBMap](https://www.kali.org/tools/smbmap/)
15. [Wmic](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic)
16. [Mimikatz](https://www.varonis.com/blog/what-is-mimikatz)
17. [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
18. https://github.com/GhostPack/SafetyKatz
19. [Lolbas Living Off The Land Binaries ](https://lolbas-project.github.io/)
20. [Windows privilege escalation](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)
21. [Linux Privilege Escalation](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) 
22. [WMI](https://attack.mitre.org/techniques/T1047/)
23. https://github.com/GhostPack/Seatbelt
24. https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
25. https://dev.to/saravana_gautham_g/abusing-lolbins-rundll32exe-lab-sysmon-detection-170h
26. https://github.com/aniqfakhrul/powerview.py
27. https://github.com/tevora-threat/SharpView
28. https://github.com/GhostPack/Rubeus
29. https://github.com/GhostPack/SharpUp
30. https://owasp.org/
31. https://www.sans.org/tools
32. https://github.com/fortra/impacket
33. https://powersploit.readthedocs.io/en/latest/
34. https://attack.mitre.org/
35. https://github.com/redcanaryco/atomic-red-team
36. https://en.wikipedia.org/wiki/List_of_file_signatures
---

##  Tasks  

### 🔍 nmap  

**Goal:** Map the network, identify active hosts, open ports, and potential vulnerabilities.  

1. Find your machine’s IP address:  
   ```bash
   ip a
   ```

2. Scan your network:  
   ```bash
   nmap <Kali_IP_Address/segment_class>
   ```
   → *Question:* How many machines were found with open ports?  

3. Scan the main server:  
   ```bash
   sudo nmap -sS -sV -A <Machine_IP>
   ```
   → *Question:* What is the type and version of SSH used?  

4. Check SSH authentication methods:  
   ```bash
   sudo nmap -sS -sV -A <Any_linux_machine_name> --script ssh-auth-methods
   ```
   → *Question:* Which authentication methods are allowed?  

5. Check for Slowloris vulnerability:  
   ```bash
   nmap <linux_webserver_machine> --script http-slowloris-check
   ```
   → *Question:* What is the vulnerability CVE?  

---

### 📂 Dirb  

**Goal:** Enumerate hidden pages and directories in websites.  

- Search for specific extensions:  
  ```bash
  dirb url -X php
  ```

- Basic scan:  
  ```bash
  dirb http://exploit.local
  ```
  → *Default wordlist used:*  
  `/usr/share/dirb/wordlists/common.txt`  

- Scan with vulnerability wordlist:  
  ```bash
  dirb http://techportal.local /usr/share/dirb/wordlists/vulns/cgis.txt
  ```

- Ignore HTTP 400 errors:  
  ```bash
  dirb url -N 400
  ```

- Ignore errors and search for `.php` pages:  
  ```bash
  dirb url -N 400 -X php
  ```

---

### 🌐 Nikto  

**Goal:** Scan web servers and identify known vulnerabilities.  

1. Quick help:  
   ```bash
   nikto -H
   ```

2. Main flags:  
   - Set target: `-url` or `-host`  
   - Exclude tests: `-Tuning`  

3. Basic scan:  
   ```bash
   nikto -url website_name
   ```
   → *Question:* Which software is outdated?  

4. Scan multiple hosts (from a file) and specific ports:  
   ```bash
   nikto -h /home/cyberuser/hostlist.txt -p 8080,443
   ```
---

### Metasploit 

msfconsole
use auxiliary/scanner/smb/smb_version
show targets
show payloads
show options

meterpreter 
 

---

### Wireshark

Create a filter that captures all traffic associated with IPv4 address 192.168.66.20. 
ip.addr == 192.168.66.20

How many packets use port 53 as a destination port? Consider both TCP and UDP packets.
tcp.dstport == 53
udp.dstport == 53

What is the correct syntax for running a query that displays all packets using a source IP of 192.168.200.1, excluding ICMP packets?
ip.addr==192.168.200.1 and !icmp

 filter that displays all TCP packets with an SYN flag set to 1
 tcp.flags.syn == 1

 Which of the following filtering queries should be used for viewing email traffic, smaller or equal to 128 bytes per packet?
 
frame.len <= 128 and (smtp or pop or imap)

What is the number of the first DNS Response packet associated with the DNS Request packet marked by number 414?

Each packet in a transport stream is identified by a 13-bit packet identifier (PID).
To find the packet ID value, locate the DNS request packet by its frame number (No. value) of 414.
Using the id value shown in the initiated request (id=0x7831), look for the corresponding DNS response packet.

To locate the response packet using the display filter, filter by the associated transaction id- 'dns.id==0x7831'.
This filter will show all packets associated with this id value (queries and response packets).
Viewing these results, look for the first response packet frame number (No. value).

### Reponder

By scanning the systems in the network, it is possible to receive helpful information regarding potential targets, such as SMB signing not required, which allows an attacker to perform a man-in-the-middle attack by relaying captured credentials from one system to another.

Run the sudo python `/usr/share/responder/tools/RunFinger.py -i 10.233.20.0/23` command.

Responder can be used in active or passive mode.

Active mode means actively manipulating the data. It could "break" the network by responding to requests and broadcasts, which could resolve authentication popups to network users that eventually could raise an alarm.

Passive mode is monitoring and analyzing the network traffic, capturing the relevant data and relaying it to other systems, attempting to crack password hashes, or using clear text passwords.

Run the sudo `python /usr/share/responder/Responder.py -h`  command.

Which option prevents the responder from running in active mode?

`-A`

Like other sniffing tools, responder constantly sniffing the network requests and broadcasts. In this question you will use the responder in active mode.

Run responder using the `sudo python /usr/share/responder/Responder.py -wfrP -I eth0`

##### windows

The first enumeration stage is to scan the network and identify the Windows systems in your environment. 
Run the ip a command to identify your IP address and network segment.
Using ports 445 and 389 can assist in identifying the Windows servers.
Next, run the nmap --open -p445,389 <attacker_machine_IP/segment_class> command.

SMB signing is a security mechanism in Windows that ensures the authenticity and integrity of communications between clients and servers using the Server Message Block protocol. When SMB signing is not "enabled and required", it can be exploited.
This question will give you more information about the Windows machine SMB signing status using nmap scripts.
Run the nmap --open -p445 <attacker_machine_IP/segment_class> --script smb2-security-mode command.
Attackers can exploit SMB signing vulnerabilities to launch man-in-the-middle attacks and gain unauthorized access to data transmitted over SMB connections, allowing them to execute malicious code and steal sensitive information.

At the beginning of the lab, you performed a network scan and identified a domain controller (the machine that uses port 389 is the most probable machine, checking for other available ports will confirm it).
Identifying user accounts is valuable when searching for information during an attack; it can be used for information gathering, login attempts, impersonation, and manipulation.
The "-U" option will provide information on the user accounts.
Run the enum4linux -u <username> -p <password> -U <domainController> command. and review the output.


Identifying the users with high privileges will enable attackers to focus on them to achieve a system takeover. 
Using the "-G" option will provide information on group members.
Run the enum4linux -u <username> -p <password> -G <domainController> | grep "Domain Admins" command.

The Windows password policy can contain various settings and requirements, such as minimum password length, complexity requirements, password expiration, password history, account lockout thresholds, and more. These settings are designed to help protect against common password-based attacks and ensure the security of user accounts and data.
Using the "-P" option will provide information on the domain's password policy.
Run the enum4linux -u <username> -p <password> -P <domainController> command.



Metasploit is a powerful tool to scan, enumerate, and exploit systems.
Run the msfconsole command to start the Metasploit framework.
Next, select the module by using the `use exploit/windows/smb/psexec` command.
Configure the module with the following parameters:
`set rhosts <fs-xxxxx_name_or_IP_address>
set smbuser <username>
set smbpass <password>
set smbdomain stark
exploit`
Next, run the `shell` command in the "Meterpreter" command line.
Now, run the `wmic product get name,installdate` command to get the installed software.


Security updates for Windows are crucial for securing the operating system.
Missing security updates could indicate that the server is vulnerable and could be compromised.
While still in the shell session you created in the previous question, examine the installed updates by running the `wmic qfe get Caption, Description, HotFixID, InstalledOn` command.
The "get" option lets you select which columns will be presented.

Smbmap is a command-line tool used to enumerate and discover open SMB (Server Message Block) shares on Windows and Linux systems.
Open an additional terminal tab and run the smbmap -H <domainController> -u <username> -p password>  command.
Which folder has Read/Write permissions?

Smbclient is a command-line tool to access and manage files, printers, and other resources on a remote SMB/CIFS (Server Message Block/Common Internet File System) server.
To create an smb shell on the server, run the smbclient //<domainController>/<shared_folder> -U <username> '<password>' command.
Next, use the dir command to view the file list and run the get <file_name> command to download it to the Kali machine.
Now, run the exit command to return to the Kali, and next run the cat <file_name> to view its content.
What is the password in the file?

Windows
sysinfo
getuid
getsystem
hashdump (and CrackMapExec)

whoami /priv


Linux
psexec
RDP Tunneling
netsh interface portproxy

