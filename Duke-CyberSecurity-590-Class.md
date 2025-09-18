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
