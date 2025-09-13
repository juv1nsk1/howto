### CyberSecuirty - Ethical Hacking

# Links

1. Comprehensive Guide on Dirb Tool
https://www.hackingarticles.in/comprehensive-guide-on-dirb-tool/

2. Nikto open-source web server scanner that performs comprehensive tests
https://highon.coffee/blog/nikto-cheat-sheet/


Windows CMD Commands Cheat Sheet
https://serverspace.io/support/help/windows-cmd-commands-cheat-sheet/

Linux Commands Cheat Sheet
https://www.linuxtrainingacademy.com/linux-commands-cheat-sheet/
# Tasks

## nmap

Network scanning starts by identifying your current segment and subnet and searching for devices that are connected to the network.
Identify your ethernet IP address using the ip a command.
Next, scan your network using the 

```nmap <Kali_IP_Address/segment_class>``` 

How many machines were found to have opened ports?
Network scans can provide much more information when using the proper variables.
Identify the IP address of a machine named "MainServer" and run the 

```sudo nmap -sS -sV -A <Machine_IP>``` 

Scan using the ```sudo nmap -sV <web-server_IPaddress>``` 
What is the type and version of the ssh used?


Network scanning tools like nmap use scripts that can assist with the scan and provide even more details.
Run the 

```sudo nmap -sS -sV -A <Any_linux_macine_name> --script ssh-auth-methods``` 

According to the received output, which authentication methods are allowed?

Network scanning with nmap can also provide you with information regarding vulnerabilities that might exist in the scanned machine.
Run the 

```nmap <linux_webserver_machine> --script http-slowloris-check```

According to the output, what is the vulnerability CVE?


## Dirb

The dirb tool is used to scan websites and identify web pages. During a scan, some hotkeys can perform actions while the scan is running.

Run the dirb command.

Review the help menu.

Which of the following options can be used to search for specific file extensions?    ```-X```

Scanning a website requires only one setting: the website address.

A wordlist that the dirb will use against the website for enumeration, vulnerabilities, or else. If not configured, a default wordlist will be used, which contains a list of words used for webpage enumeration.

Run the dirb http://exploit.local command and review the output.

What is the default wordlist file that is being used?

```/usr/share/dirb/workdlists/common.txt```

Wordlists can be used for multiple actions. They can be used for web page scanning, brute force attacks, vulnerability scanning, and more.

Rerun the dirb http://techportal.local only this time use the "/usr/share/dirb/wordlists/vulns/cgis.txt" wordlist, which can identify vulnerabilities in cgi pages.

As mentioned, the dirb command provides HTTP response codes, which can provide much useless information, as seen in the previous question. Still, it can also filter unwanted codes to minimize the output.

Rerun the previous command; this time, add the option to ignore all HTTP bad requests (Code 400).

```dirb url -N 400```

The dirb command can also search for specific extensions that might be vulnerable or accessible by an attacker.

Run the scan you performed in the previous question and add the option to search for pages with the  "php"  extension.

```dirb url -N 400 -X php``` 


## Nikto

 ````nikto -H ``` 

Which two flags can be used to set the target website?

```-url -host```

How can you exclude specific tests from a Nikto scan? 

How can you exclude specific tests from a Nikto scan? 

```- tuning```

Nikto can provide information on the Server the website is running on.

Run the nikto ```-url website_name ```

Nikto can also provide information on the web server software when available.
Review the output of the scans. Which of the following software is outdated?

You can also use a file containing web server names or IP addresses to scan multiple sites.

Use the /home/cyberuser/hostlist.txt file for the scan and the -p flag to scan ports 8080 and 443.

```-h file -p 8080,443```



