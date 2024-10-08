<h1>TryHackMe SOC Level 1</h1>


<h2>Description</h2>
Gained practical experience in critical SOC functions through hands-on labs, focusing on the implementation and analysis of security frameworks, threat intelligence, network traffic, and endpoint monitoring.
<br />


<h2>Languages and Utilities Used</h2>

- <b>Wireshark</b> 
- <b>Snort</b>
- <b>Zeek</b>
- <b>TShark</b>
- <b>Sysmon</b>
- <b>Windows Event Logs</b>
- <b>Osquery</b>
- <b>Wazuh</b>
- <b>Splunk</b>
- <b>ELK Stack (Elasticsearch, Logstash, Kibana)</b>
- <b>Autopsy</b>
- <b>Redline</b>
- <b>KAPE</b>
- <b>Volatility</b>
- <b>OpenCTI</b>
- <b>MISP</b>
- <b>Yara</b>

<h2>Environments Used </h2>

- <b>Virtualized Labs</b>
- <b>Windows Systems (for endpoint security and forensic analysis)</b>
- <b>Linux Systems (for forensic analysis and network traffic monitoring)</b>
- <b>Cloud-based Threat Intelligence Platforms (MISP, OpenCTI)</b>
- <b>Simulated SOC Environments for incident response and SIEM tasks</b>
- <b>Network Traffic Analysis Environments (Snort, Zeek, Wireshark, TShark)</b>
- <b>Digital Forensics Labs (Autopsy, Redline, KAPE, Velociraptor)</b>

<h2>Frameworks:</h2>

<p align="center">
Pyramid Of Pain: <br/>
<img src="https://i.imgur.com/HsvyzIw.jpeg" height="50%" width="50%" />
<br/>          
<br/> 
<p>Learned to apply key cyber defense frameworks such as the Pyramid of Pain, MITRE ATT&CK, Cyber Kill Chain, and Unified Kill Chain to enhance threat detection, incident response, and threat hunting capabilities. Gained insights into the significance of different Indicators of Compromise (IOCs), such as hashes, IP addresses, domain names, and artifacts, in hindering adversaries' attack strategies. Also explored how advanced techniques like Fast Flux and User-Agent strings are used by attackers to evade detection.</p>  
<br />
<br />
Cyber Kill Chain:  <br/>
<img src="https://i.imgur.com/7w6Ib1z.jpeg" height="70%" width="70%" />
<p>Learned the phases of the Cyber Kill Chain, a framework used to understand and defend against cyber attacks such as ransomware, breaches, and APTs. Explored each stage of an attack, from reconnaissance and weaponization to delivery, exploitation, and command and control (C2). Gained insights into techniques like phishing, USB drops, and zero-day exploits, as well as how attackers maintain persistence and move laterally through networks. Learned how defenders can recognize and disrupt attacks at various stages to prevent adversaries from achieving their objectives.</p>
<br />
<br />
<br />
MITRE ATT&CK: <br/>
<img src="https://i.imgur.com/U12b95Q.jpeg" height="80%" width="80%" />

<p>Gained an understanding of the MITRE Corporation’s cybersecurity contributions, including the ATT&CK® framework, which maps adversary TTPs (Tactics, Techniques, and Procedures) to real-world attacks. Explored additional MITRE resources such as the Cyber Analytics Repository (CAR), ENGAGE for adversary deception, and D3FEND for mapping countermeasures. Learned how these tools help defenders detect and respond to threats, simulate adversary behavior, and improve security postures through threat-informed defense strategies.</p>

<h2>Threat Intelligence:</h2>


Cyber Threat Intel Process: <br/>
<img src="https://i.imgur.com/0fHt5Xc.jpeg" height="50%" width="50%" />
<p>Learned the fundamentals of Cyber Threat Intelligence (CTI), including the collection, processing, and analysis of data to identify adversaries, their tactics, and indicators of compromise. Explored the four main types of threat intelligence—strategic, technical, tactical, and operational—used to inform security teams and enhance decision-making. Gained insights into the CTI lifecycle, from defining objectives and collecting data to processing, analyzing, and disseminating actionable intelligence to stakeholders. Also reviewed industry standards and frameworks such as MITRE ATT&CK, STIX, and the Cyber Kill Chain for organizing and sharing threat intelligence.</p>
<br />
<br />
CTI Tools:  <br/>
<img src="https://i.imgur.com/J4blpIn.jpeg" height="25%" width="25%" />
<img src="https://i.imgur.com/auY89pd.jpeg" height="25%" width="25%" />
<img src="https://i.imgur.com/xqD9z7R.jpeg" height="25%" width="25%" />
<img src="https://i.imgur.com/q3diFsB.jpeg" height="25%" width="25%" />
<p>Gained proficiency in cyber threat analysis tools like Urlscan.io and Abuse.ch for scanning and tracking malicious websites, malware, and botnets. Explored PhishTool for email phishing detection and Cisco Talos Intelligence for analyzing threat indicators and vulnerabilities.

Developed skills in YARA, creating rules for malware detection through pattern matching and integrating it with tools like Cuckoo Sandbox. Additionally, explored key CTI platforms such as OpenCTI and MISP for managing, analyzing, and sharing threat intelligence. These platforms integrate with tools like TheHive and leverage frameworks like MITRE ATT&CK to support malware analysis and threat investigations across trusted communities.</p>

<h2>Network Security and Traffic Analysis:</h2>


Wireshark:  <br/>
<img src="https://i.imgur.com/pRK5xrn.jpeg" height="50%" width="50%" />
<img src="https://i.imgur.com/6FlrcPE.jpeg" height="80%" width="80%" />
<p>In Wireshark, I used the Statistics menu to analyze traffic patterns and key details like resolved addresses, protocol hierarchy, conversations, and endpoints to identify significant network events. By applying capture and display filters, I filtered traffic based on IP, TCP, UDP, HTTP, and DNS to isolate relevant packets. Advanced filters such as contains, matches, and in were used to refine searches for specific strings, ports, and packet types. I also utilized features like bookmarks, filter buttons, and profiles for efficient reuse of complex filters during network traffic investigations.</p>
<br />
<br />
Snort:  <br/>
<img src="https://i.imgur.com/2G7j9vD.jpeg" height="50%" width="50%" />
<img src="https://i.imgur.com/H7T92bu.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/CZXJ78Z.jpeg" height="80%" width="80%" />
<p>I used Snort to analyze network traffic, detect ICMP packets, and apply custom rules for threat detection. By running Snort in Sniffer, Logger, and IDS/IPS modes, I monitored live traffic, generated alerts, and logged packets for deeper analysis, demonstrating its key functionality in identifying and preventing malicious activity in a network environment.</p>
<br />
<br />
Zeek:  <br/>
<img src="https://i.imgur.com/TPvb4Md.jpeg" height="50%" width="50%" />
<img src="https://i.imgur.com/VnCltZ3.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/g710ZHf.jpeg" height="80%" width="80%" />
<p>I utilized Zeek as a powerful network monitoring tool to analyze network traffic and generate detailed logs for security investigations. By processing pcap files and using Zeek's logging capabilities, I was able to gain deep visibility into network activity, focusing on identifying anomalies, protocol usage, and traffic patterns. I leveraged Zeek's extensive logging, such as connection and protocol-specific logs, to investigate potential security incidents. Additionally, I utilized command-line tools like zeek-cut to extract relevant data from logs and applied custom scripts to automate event correlation and streamline my analysis process.</p>
<br />
<br />
Tshark:  <br/>
<img src="https://i.imgur.com/SfFiTYH.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/mGw0SUS.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/NJ6USna.jpeg" height="80%" width="80%" />
<p>I used TShark, the command-line version of Wireshark, to analyze network traffic by filtering, capturing, and processing packets. TShark's flexibility allowed me to perform in-depth analysis and automate tasks via command-line tools like capinfos, grep, and cut. I leveraged capture and display filters for live and post-capture analysis, using the -f parameter for capture filters and -Y for display filters to narrow down traffic efficiently. Additionally, I utilized options such as -r to read pcap files, -w to write output, and -x for detailed hex and ASCII views of packets. TShark provided a streamlined, efficient way to analyze packets and automate repetitive tasks in network investigations.</p>

<h2>Endpoint Security Monitoring:</h2>


Sysinternals:  <br/>
<img src="https://i.imgur.com/ZsJEkqV.jpeg" height="80%" width="80%" />
<p>I used Sysinternals tools like TCPView for monitoring network connections, Process Explorer for analyzing running processes, and Autoruns to check for suspicious startup entries. These tools helped streamline system analysis and enhance threat detection.</p>
<br />
<br />
Sysmon:  <br/>
<img src="https://i.imgur.com/JwzeLPk.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/vbHJklz.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/5nrebYL.jpeg" height="80%" width="80%" />
<p>I used Sysmon to monitor key events like Process Creation (Event ID 1), Network Connection (Event ID 3), Image Load (Event ID 7), and others to detect anomalies such as suspicious processes, DLL injection, and unauthorized access attempts. By leveraging Sysmon with well-configured rulesets, I filtered out noise and focused on actionable alerts, forwarding them to SIEM for further analysis and investigation.</p>
<br />
<br />
osquery:  <br/>
<img src="https://i.imgur.com/OxQIAkk.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/RWqfQHF.jpeg" height="80%" width="80%" />
<p> I used Osquery's interactive mode to query the system, exploring tables and schemas, filtering results with SQL queries, and joining tables to gather specific insights on processes, users, and other system behaviors. This flexible querying aids in incident response and threat hunting tasks.</p>
<br />
<br />
Wazuh: <br/>
<img src="https://i.imgur.com/m9XdoeT.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/fCGPwkc.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/U0cPhuY.jpeg" height="80%" width="80%" />
<p>I used Wazuh, an open-source EDR solution, to monitor endpoint activity and detect security threats across Windows and Linux systems. By deploying agents, I collected logs on processes like authentication, file access, and vulnerabilities, using Wazuh's rule-based alerts to identify suspicious events. I integrated Sysmon to track key system processes and enhanced detection. Additionally, I leveraged Wazuh’s API for retrieving data and generating reports, enabling detailed analysis of security events.</p>

<h2>Security Information and Event Management:</h2>


ELK Stack: <br/>
<img src="https://i.imgur.com/tF6nIEA.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/oQ9nMhp.jpeg" height="80%" width="80%" />
<p>I used the ELK stack (Elasticsearch, Logstash, Kibana) to analyze VPN logs, identifying anomalies like failed login attempts and unauthorized access. Using Kibana’s Discover tab and KQL, I filtered and searched logs by user, IP, and time. I also created visualizations to highlight patterns, such as failed connections from specific countries, improving my ability to investigate and monitor network security events efficiently.</p>
<br />
<br />

Brute Force process: <br/>
<img src="https://i.imgur.com/pDtFS5s.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/fBvF9hv.jpeg" height="80%" width="80%" />
<br />
C2 connection Established: <br/>
<img src="https://i.imgur.com/OBrvihs.jpeg" height="80%" width="80%" />
<br />
File Downloaded from host: <br/>
<img src="https://i.imgur.com/Ry8Qbqk.jpeg" height="80%" width="80%" />
<p>I deployed a Mythic C2 server using Vultr and configured it with Docker and Kali Linux. The attack involved brute forcing an RDP login on a Windows server, performing discovery commands, disabling Windows Defender, and executing a Mythic agent generated with a C2 profile. The agent was downloaded via PowerShell, establishing a C2 connection. Using the active session, I exfiltrated a fake password file (passwords.txt) from the Windows server. This process demonstrated the complete attack path, from initial access to exfiltration, using Mythic C2 and Kali Linux.</p>
<br />
<br />
The next steps in this project is the investigation: <br/>
<br />
<br />
<br />
Query for Process Creation(event code:1) & Original file name(Apollo.exe): <br/>
<img src="https://i.imgur.com/L80hlDC.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/77UWFgc.jpeg" height="80%" width="80%" />
<br />
Alert created for Mythic/Apollo agent: <br/>
<img src="https://i.imgur.com/x9HsLVg.jpeg" height="80%" width="80%" />
<br />
Suspicious activity dashboard: <br/>
<img src="https://i.imgur.com/VLRO2zS.jpeg" height="80%" width="80%" />
<p>I created an alert in Elastic for Mythic C2 activity by querying logs for our service host executable and correlating Sysmon event codes. First, I searched for process creation events (event code 1) and extracted the SHA-256 hash and original file name (Apollo.exe). Then, I used these fields to build a query and alert that triggers on process creation involving the Apollo agent. Finally, I created a custom dashboard that monitors suspicious activity, including process creation events for PowerShell and CMD, network connections, and Defender being disabled, offering at-a-glance insights into potentially malicious activity.</p>
<br />
<br />
<br />
Ticketing system: <br/>
<img src="https://i.imgur.com/YAkU8Yr.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/R7YriON.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/e2xwm2E.jpeg" height="80%" width="80%" />
<br />
Elastic Defender: <br/>
<img src="https://i.imgur.com/jYip6R0.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/IhA8ukM.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/htj8pnY.jpeg" height="80%" width="80%" />
<p>The setup process started with osTicket, where a Windows server was deployed, and XAMPP was installed to host the osTicket instance. Configuration included editing Apache and PHP settings, creating databases, and setting firewall rules for web server security. osTicket was then integrated with Elasticsearch using an API key, enabling automatic ticket generation for alerts.

Next, the investigation of SSH brute force attacks was demonstrated by querying Elasticsearch for specific IPs and users involved in the attacks. Tools like AbuseIPDB and GreyNoise were used to assess the threat level of the IPs. Similar methodologies were applied to RDP brute force investigations, where IP reputation was checked, and failed/successful login attempts were analyzed.

The investigation of Mythic C2 focused on process creation and network connections. Sysmon telemetry and process GUIDs were used to track C2 agent behavior, file creations, and outbound connections, particularly for the agent named servicehost.exe. Powershell commands and network connections were analyzed to understand the C2 activity timeline.

Lastly, Elastic Defend (Elastic's EDR solution) was installed to monitor and protect endpoints. The tool blocked malicious files like mydfir-30.exe, provided detailed telemetry (file hashes, paths, etc.), and isolated compromised hosts. Elastic Defend's features, such as real-time detection and prevention, were highlighted, along with host isolation.</p>
<br/>
<br/>
<b>Conclusion<b> <br />
<p>Throughout this project, I demonstrated a range of essential SOC analyst skills, including setting up and managing tools for logging, monitoring, and incident response. By integrating ELK with OS Ticket, I created an efficient alert-to-ticketing system, streamlining incident management. I also successfully orchestrated a combination of host-based and network telemetry monitoring to detect, analyze, and respond to potential threats. Overall, this project highlights my technical expertise in creating a comprehensive SOC environment, demonstrating strong investigative techniques, threat detection, and response capabilities essential for maintaining network security.</p>


