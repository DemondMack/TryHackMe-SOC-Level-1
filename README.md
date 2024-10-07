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
<br />
CTI Tools:  <br/>
<img src="https://i.imgur.com/J4blpIn.jpeg" height="25%" width="25%" />
<img src="https://i.imgur.com/auY89pd.jpeg" height="25%" width="25%" />
<img src="https://i.imgur.com/xqD9z7R.jpeg" height="25%" width="25%" />
<img src="https://i.imgur.com/q3diFsB.jpeg" height="25%" width="25%" />
<p>Learned about key cyber threat analysis tools like Urlscan.io and Abuse.ch, which assist in scanning, analyzing, and tracking malicious websites, malware, and botnets. Urlscan.io automates the analysis of URLs to identify IPs, domains, and redirects, while Abuse.ch provides platforms such as MalwareBazaar and Feodo Tracker to share and track malware samples and botnet C2 infrastructures. Additionally, explored PhishTool for email analysis, uncovering phishing indicators, and Cisco Talos Intelligence for investigating threat indicators, vulnerabilities, and email traffic patterns to enhance threat detection and prevention.</p>
<br />
<br />
<br />
Windows Server seperated from VPC:  <br/>
<img src="https://i.imgur.com/o2grXTy.jpeg" height="80%" width="80%" />
<p>Deployed a Windows Server 2022 on Vultr using the shared CPU option. The server was set up without being part of the Virtual Private Cloud (VPC) to isolate it from other critical infrastructure. Configured the server and verified Remote Desktop Protocol (RDP) access to ensure it's exposed to the internet. The server will start generating logs for future analysis of unsuccessful login attempts.</p>
<br />
<br />
<br />
Fleet Server with Elastic Agent and Windows Server enrolled:  <br/>
<img src="https://i.imgur.com/uXz0c3B.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/ypcURGK.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/T5iRfce.jpeg" height="80%" width="80%" />
<p>Deployed an Ubuntu server to act as the Fleet Server in the cloud and configured it to manage agents centrally. Installed and configured the Elastic Agent on the Fleet Server and addressed connection issues by adjusting firewall rules for both the Fleet Server and Elasticsearch (port 9200 and 8220). Successfully enrolled the Windows Server into the Fleet, allowing for system logs and metrics collection. Finally, captured initial authentication logs from the Windows server, verifying the setup.</p>




<br />
<br />
Sysmon installation:  <br/>
<img src="https://i.imgur.com/MlnUpcj.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/KcM0yLC.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/NLHMqsW.jpeg" height="80%" width="80%" />
<p>Installed and configured Sysmon on the Windows Server. Downloaded Sysmon from Microsoft Learn and retrieved a popular configuration file from GitHub. Using PowerShell, installed Sysmon as a service and confirmed its successful setup by checking the Windows Event Viewer for Sysmon logs. Verified that Sysmon was capturing network connections and generating logs for further monitoring.</p>
<br />
<br />
<br />
Intergrated Sysmon & Microsoft Defender:  <br/>
<img src="https://i.imgur.com/9FOaHUI.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/rOaZ4Js.jpeg" height="80%" width="80%" />
<p>Added integrations for Sysmon and Microsoft Defender into the Elasticsearch instance, allowing the collection of logs from custom Windows Event channels. Configured specific event IDs for ingestion, such as 1116, 1117, and 50001, for more targeted logging. Troubleshooting included ensuring connectivity between agents and Elasticsearch by allowing incoming connections on port 9200. Verified Sysmon and Defender logs were successfully ingested into the instance.</p>
<br />
<br />
<br />
Ubuntu SSH server Authentication Logs:  <br/>
<img src="https://i.imgur.com/ZgyesUv.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/SzLhOqG.jpeg" height="80%" width="80%" />
<p>Deployed an Ubuntu server on Vultr for monitoring SSH authentication logs. Configured the server, updated repositories, and used PowerShell to SSH into the instance. Accessed authentication logs in /var/log/auth.log to identify failed login attempts, specifically filtering for failed root login attempts. Used the grep and cut commands to extract and display the failed login IP addresses. Prepared the server for monitoring failed brute-force attacks and planned to install the Elastic Agent for log forwarding to Elasticsearch.</p>
<br />
<br />
<br />
Alert & Dashboard creation for SSH activity:  <br/>
<img src="https://i.imgur.com/Pe2DPyq.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/9TMIaOU.jpeg" height="80%" width="80%" />
<p>Ingested logs from the SSH server into Elasticsearch and queried for brute force activity by filtering logs based on agent name, user, and source IP to identify failed authentication attempts. Saved the search as "SSH Failed Activity" and created an alert for brute force attempts, setting thresholds to trigger the alert when more than five failed login attempts occur within five minutes. Additionally, created a dashboard in Elasticsearch Maps to visualize the geographic source of these attempts using the source IP’s geolocation. Duplicated the dashboard to track successful SSH authentication attempts. This setup allows for both alerting on brute force activity and monitoring the source of the attacks in real time.After successfully ingesting logs from our SSH server into the Elasticsearch instance, the next step was to do the same for the RDP server. By filtering for event ID 4625, which represents failed login attempts, we identified multiple failed authentications. Key fields such as source IP and username were added to the table for detailed monitoring. A saved search, "RDP Failed Activity," was created to track these events.

To further strengthen monitoring, an alert for RDP brute force attempts was created, similar to the SSH brute force alert. This alert was configured to trigger after five failed login attempts within five minutes. Finally, a dashboard was developed for visualization, allowing for easy tracking of where these attacks are originating.
This process emphasizes the importance of securing exposed services such as SSH and RDP by ensuring strong passwords, multi-factor authentication (MFA), and limited access, as they are prime targets for brute force attacks.</p>

<br />
<br />
<br />
Attack Diagram: <br/>
<img src="https://i.imgur.com/5z9BUMl.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/cHHsWah.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/BpgyWXU.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/U0typtC.jpeg" height="80%" width="80%" />
<p>Created an attack diagram using draw.io to map out a cyber attack involving a Mythic C2 server, Windows server, and an attacker laptop running Kali Linux. The process included six phases: RDP brute force for initial access, running discovery commands, disabling Windows Defender for defense evasion, downloading and executing a Mythic agent via PowerShell for execution, establishing a C2 session, and exfiltrating a fake password file (passwords.txt). This diagram served as a visual guide for planning and executing the attack path in a controlled environment. Now it's time to attack!!!</p>
<br />
<br />
<br />


Mythic Server Intialization: <br/>
<img src="https://i.imgur.com/F70KHGl.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/6tEEO0V.jpeg" height="80%" width="80%" />
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


