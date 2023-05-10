KQL Queries for Threat Hunting
Super simple KQL queries for threat hunting for malicious activity in an environment with Defender/Sentinel

## Find suspicious PowerShell activity


DeviceProcessEvents | where FileName == "powershell.exe" | where ProcessCommandLine contains "WebClient" | where ProcessCommandLine contains "DownloadFile" | where ProcessCommandLine contains "DownloadData" | where ProcessCommandLine contains "DownloadString" | where ProcessCommandLine contains "WebRequest" | where ProcessCommandLine contains "Shellcode" | where ProcessCommandLine contains "http" | where ProcessCommandLine contains "https"


## Find malicious file downloads

DeviceFileEvents | where FileName contains ".exe" | where ThreatTypes has "Malware"


## Find suspicious logins

DeviceLogonEvents | where LogonType == "LogonType" | where AccountName == "AccountName" | where IPAddress == "IPAddress"


## Find brute force login attempts

DeviceLogonEvents | where FailedAttempts > 5 | where IPAddress == "IPAddress"


## Find lateral movement

DeviceProcessEvents | where InitiatingProcessFileName == "powershell.exe" | where ProcessCommandLine contains "net use" | where ProcessCommandLine contains "copy" | where ProcessCommandLine contains "robocopy" | where ProcessCommandLine contains "xcopy"


## Find data exfiltration

DeviceFileEvents | where DestinationFileName contains ".txt" | where DestinationFileName contains ".csv" | where DestinationFileName contains ".xlsx" | where DestinationFileName contains ".pdf" | where DestinationFileName contains ".docx" | where DestinationIPAddress != "DestinationIPAddress"
These are just a few examples of KQL queries that you could use for threat hunting. There are many other queries that you could create, depending on your specific needs.
I hope this document is helpful. Please let me know if you have any questions.

