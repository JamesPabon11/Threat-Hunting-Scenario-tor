

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/JamesPabon11/Threat-Hunting-Scenario-tor/blob/main/Threat-Hunting-Scenario-tor)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any file that had the string “tor” in it and discovered what looks like user “Employee” downloaded a tor installer and browser, that resulted in many tor related files being copied to the desktop and creation of a file called “tor-shopping-list”. 

Query used to locate events: 

<img width="1031" height="241" alt="image" src="https://github.com/user-attachments/assets/2cc6deea-1a3a-495b-b315-c80ea5bae5cf" />

<img width="1247" height="560" alt="image" src="https://github.com/user-attachments/assets/097f6f59-a95f-4d2b-94f9-b509a8d0e2eb" />




---


### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor.exe". Based on the logs returned, an employee on the "threathuntfinal" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

<img width="1585" height="236" alt="image" src="https://github.com/user-attachments/assets/38316d27-a5a8-4977-8616-b38263945df8" />


<img width="1674" height="335" alt="image" src="https://github.com/user-attachments/assets/c9902c25-4a11-4410-bd80-0eb79e61616d" />

Tor-browser-windows-x86_64-portable-15.0.11.exe installation at 2026-05-04T17:46:12.182745Z The file name is the standard, official installer for the Tor Browser on Windows.

<img width="1690" height="474" alt="image" src="https://github.com/user-attachments/assets/0f02f457-7ba0-46e1-aea7-fa3d8bfdcff2" />


---


### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned.

**Query used to locate events:**

<img width="1196" height="235" alt="image" src="https://github.com/user-attachments/assets/79437325-fbbf-412f-8fae-a2ae5b8fc967" />

<img width="1787" height="673" alt="image" src="https://github.com/user-attachments/assets/3e6712ca-b42b-4cd3-addf-00692c767c61" />



---



### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports.

**Query used to locate events:**

<img width="1461" height="286" alt="image" src="https://github.com/user-attachments/assets/8372c37c-5391-4d06-9354-a695647cbb15" />

<img width="1794" height="282" alt="image" src="https://github.com/user-attachments/assets/200ffb2f-d550-4076-b4fd-c41994cbe7cc" />


---

## Chronological Event Timeline 

Chronological Timeline of Tor-Related Events
1. Acquisition and Delivery
Action: The account holder initiated a download of the official Tor Browser installer.
Artifact: The file tor-browser-windows-x86_64-portable-15.0.11.exe was created on the system.
Significance: The use of the "Portable" version on the Desktop is a common tactic to bypass formal software installation policies.
KQL Discovery Query:
Code snippet

DeviceFileEvents
| where FileName startswith "tor"
| where DeviceName == "threathuntfinal"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256


3. Staging and Preparation
Action: Following the download, multiple Tor-related files were copied to the Desktop.
Observation: The creation of a file named "tor-shopping-list" was detected.
Significance: This suggests premeditated activity; the user was likely keeping a record of resources or targets to access once the anonymous session was established.

4. Execution and Initialization
Action: The installer was executed at 2026-05-06T20:08:24Z.
Significance: This timestamp marks the transition from a downloaded file to an active process in system memory.

5. Network Anonymization (Activity)
Action: Between 4:23 PM and 4:24 PM, tor.exe established successful connections to external nodes.
Observation: Connections were made to remote IPs (e.g., 37.59.175.224, 216.218.219.41) on ports 443 and 9001.
Significance: These ports are standard for Tor Entry/Relay nodes. Once these connections were successful, the "Employee" account had a functional, encrypted tunnel to mask further actions.

KQL Discovery Query:
Code snippet
DeviceNetworkEvents
| where DeviceName == "threathuntfinal"
| where InitiatingProcessFolderPath has "Tor Browser"
| extend Destination = iff(isnotempty(RemoteUrl), RemoteUrl, RemoteIP)
| project Timestamp, DeviceName, ActionType, Destination, RemotePort,   InitiatingProcessFileName, InitiatingProcessCommandLine
| where RemotePort in (9001, 9030, 443)
| sort by Timestamp desc



Summary of Events
On May 6, 2026, the Employee account on host threathuntfinal performed a series of unauthorized actions to anonymize their network presence. The account downloaded and executed an official, portable version of the Tor Browser, staging the files directly on the user's Desktop.
The investigation identified a specific file, "tor-shopping-list," created during this process, which suggests the activity was a planned component of the broader attack. By 4:24 PM, the tor.exe process successfully established encrypted circuits through various global relay nodes. This provided a secure tunnel that was subsequently used to perform high-volume administrative changes in Azure (including 49 resource creations) while hiding the user's true IP address and location from security logs.

Response Taken
TOR usage was confirmed on the endpoint : ”employee”. The device was isolated and the user's direct manager was notified.

