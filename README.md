# Threat Hunt Report: Unauthorized TOR Usage

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

---

## Platforms and Tools Leveraged
- Windows Workstation (Endpoint: `badactor911`)
- Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)
- Tor Browser

---

## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours.  

**Objective:** Detect any TOR usage and analyze related incidents to mitigate potential risks. Notify management if TOR activity is confirmed.

---

## High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for `tor(.exe)` or `firefox(.exe)` file events.  
- **Check `DeviceProcessEvents`** for installation or execution signs.  
- **Check `DeviceNetworkEvents`** for outgoing TOR-related connections (ports `9001`, `9030`, `9050`, `9150`).  

---

## Steps Taken

### 1. File Events Discovery

Searched the `DeviceFileEvents` table for filenames containing "tor".  
- Discovered downloads of TOR-related files.  
- Found creation of a suspicious file described as a *"Tor shopping list"*, which was later deleted — suggesting concealment attempts.  
- **Timestamp:** `2025-08-20 20:54:30`  

**Query:**
```kql
DeviceFileEvents
| where FileName startswith "tor"
| order by Timestamp desc
| where DeviceName == "badactor911"
| project Timestamp, DeviceName, Account = InitiatingProcessAccountDomain,
         ActionType, FileName, SHA256
```
<img width="1345" height="746" alt="image" src="https://github.com/user-attachments/assets/723f2119-cba7-4a2d-8baf-3d4ed3a5cda4" />



---

### 2. Process Events – TOR Installation

Searched the `DeviceProcessEvents` table for command lines containing "tor".  
- Identified execution of `tor-browser-windows-x86_64-portable-14.5.6.exe`.  
- Verified as legitimate and signed by *The Tor Project*.  
- Evidence of Firefox and Edge use shortly after, indicating browsing activity.  
- **Timestamp:** `2025-08-20 20:56:01`  

**Query:**
```kql
DeviceProcessEvents
| where DeviceName == "badactor911"
| where ProcessCommandLine contains "tor"
| project Timestamp, AccountName, DeviceName, ActionType,
         FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1345" height="746" alt="image" src="https://github.com/user-attachments/assets/009fc7d4-78dc-406f-bb27-f7744eeed9c9" />



---

### 3. Process Events – TOR Execution

Confirmed TOR Browser launch by detecting execution of `firefox.exe` from the TOR Browser folder.  
- **Timestamp:** `2025-08-20 20:57:05`

**Query:**
```kql
DeviceProcessEvents
| where DeviceName == "badactor911"
| where FileName has_any ("firefox.exe", "tor.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, AccountName, DeviceName, ActionType,
         FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1345" height="746" alt="image" src="https://github.com/user-attachments/assets/3699dcaf-b8f7-45eb-9051-9200c60db7ac" />


---

### 4. Network Events – TOR Connections

Analyzed `DeviceNetworkEvents` for TOR-related ports.  
- At `20:58`, confirmed connections through `127.0.0.1:9150` (TOR proxy).  
- Multiple connections attempted on TOR ports (`9001`, `9030`, `9050`), some successful.  

**Query:**
```kql
DeviceNetworkEvents
| where DeviceName == "badactor911"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9050", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType,
         InitiatingProcessFolderPath, RemotePort, LocalIP, LocalPort,
         InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1345" height="746" alt="image" src="https://github.com/user-attachments/assets/1b7e7231-8d52-42f9-8d45-f1046456e540" />


---

## Chronological Event Timeline

- **2025-08-20 20:54:30** – File `Tor shopping list` created and later deleted.  
- **2025-08-20 20:56:01** – TOR installer (`tor-browser-windows-x86_64-portable-14.5.6.exe`) executed.  
- **2025-08-20 20:57:05** – TOR Browser (`firefox.exe`) launched from install folder.  
- **2025-08-20 20:58:00–20:58:20** – TOR network connections established via `127.0.0.1:9150` and related ports.  
- **2025-08-20 20:59:14–21:00:35** – Continued TOR browsing activity observed.  
- **2025-08-20 21:21:48–21:22:10** – TOR executables and shopping list file deleted (cleanup activity).  

---

## Summary

The user `badactor911` deliberately:  
1. Created and later deleted a file labeled *“Tor shopping list”*.  
2. Downloaded and executed the TOR installer.  
3. Launched the TOR Browser.  
4. Successfully connected to the TOR network.  
5. Engaged in anonymous browsing until cleanup efforts were made.  
6. Deleted TOR-related artifacts to conceal activity.  

**Conclusion:** Intentional TOR installation, use, and concealment confirmed.

---

## Response Taken

- TOR activity confirmed on endpoint `badactor911`.  
- Device isolated from the network.  
- User’s manager notified.  

---
