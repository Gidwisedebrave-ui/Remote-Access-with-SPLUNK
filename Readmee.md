# Remote Access Investigation via Splunk

## Overview
This project documents the process of identifying remote access events on Windows systems using Splunk. Specifically, it focuses on detecting Remote Desktop (RDP) sessions and session unlocks.

## Log Source
- **Index:** `wineventlog`
- **Sourcetype:** `WinEventLog:Security`
- **Event ID:** `4624` (Successful Logon)

## Investigation Methodology
I identified remote access by filtering for specific **Logon Types**:
- **Type 10:** New Remote Interactive (RDP).
- **Type 7:** Session Unlock (used to identify users returning to a remote session).

### Primary Search Query
```splunk
index=wineventlog EventCode=4624 (Logon_Type=10 OR Logon_Type=7)
| table _time, ComputerName, Account_Name, Logon_Type, Source_Network_Address

