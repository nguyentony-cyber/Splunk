# Splunk

## 📌 Objective

Set up a Splunk Enterprise lab (Windows) to ingest Windows Security Event logs, create SPL detection searches that identify brute‑force behavior (repeated failed logons from the same source), configure an automated alert, and build a dashboard for monitoring and triage.

## 🧠 Skills Gained

- Installing and configuring Splunk Enterprise on Windows.  
- Ingesting Windows Event Logs (Security) using Upload or Universal Forwarder.  
- Writing SPL queries to detect repeated failed logons (EventCode 4625) and correlate with successful logons (4624) and privileged logons (4672).  
- Creating scheduled alerts and applying throttling to reduce noise.  
- Building dashboards for analyst triage and testing detections with synthetic events.  
- Documenting detection logic for resume/portfolio.

## 🛠️ Tools & Technologies Used

- Splunk Enterprise (Windows) — Splunk Web 
- Windows Security Event Logs (EventCode 4625 = failed logon, 4624 = successful logon, 4672 = special privileges)  
- SPL (Search Processing Language)  
- PowerShell (for event generation/testing)  
- Dashboard Studio / Saved Searches / Alerts in Splunk

## 🖥️ Lab Environment & File Overview

Component | Details
---|---
Splunk Server (Windows) | `http://localhost:8000` (Splunk Enterprise installed)
Index | `project_logs` 
Sourcetype | `WinEventLog:Security`
Sample Log Source | Exported `security.evtx` or Universal Forwarder sending Security events
Saved Searches | `splunk/savedsearches/brute_force_detection.conf`
Dashboard | `splunk/dashboards/windows_security_monitoring.xml`
Alert | Saved Splunk alert created from the brute force saved search

## 🔍 Pre-Lab Setup (Downloads & File Placement)

1. Install Splunk Enterprise on Windows.  
   - Download installer and run `.msi` → log in at `http://localhost:8000`.  
2. Create an index called `project_logs` (Settings → Indexes → New).  
3. Add data:
   - Option A: In Splunk Web → Add Data → Monitor → Local Event Logs → select **Security** (useful for local testing).  
   - Option B: Export `security.evtx` (Event Viewer → Save All Events As...) and Upload it via Add Data → Upload.
   - Option C: Install Splunk Universal Forwarder on another Windows host and forward Security events to Splunk.
   - When ingesting, set Index to `project_logs` and sourcetype to `WinEventLog:Security`.
4. Confirm logs are searchable:
   ```spl
   index=project_logs sourcetype="WinEventLog:Security" | head 10

   
## Step-by-Step Procedure 
Open Splunk Web → Search & Reporting to run these searches and save them as reports/alerts.

1) Verify recent Windows Security events
index=project_logs sourcetype="WinEventLog:Security"
| head 20

2) All failed logon events (EventCode 4625)
index=project_logs sourcetype="WinEventLog:Security" EventCode=4625

3) Summarize failed logons by Account and Source IP
index=project_logs sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, Source_Network_Address, host
| sort -count

4) Brute-force candidate (IPs with >5 failed logons in 10 minutes)
index=project_logs sourcetype="WinEventLog:Security" EventCode=4625
| bin _time span=10m
| stats count by _time, Source_Network_Address
| where count > 5

5) Correlate failed attempts then success (4625 -> 4624)
(index=project_logs sourcetype="WinEventLog:Security" EventCode=4625) OR (index=project_logs sourcetype="WinEventLog:Security" EventCode=4624)
| eval status=case(EventCode==4625,"Failed", EventCode==4624,"Successful")
| streamstats window=5 current=f last(status) as prev_status by Account_Name
| where status=="Successful" AND prev_status=="Failed"
| table _time, Account_Name, host, Source_Network_Address

6) Privileged (special) logons (EventCode 4672)
index=project_logs sourcetype="WinEventLog:Security" EventCode=4672
| stats count by Account_Name, host

7) Save the brute-force rule as an Alert (UI steps)

Run search (Step 4).

Click Save As → Alert.

Title: Brute-Force Detection (Windows)

Schedule: Run Every 5 minutes, Time Range: Last 10 minutes

Trigger: If number of results is greater than 0

Throttle: Suppress for 30 minutes

Action: Add to Triggered Alerts (and optionally email/webhook)

8) Dashboard panels (three panels)

Top offenders:

index=project_logs sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Source_Network_Address
| sort -count
| head 10


Failed vs Successful logons over time:

(index=project_logs sourcetype="WinEventLog:Security" EventCode=4625) OR (index=project_logs sourcetype="WinEventLog:Security" EventCode=4624)
| eval status=if(EventCode==4625,"Failed","Successful")
| timechart span=15m count by status


Recent brute-force offenders (table):

index=project_logs sourcetype="WinEventLog:Security" EventCode=4625
| bin _time span=10m
| stats count by _time, Source_Network_Address
| where count > 5
| sort -_time

9) Test (PowerShell: create Windows Event 4625-like entries or append exported EVTX)


🖼️ Screenshots 

<img width="1000" height="909" alt="Screenshot 2025-10-11 171250" src="https://github.com/user-attachments/assets/6b526a6c-e591-40ee-a063-92ea190cc806" />


<img width="1000" height="785" alt="Screenshot 2025-10-11 171238" src="https://github.com/user-attachments/assets/980b64f9-aaf8-49b4-965f-df06f6f905a8" />



📄 Executive Summary

This project demonstrates an end‑to‑end Splunk SIEM use case for detecting brute‑force attacks against Windows hosts. You ingest Windows Security events, author SPL detection logic for failed and successful logons and privileged events, create scheduled alerts with throttling, and visualize results in a dashboard. These outputs provide measurable evidence of impact suitable for a resume.

