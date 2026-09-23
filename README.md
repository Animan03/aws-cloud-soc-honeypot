# AWS Cloud SOC Honeypot

A hands-on cloud security monitoring lab built on AWS that simulates attacker activity against an EC2 honeypot, centralizes security telemetry in Amazon CloudWatch, detects suspicious behavior, generates alerts, and supports investigation using security analytics and MITRE ATT&CK mapping.



---

## Project Overview

This project demonstrates an end-to-end Security Operations Center (SOC) monitoring workflow using AWS-native services and open-source Linux security tooling.

An intentionally exposed EC2 instance acts as a lightweight honeypot. SSH authentication activity and Linux process-execution telemetry are collected from the host and forwarded to Amazon CloudWatch Logs.

CloudWatch Logs Insights is then used for threat hunting and detection, while CloudWatch Metric Filters and CloudWatch Alarms provide automated alerting.

The project concludes with investigation of the observed activity, extraction of indicators, and mapping of relevant behavior to MITRE ATT&CK techniques.

### Security Monitoring Pipeline

```text
Attacker Activity
       ↓
AWS EC2 Honeypot
       ↓
SSH + auditd Telemetry
       ↓
Amazon CloudWatch Logs
       ↓
Logs Insights / Detection Logic
       ↓
Metric Filter
       ↓
CloudWatch Metric
       ↓
CloudWatch Alarm
       ↓
SOC Investigation
       ↓
MITRE ATT&CK Mapping
```

---

## Objectives

The project was designed to demonstrate practical skills in:

* Cloud security monitoring
* Security log collection and centralization
* Linux security telemetry
* SSH attack detection
* Process-execution monitoring
* Detection engineering
* Threat hunting
* Cloud-based alerting
* Security incident investigation
* IOC extraction
* MITRE ATT&CK mapping

---

## Architecture

The environment consists of an AWS EC2 instance running Amazon Linux 2023.

The EC2 instance receives SSH traffic and generates multiple forms of security telemetry.

### Main components

| Component                | Purpose                                  |
| ------------------------ | ---------------------------------------- |
| AWS EC2                  | Honeypot and monitored host              |
| Amazon Linux 2023        | Operating system                         |
| OpenSSH                  | SSH service and authentication telemetry |
| auditd                   | Process-execution monitoring             |
| Amazon CloudWatch Logs   | Centralized telemetry collection         |
| CloudWatch Logs Insights | Threat hunting and investigation         |
| CloudWatch Metric Filter | Detection logic                          |
| CloudWatch Metric        | Detection event tracking                 |
| CloudWatch Alarm         | Automated alerting                       |
| MITRE ATT&CK             | Threat behavior classification           |

---

## Telemetry Collection

### SSH Authentication Logs

SSH authentication activity is collected and forwarded to:

```text
/soc/honeypot/auth
```

The telemetry contains events such as:

```text
Invalid user fakeattacker from <source IP>
Invalid user admin from <source IP>
Invalid user tes from <source IP>
```

These events can be analyzed to identify repeated authentication attempts and username enumeration.

### Linux Process Execution

Linux `auditd` is configured to monitor process execution using the `execve` system call.

The resulting telemetry is forwarded to:

```text
/soc/honeypot/audit
```

Example events include:

```text
type=EXECVE
```

This provides visibility into commands executed on the monitored host.

---

## Detection Engineering

Three primary detection scenarios were implemented.

### 1. SSH Username Enumeration

Detects repeated SSH authentication attempts against invalid usernames.

The detection extracts:

* Source IP
* Attempted username
* Number of attempts
* Number of distinct usernames

This can help identify automated SSH enumeration and brute-force behavior.

---

### 2. Host Reconnaissance Burst

Identifies bursts of reconnaissance commands executed on the host.

Commands monitored include:

```text
whoami
id
hostname
uname
cat
ip
ss
ps
sudo
find
```

The detection focuses on multiple distinct reconnaissance commands occurring within a short time window rather than treating an individual benign command as malicious.

---

### 3. Suspicious Utility Execution

Monitors execution of utilities that may be relevant during post-compromise activity, including:

```text
curl
wget
nc
ncat
socat
python
python3
```

These utilities have legitimate administrative uses, so the detection is intended to provide contextual signals for investigation rather than automatically classify their execution as malicious.

---

## Example Threat Hunting Query

Example CloudWatch Logs Insights query used to identify a reconnaissance burst:

```sql
fields @timestamp, @message
| filter @message like /type=EXECVE/
| parse @message /a0="(?<command>[^"]+)"/
| filter command in ["whoami","id","hostname","uname","cat","ip","ss","ps","sudo","find"]
| stats count() as events,
        count_distinct(command) as unique_commands
    by bin(10m)
| filter unique_commands >= 5
| sort @timestamp desc
```

This allows an analyst to identify periods containing multiple distinct discovery commands.

---

## Alerting

A CloudWatch Metric Filter was configured to identify suspicious SSH authentication activity.

The resulting metric was connected to a CloudWatch Alarm.

During controlled testing, the alarm successfully transitioned into:

```text
In Alarm
```

This validated the alerting pipeline from host activity through centralized logging and detection to an AWS-native security alert.

---

## Investigation Workflow

The investigation process follows a simplified SOC workflow:

```text
1. Identify suspicious activity
          ↓
2. Examine authentication telemetry
          ↓
3. Identify source IPs and usernames
          ↓
4. Correlate timestamps
          ↓
5. Examine process execution
          ↓
6. Identify reconnaissance behavior
          ↓
7. Extract relevant indicators
          ↓
8. Map behavior to MITRE ATT&CK
          ↓
9. Determine incident disposition
```

A detailed investigation is documented in:

```text
investigations/INC-001-ssh-enumeration-recon.md
```

---

## MITRE ATT&CK Mapping

Observed behaviors were evaluated against relevant MITRE ATT&CK techniques.

| Observed Behavior                | Potential Technique                            |
| -------------------------------- | ---------------------------------------------- |
| Repeated authentication attempts | T1110 — Brute Force                            |
| Network/service reconnaissance   | T1046 — Network Service Scanning               |
| User discovery                   | T1033 — System Owner/User Discovery            |
| System information discovery     | T1082 — System Information Discovery           |
| Network configuration discovery  | T1016 — System Network Configuration Discovery |
| Network connection discovery     | T1049 — System Network Connections Discovery   |
| Process discovery                | T1057 — Process Discovery                      |

The mappings are treated as contextual classifications based on observed behavior rather than proof of a specific adversary technique.

---

## Incident Investigation

The project includes a documented simulated investigation covering:

* SSH enumeration
* Authentication telemetry
* Process-execution telemetry
* CloudWatch log analysis
* Detection validation
* Alert validation
* IOC extraction
* MITRE ATT&CK mapping
* Incident disposition

### Incident Result

**Classification:** Simulated security incident / detection validation

**Compromise confirmed:** No

**Telemetry collection:** Successful

**Detection:** Successful

**Alerting:** Successful

**Investigation:** Successful

---

## Evidence

Screenshots demonstrating the implementation and testing are available in:

```text
screenshots/
```

Evidence includes:

* EC2 honeypot
* SSH attack activity
* `auditd` `EXECVE` events
* CloudWatch Logs
* Detection queries
* CloudWatch Alarm
* SOC dashboard

---

## Repository Structure

```text
aws-cloud-soc-honeypot/
│
├── README.md
│
├── architecture/
│   └── architecture-diagram.png
│
├── detections/
│   ├── ssh-username-enumeration.md
│   ├── reconnaissance-burst.md
│   └── suspicious-utility-execution.md
│
├── investigations/
│   └── INC-001-ssh-enumeration-recon.md
│
├── screenshots/
│   ├── ec2-instance.png
│   ├── ssh-attacks.png
│   ├── audit-execve.png
│   ├── reconnaissance-detection.png
│   ├── cloudwatch-alarm.png
│   └── soc-dashboard.png
│
└── queries/
    ├── ssh-detections.txt
    └── audit-detections.txt
```

---

## Skills Demonstrated

### Cloud

* AWS EC2
* IAM
* Amazon CloudWatch
* CloudWatch Logs
* CloudWatch Logs Insights
* CloudWatch Metric Filters
* CloudWatch Alarms

### Linux / Security

* Amazon Linux
* SSH/OpenSSH
* `auditd`
* Linux process monitoring
* Authentication log analysis
* `journalctl`
* Linux command-line administration

### Security Operations

* Log ingestion
* Detection engineering
* Threat hunting
* Security alerting
* IOC extraction
* Incident investigation
* Event correlation
* MITRE ATT&CK mapping

---

## Key Learning Outcomes

This project provided hands-on experience building a security monitoring pipeline from the ground up rather than relying solely on pre-built security alerts.

The main workflow was:

```text
Generate Activity
      ↓
Collect Telemetry
      ↓
Centralize Logs
      ↓
Build Detection
      ↓
Generate Alert
      ↓
Investigate
      ↓
Map Behavior
```

The project also demonstrated an important SOC principle: individual events are often benign in isolation, while combinations of events and their temporal relationships can provide stronger security signals.

---

## Disclaimer

This project was created as a controlled security lab and educational environment.

The observed attack activity was simulated or generated for detection validation. No unauthorized access to third-party systems was performed.
