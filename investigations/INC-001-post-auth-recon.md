# INC-001 — SSH Enumeration and Host Reconnaissance

## Incident Summary

A simulated attack investigation was performed against an AWS EC2 honeypot exposed to SSH traffic.

The investigation began with repeated SSH authentication attempts using invalid usernames. The activity was captured by the EC2 host, forwarded to Amazon CloudWatch Logs, and analyzed using CloudWatch Logs Insights.

Additional controlled testing generated host reconnaissance commands on the EC2 instance. These commands were captured by Linux `auditd` as `EXECVE` events and ingested into a separate CloudWatch log group.

The investigation demonstrates an end-to-end security monitoring workflow:

```text
SSH Activity
     ↓
EC2 Honeypot
     ↓
Authentication / auditd Telemetry
     ↓
CloudWatch Logs
     ↓
Detection
     ↓
CloudWatch Alarm
     ↓
SOC Investigation
     ↓
MITRE ATT&CK Mapping
```

## Environment

| Component                | Purpose                                  |
| ------------------------ | ---------------------------------------- |
| AWS EC2                  | Honeypot host                            |
| Amazon Linux 2023        | Operating system                         |
| OpenSSH                  | SSH service and authentication telemetry |
| auditd                   | Process-execution monitoring             |
| CloudWatch Logs          | Centralized log collection               |
| CloudWatch Logs Insights | Threat hunting and investigation         |
| CloudWatch Metric Filter | Detection of suspicious SSH activity     |
| CloudWatch Alarm         | Alerting                                 |
| MITRE ATT&CK             | Threat behavior classification           |

### Log Sources

```text
/soc/honeypot/auth
```

SSH authentication activity.

```text
/soc/honeypot/audit
```

Linux `auditd` process-execution events.

## Initial Detection

The honeypot received repeated SSH connection attempts using usernames that did not exist on the system.

Examples observed during testing included:

```text
fakeattacker
admin
root
tes
```

The EC2 SSH service recorded events such as:

```text
Invalid user fakeattacker from 175.45.84.198
Invalid user admin from 175.45.84.198
Invalid user tes from 175.45.84.198
```

The authentication activity was forwarded to CloudWatch Logs.

## Detection Query

The following CloudWatch Logs Insights query was used to identify invalid SSH attempts and group them by source IP:

```sql
fields @timestamp, @message
| filter @message like /Invalid user/
| parse @message /Invalid user (?<username>\S+) from (?<src_ip>\S+)/
| stats count() as attempts,
        count_distinct(username) as usernames
    by src_ip
| sort attempts desc
```

This allows an analyst to identify sources attempting multiple usernames rather than investigating individual authentication failures independently.

## Alerting

A CloudWatch metric filter was configured to identify the relevant SSH authentication pattern.

The resulting CloudWatch metric was connected to a CloudWatch Alarm.

During controlled testing, the alarm entered:

```text
In Alarm
```

This demonstrated the complete detection and alerting path from host telemetry to an AWS-native security alert.

## Host Reconnaissance

Controlled testing was also performed on the EC2 honeypot to generate process-execution telemetry.

Commands included:

```text
whoami
id
hostname
uname -a
ip addr
ip route
ss -tulnp
ps aux
sudo -l
find /tmp -maxdepth 2 -type f -ls
```

These commands generated `EXECVE` audit events.

Example audit telemetry included:

```text
type=EXECVE
```

The events were collected in:

```text
/soc/honeypot/audit
```

## Reconnaissance Detection

CloudWatch Logs Insights was used to identify bursts containing multiple reconnaissance commands:

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

The purpose of this detection is to identify a pattern of reconnaissance activity rather than treating an individual benign command as malicious.

## Investigation Findings

### Finding 1 — SSH Enumeration

Repeated SSH attempts against multiple invalid usernames were observed.

**Assessment:** Suspicious.

Multiple username attempts can be consistent with automated SSH enumeration or brute-force activity.

### Finding 2 — Host Reconnaissance

Multiple system and network discovery commands were observed during controlled testing.

**Assessment:** Suspicious when correlated with preceding unauthorized access attempts; individually, the commands can have legitimate administrative purposes.

### Finding 3 — Process Execution Telemetry

Linux `auditd` successfully generated `EXECVE` events for executed commands.

**Assessment:** Telemetry collection functioning as expected.

### Finding 4 — Centralized Logging

Authentication and audit telemetry were successfully ingested into separate CloudWatch Logs groups.

**Assessment:** Centralized logging functioning as expected.

### Finding 5 — Alerting

The SSH detection generated a CloudWatch Alarm that entered the `In Alarm` state during testing.

**Assessment:** Detection and alerting pipeline functioning as expected.

## Indicators of Compromise

The investigation can extract the following potential indicators:

| Indicator               | Example                                               |
| ----------------------- | ----------------------------------------------------- |
| Source IP               | `175.45.84.198`                                       |
| Target service          | SSH / TCP 22                                          |
| Attempted usernames     | `fakeattacker`, `admin`, `root`, `tes`                |
| Suspicious behavior     | Repeated invalid SSH authentication attempts          |
| Reconnaissance commands | `whoami`, `id`, `hostname`, `uname`, `ip`, `ss`, `ps` |

Source IP addresses should be taken directly from the CloudWatch evidence rather than hard-coded into this report.

## MITRE ATT&CK Mapping

The observed behavior may map to several MITRE ATT&CK techniques.

| Behavior                                           | Potential Technique                            |
| -------------------------------------------------- | ---------------------------------------------- |
| SSH enumeration / repeated authentication attempts | T1110 — Brute Force                            |
| Network/service reconnaissance                     | T1046 — Network Service Scanning               |
| User discovery                                     | T1033 — System Owner/User Discovery            |
| System information discovery                       | T1082 — System Information Discovery           |
| Network configuration discovery                    | T1016 — System Network Configuration Discovery |
| Network connection discovery                       | T1049 — System Network Connections Discovery   |
| Process discovery                                  | T1057 — Process Discovery                      |

The mapping is based on the observed behavior and should be treated as contextual rather than proof that a particular ATT&CK technique was definitively used.

## Analyst Assessment

The activity demonstrates characteristics consistent with automated SSH reconnaissance followed by host discovery behavior.

However, the testing environment deliberately generated portions of the activity, and the observed external SSH attempts did not establish a successful compromise.

The primary objective of this investigation was therefore to validate the ability of the monitoring environment to:

1. Collect authentication telemetry.
2. Collect process-execution telemetry.
3. Centralize logs in CloudWatch.
4. Detect suspicious activity using Logs Insights and metric filters.
5. Generate CloudWatch alerts.
6. Investigate activity using source IPs, usernames, timestamps, and commands.
7. Map observed behavior to MITRE ATT&CK techniques.

## Incident Disposition

**Classification:** Simulated security incident / detection validation

**Result:** Detection pipeline successfully validated.

**Compromise confirmed:** No

**Telemetry collection:** Successful

**Detection:** Successful

**Alerting:** Successful

**Investigation:** Successful
