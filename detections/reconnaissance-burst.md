# Host Reconnaissance Burst Detection

## Objective

Identify bursts of host reconnaissance commands executed on the EC2 honeypot.

## Data Source

* Linux `auditd`
* `EXECVE` audit events
* CloudWatch Logs
* Log group: `/soc/honeypot/audit`

The audit configuration records process execution using the `execve` system call.

## Detection Logic

The detection identifies commonly used reconnaissance commands and looks for multiple distinct commands occurring within a short time window.

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

## Security Rationale

A sequence of commands such as:

* `whoami`
* `id`
* `hostname`
* `uname`
* `ip`
* `ss`
* `ps`
* `sudo`

can indicate that an actor is attempting to understand the compromised environment.

The detection therefore focuses on the **combination and frequency of commands**, rather than treating an individual command such as `whoami` as malicious.

## Investigation

An analyst should examine:

1. Timestamp of the activity
2. Commands executed
3. User associated with the processes
4. Parent process information where available
5. Related SSH authentication activity
6. Source IP associated with the preceding access
7. Subsequent execution of utilities such as `curl`, `wget`, or networking tools

## Example Investigation

Controlled testing generated benign reconnaissance activity on the honeypot using commands such as:

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

These commands generated `EXECVE` telemetry that was ingested into CloudWatch and surfaced through Logs Insights.

## MITRE ATT&CK Relevance

Potentially relevant techniques include:

* **T1033 – System Owner/User Discovery**
* **T1082 – System Information Discovery**
* **T1016 – System Network Configuration Discovery**
* **T1049 – System Network Connections Discovery**
* **T1057 – Process Discovery**
* **T1087 – Account Discovery**

Technique mapping should be based on the individual command and surrounding investigation evidence.
