# Suspicious Utility Execution Detection

## Objective

Identify execution of utilities that can be used during reconnaissance, downloading, scripting, networking, or post-compromise activity.

## Data Source

* Linux `auditd`
* `EXECVE` events
* CloudWatch Logs
* Log group: `/soc/honeypot/audit`

## Detection Logic

The detection searches process-execution telemetry for utilities commonly observed during security investigations.

```sql
fields @timestamp, @message
| filter @message like /type=EXECVE/
| parse @message /a0="(?<command>[^"]+)"/
| filter command in ["curl","wget","nc","ncat","socat","python","python3"]
| stats count() as executions by command
| sort executions desc
```

## Security Rationale

Utilities such as `curl`, `wget`, networking tools, and scripting interpreters can have legitimate administrative uses. However, their execution after suspicious authentication or reconnaissance activity can increase the likelihood that an actor is performing post-compromise actions.

This detection is therefore intended as a **contextual detection**, rather than automatically classifying the execution of these utilities as malicious.

## Investigation

An analyst should correlate:

1. Utility executed
2. Timestamp
3. User executing the command
4. Preceding SSH activity
5. Previous reconnaissance commands
6. Command arguments, where captured
7. Network connections
8. Other process-execution events

## Example

A sequence such as:

```text
SSH authentication attempt
        ↓
Host reconnaissance
        ↓
curl / wget execution
        ↓
Additional process execution
```

would warrant greater investigation than an isolated execution of `curl`.

## MITRE ATT&CK Relevance

Depending on command arguments and observed behavior, activity may potentially relate to techniques such as:

* **T1105 – Ingress Tool Transfer**
* **T1059 – Command and Scripting Interpreter**

The final mapping should be based on observed behavior and investigation evidence.
