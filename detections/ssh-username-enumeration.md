# SSH Username Enumeration Detection

## Objective

Detect repeated SSH authentication attempts against usernames that do not exist on the EC2 honeypot.

## Data Source

* AWS EC2
* Amazon Linux 2023
* SSH/OpenSSH authentication logs
* CloudWatch Logs
* Log group: `/soc/honeypot/auth`

## Detection Logic

The detection searches SSH authentication logs for `Invalid user` events and extracts the attempted username and source IP address.

```sql
fields @timestamp, @message
| filter @message like /Invalid user/
| parse @message /Invalid user (?<username>\S+) from (?<src_ip>\S+)/
| stats count() as attempts,
        count_distinct(username) as usernames
    by src_ip
| sort attempts desc
```

## Security Rationale

Repeated attempts against multiple usernames can indicate:

* Username enumeration
* SSH brute-force activity
* Automated scanning
* Credential attack preparation

A single failed authentication attempt is not necessarily malicious. Repeated attempts involving multiple usernames from the same source are more suspicious.

## Investigation

When an alert or suspicious pattern is identified, an analyst should investigate:

1. Source IP address
2. Number of authentication attempts
3. Usernames targeted
4. Frequency and timing of attempts
5. Whether any authentication was successful
6. Related process-execution activity on the host

## Example Observed Activity

During testing, the honeypot received SSH connection attempts using usernames including `fakeattacker`, `admin`, `root`, and `tes`.

The attempts were rejected by the SSH service and recorded in the authentication telemetry.

## MITRE ATT&CK Relevance

Potentially associated with:

* **T1046 – Network Service Scanning**
* **T1110 – Brute Force**

The exact technique should be determined based on the broader activity and investigation context rather than treating every failed SSH attempt as brute force.
