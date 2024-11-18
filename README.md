# Correlated log events the key to operational effectiveness  
Cyber-attacks come in many flavours distributed denial of service, virus, SQL injection, Cross site scripting etc. This is why it is imperative to correlate log events across different data sources—firewalls, endpoints, databases, and web servers. This can reveal patterns that single logs alone cannot, highlighting potential attacks before they become successful breaches.

This is becoming increasing more important because of the challenging landscape defenders face: attackers only need one successful exploit, while defenders must secure a vast range of assets. By effectively correlating log events, defenders can break down this asymmetry, uncovering connections that might otherwise go unnoticed. For example, a lone SQL injection attempt might seem benign, but if seen alongside unusual traffic from the same IP or unusual login attempts, it could signal a coordinated attack.

With tools like Microsoft Sentinel, which offers robust analytics rules, you can automate threat detection across these correlated events. Sentinel's analytics rules allow users to aggregate events into incidents, which provides security teams with context-rich insights into attacks. This way, they can identify an attack in its early stages rather than responding to isolated events after the fact.

### 1. The Value of Contextual Analysis

Correlating log data enables defenders to go beyond isolated events and see the full picture of a potential security incident. Single events, like a failed login attempt or a request to an unfamiliar endpoint, may appear benign in isolation. However, by correlating these logs across different data sources, defenders can understand the context—allowing them to focus on incidents with a high likelihood of being genuine threats.

In Microsoft Sentinel, for instance, analytics rules can identify patterns by aggregating and correlating multiple data points, such as login anomalies across endpoints, or sudden access attempts on sensitive systems. By building a story around these connections, Sentinel helps security teams recognize and prioritize high-risk alerts. Contextual analysis also reduces the noise of false positives, which often clutter alerts in traditional monitoring systems, thereby making detection faster and more precise.

### 2. Examples of Correlation Rules in Action
Here are a few practical examples where correlation rules can greatly improve detection accuracy:

- Brute Force and Privilege Escalation: A brute-force attempt might appear as a cluster of failed login attempts from a single IP address. If this is followed by a successful login and privilege escalation activity on the same user account, a correlation rule would flag this combination as suspicious. Sentinel would generate a priority incident that points to a compromised user account, which requires immediate investigation.

This query detects multiple failed login attempts from a single IP, followed by a successful login and privilege escalation on the same account.
```
// Detects a brute force pattern followed by privilege escalation on the same account, suggesting potential compromise
let FailedLogins = 
    SecurityEvent
    | where EventID == 4625  // Event ID for failed login
    | summarize FailedAttempts = count() by TargetAccount, IPAddress = tostring(IpAddress), bin(TimeGenerated, 1h)
    | where FailedAttempts > 5;  // Threshold for brute force attempt

let SuccessfulLogin = 
    SecurityEvent
    | where EventID == 4624  // Event ID for successful login
    | where TargetAccount in (FailedLogins | project TargetAccount) 
    | project TimeGenerated, TargetAccount, IpAddress, SuccessfulLoginTime = TimeGenerated;

let PrivilegeEscalation =
    SecurityEvent
    | where EventID == 4672  // Event ID for special privileges assigned
    | where TargetAccount in (SuccessfulLogin | project TargetAccount)
    | project TimeGenerated, TargetAccount, EscalationTime = TimeGenerated;

FailedLogins
| join kind=inner (SuccessfulLogin) on TargetAccount, IPAddress
| join kind=inner (PrivilegeEscalation) on TargetAccount
| where SuccessfulLoginTime < EscalationTime
| project TargetAccount, IPAddress, FailedAttempts, SuccessfulLoginTime, EscalationTime
| extend Incident = "Potential Compromised Account with Privilege Escalation"

```



- Suspicious Data Exfiltration: Imagine a scenario where a user logs in from an unusual location, downloads a high volume of data from a secure database, and immediately logs out. Individually, these actions might pass unnoticed. However, a correlation rule combining these events could detect and alert on this sequence as a potential data exfiltration attempt, giving the security team critical context to act promptly.
  
This query correlates unusual login locations, high-volume downloads, and a logoff event.

```
// Detects unusual login, high data download, and immediate logout, indicating potential data theft

let UnusualLogin = 
    SigninLogs
    | where ResultType == "0" // Successful login
    | where Location != "Expected_Location"  // Replace with expected location(s)
    | project UserPrincipalName, IPAddress, LoginTime = TimeGenerated;

let DataDownload = 
    AuditLogs
    | where ActivityDisplayName == "FileDownloaded" // Adjust as needed
    | where UserPrincipalName in (UnusualLogin | project UserPrincipalName)
    | summarize DataVolume = sum(FileSize) by UserPrincipalName, DownloadTime = TimeGenerated
    | where DataVolume > 10000000; // Threshold for high data volume, adjust as needed

let LogoffEvent = 
    SigninLogs
    | where ResultType == "0" 
    | where UserPrincipalName in (DataDownload | project UserPrincipalName)
    | where EventName == "UserLoggedOut"
    | project UserPrincipalName, LogoffTime = TimeGenerated;

UnusualLogin
| join kind=inner (DataDownload) on UserPrincipalName
| join kind=inner (LogoffEvent) on UserPrincipalName
| where LoginTime < DownloadTime and DownloadTime < LogoffTime
| project UserPrincipalName, IPAddress, LoginTime, DownloadTime, LogoffTime, DataVolume
| extend Incident = "Suspicious Data Exfiltration"

```


  
- Malware and Lateral Movement: Suppose there’s an alert about a malicious file detected on one endpoint, followed by abnormal network activity on several adjacent endpoints. Correlating these events could point to lateral movement of malware through the network, suggesting that the attacker is attempting to escalate the breach. This allows security teams to block the threat across multiple endpoints before significant damage occurs.
  
This query detects a malicious file event on one endpoint followed by abnormal network connections on other endpoints, indicating potential lateral movement.
```
// Detects a malware alert on one device followed by abnormal network activity to other devices, which could mean lateral movement.
let MalwareDetection = 
    DeviceEvents
    | where ActionType == "MalwareDetected" 
    | project DeviceName, User, MalwareName, DetectionTime = TimeGenerated;

let LateralMovement = 
    DeviceNetworkEvents
    | where ActionType == "NetworkConnectionInitiated"
    | where DestinationDeviceName != DeviceName
    | summarize Connections = count() by InitiatingDevice = DeviceName, DestinationDevice = DestinationDeviceName, bin(TimeGenerated, 1h)
    | where Connections > 10; // Threshold for suspicious lateral movement

MalwareDetection
| join kind=inner (LateralMovement) on DeviceName
| where DetectionTime < TimeGenerated
| project InitiatingDevice, DestinationDevice, MalwareName, DetectionTime, TimeGenerated
| extend Incident = "Malware Detected with Potential Lateral Movement"

```


### 3. Operational Efficiency Gains

Security teams are often overwhelmed by a deluge of alerts. In fact, one of the main challenges in Security Operations Centres (SOCs) is alert fatigue, where repeated false positives can distract analysts from genuine threats. By correlating related log events, security teams can focus on meaningful, high-quality alerts that require action, rather than sifting through isolated alerts of limited relevance.

Correlated events also streamline investigation workflows, as the entire context is encapsulated in a single alert or incident. This reduces the time analysts spend piecing together information from various logs and enables a quicker, more coordinated response. For example, in Microsoft Sentinel, these correlated incidents also provide pre-built investigation graphs and drill-down options, allowing analysts to trace the attack path without navigating multiple tools.

## Conclusion
Through contextual analysis, effective use of correlation rules, and operational efficiency improvements, log correlation becomes a key element of a robust cybersecurity defense. It transforms raw data into actionable intelligence, enabling a proactive and streamlined approach to security.

## Resources 
 
- <a href="https://github.com/RaphaelEjike/ThreatHunting ">My KQL threat hunting workflows (Private)</a>
- <a href="https://www.kqlsearch.com/">www.kqlsearch.com</a>
- <a href="https://learn.microsoft.com/en-us/kusto/query/tutorials/learn-common-operators?view=azure-data-explorer&preserve-view=true&pivots=azuredataexplorer">Kusto query tutorials</a>
- <a href="https://kqlquery.com/">https://kqlquery.com/</a>
- <a href="https://kqlquery.com/posts/kql_sources/">https://kqlquery.com/posts/kql_sources/</a>
- <a href="https://github.com/marcusbakker/KQL/blob/master/kql_cheat_sheet_dark.pdf">https://github.com/marcusbakker/KQL/blob/master/kql_cheat_sheet_dark.pdf</a>


