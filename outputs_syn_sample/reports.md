## Incident b9c7394ccb81

### Incident Summary
An incident window from 2018-12-01T13:30:30.741451 to 2018-12-01T13:30:41.049275 contains 99985 related flow records between source(s) 172.16.0.5 and destination(s) 192.168.50.1. The dominant protocol is unknown, with dominant service unknown and destination port(s) unknown.

### Observed Behavior
The abstraction characterizes the activity as very high flow rate, short burst activity. The summarized telemetry shows 9699.9134 flows per second across the incident window.

### Threat Context
The behavior is mapped to MITRE ATT&CK tactic `Impact` and technique `T1498` (Network Denial of Service). Mapping confidence is medium. Rationale: High-volume traffic labels and repeated flows are consistent with denial-of-service behavior.

### Potential Impact
Potential impact should be interpreted from observable network behavior only. For denial-of-service style incidents, sustained or bursty high-rate traffic may degrade service availability. For non-DDoS ATT&CK-labeled incidents, the impact depends on the mapped tactic and affected service.

### Recommended Analyst Actions
- Validate whether the source and destination hosts are expected to communicate during this time window.
- Check service exposure and firewall policy for the listed destination ports.
- Correlate this incident with IDS alerts, authentication logs, endpoint telemetry, and asset criticality.
- Treat CVE context as enrichment only unless confirmed by vulnerability scanning or exploit evidence.

### Evidence Limitations
This report is generated from incident-level network telemetry abstraction. It does not prove attacker identity, malware use, successful exploitation, or confirmed business impact.


## Incident bedc3655af5d

### Incident Summary
An incident window from 2018-12-01T13:30:37.883962 to 2018-12-01T13:30:39.051496 contains 4 related flow records between source(s) 192.168.50.6 and destination(s) 4.2.2.4. The dominant protocol is unknown, with dominant service unknown and destination port(s) unknown.

### Observed Behavior
The abstraction characterizes the activity as moderate flow rate, short burst activity. The summarized telemetry shows 3.426 flows per second across the incident window.

### Threat Context
The behavior is mapped to MITRE ATT&CK tactic `none` and technique `none` (none). Mapping confidence is low. Rationale: No malicious behavior label is present in the incident abstraction.

### Potential Impact
Potential impact should be interpreted from observable network behavior only. For denial-of-service style incidents, sustained or bursty high-rate traffic may degrade service availability. For non-DDoS ATT&CK-labeled incidents, the impact depends on the mapped tactic and affected service.

### Recommended Analyst Actions
- Validate whether the source and destination hosts are expected to communicate during this time window.
- Check service exposure and firewall policy for the listed destination ports.
- Correlate this incident with IDS alerts, authentication logs, endpoint telemetry, and asset criticality.
- Treat CVE context as enrichment only unless confirmed by vulnerability scanning or exploit evidence.

### Evidence Limitations
This report is generated from incident-level network telemetry abstraction. It does not prove attacker identity, malware use, successful exploitation, or confirmed business impact.


## Incident 6957bf7a2956

### Incident Summary
An incident window from 2018-12-01T13:30:37.905651 to 2018-12-01T13:30:37.905744 contains 2 related flow records between source(s) 192.168.50.6 and destination(s) 23.220.46.76. The dominant protocol is unknown, with dominant service unknown and destination port(s) unknown.

### Observed Behavior
The abstraction characterizes the activity as moderate flow rate, short burst activity. The summarized telemetry shows 2.0 flows per second across the incident window.

### Threat Context
The behavior is mapped to MITRE ATT&CK tactic `none` and technique `none` (none). Mapping confidence is low. Rationale: No malicious behavior label is present in the incident abstraction.

### Potential Impact
Potential impact should be interpreted from observable network behavior only. For denial-of-service style incidents, sustained or bursty high-rate traffic may degrade service availability. For non-DDoS ATT&CK-labeled incidents, the impact depends on the mapped tactic and affected service.

### Recommended Analyst Actions
- Validate whether the source and destination hosts are expected to communicate during this time window.
- Check service exposure and firewall policy for the listed destination ports.
- Correlate this incident with IDS alerts, authentication logs, endpoint telemetry, and asset criticality.
- Treat CVE context as enrichment only unless confirmed by vulnerability scanning or exploit evidence.

### Evidence Limitations
This report is generated from incident-level network telemetry abstraction. It does not prove attacker identity, malware use, successful exploitation, or confirmed business impact.
