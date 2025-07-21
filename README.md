# SHAP Benefits Demo

This repository contains the demo script, dashboard XML, SPL files, and data for the "Executive Summary: SHAP Benefits in Demo" presentation, focusing on lateral movement detection using Cisco logs in Splunk.

## Files
- `demo_script.spl`: Splunk search script for generating demo data.
- `executive_shap_benefits_static.xml`: Dashboard XML for the executive view.
- `Detection Engineer View.xml`: Dashboard for detection engineers with SHAP tuning.
- `shap_threat_dashboard_table.xml`: Dashboard with SHAP threat analysis.
- `lateral_movement_overview_v7.xml`: Overview dashboard for Splunk .conf25.
- `shap_comparison_dashboard_final_v10.xml`: Pre- vs. post-SHAP comparison dashboard.
- `cisco_lateral_movement_logs.csv`: Sample Cisco logs for the demo.
- `shap_features.csv`: Feature-engineered data for SHAP analysis.
- `generate_shap_values.py`: Python script to generate SHAP values.
- `shap_values_output.csv`: SHAP results for detection.

## Usage
1. Clone this repository: `git clone https://github.com/ramuvadlamudi/shap-demo-presentation`.
2. Import dashboard XML files into Splunk as dashboards.
3. Ingest `cisco_lateral_movement_logs.csv` into Splunk (index=shap_demo, sourcetype=cisco:combined_demo).
4. Run feature engineering SPL, export to `shap_features.csv`, and execute `generate_shap_values.py` to produce `shap_values_output.csv`.
5. Upload `shap_values_output.csv` to Splunk as a lookup (`shap_values.csv`) and adjust dashboards as needed.

## Workflow
1. **Cisco Logs (Splunk)**: Ingest raw Cisco logs.
2. **Feature Engineering (SPL)**: Transform logs into features.
3. **Export CSV**: Generate `shap_features.csv`.
4. **SHAP in Python**: Compute SHAP values with `generate_shap_values.py`.
5. **Import Results**: Ingest `shap_values_output.csv` as `shap_values.csv`.
6. **Dashboards**: Visualize with dashboards.

## Detection Use Case Logic
### Objective
Detect lateral movement by identifying suspicious patterns: process executions (e.g., `psexec.exe`, `cmd.exe`), high-risk port activity (e.g., 445/SMB, 3389/RDP), unknown/suspicious DNS queries, and abnormal data transfers.

### Detection Logic
- **Indicators**:
  - Execution of `psexec.exe` or `cmd.exe`.
  - Connections to ports 445 or 3389.
  - DNS queries to `unknown.com` or `suspicious.org`.
  - High data transfer (bytes_sent > 800 or bytes_received > 400).
  - Anomalous DNS query counts (>10).
- **Threat Score**: Weighted sum (0–1 scale) of indicators.
- **SHAP Integration**: Prioritizes investigation using SHAP values.

### SPL for Detection

index=shap_demo sourcetype=cisco:combined_demo
| eval is_suspicious_process=if(process_name IN ("psexec.exe", "cmd.exe"), 1, 0)
| eval is_high_risk_port=if(port IN (445, 3389), 1, 0)
| eval is_suspicious_domain=if(domain IN ("unknown.com", "suspicious.org") OR domain="", 1, 0)
| eval high_data_transfer=if(bytes_sent > 800 OR bytes_received > 400, 1, 0)
| eval high_dns_query_count=if(dns_query_count > 10, 1, 0)
| eval threat_score = (is_suspicious_process * 0.3) + (is_high_risk_port * 0.25) + (is_suspicious_domain * 0.25) + (high_data_transfer * 0.15) + (high_dns_query_count * 0.05)
| eval alert_label=if(threat_score >= 0.7, "malicious", if(threat_score >= 0.4, "suspicious", "normal"))
| table _time, host, user, process_name, port, domain, bytes_sent, bytes_received, dns_query_count, threat_score, alert_label
| sort -threat_score
- **Explanation**: Binary indicators for processes, ports, domains, data transfers, and DNS queries. Weighted `threat_score` with labels (`malicious` ≥ 0.7, `suspicious` ≥ 0.4).

### Feature Engineering in Splunk
#### Objective
Extract and normalize features for SHAP analysis.

#### Features for SHAP
1. `is_suspicious_process`: 1 if `psexec.exe` or `cmd.exe`, else 0.
2. `is_high_risk_port`: 1 if port 445 or 3389, else 0.
3. `is_suspicious_domain`: 1 if `unknown.com`, `suspicious.org`, or empty, else 0.
4. `high_data_transfer`: 1 if bytes_sent > 800 or bytes_received > 400, else 0.
5. `high_dns_query_count`: 1 if dns_query_count > 10, else 0.
6. `connection_duration_norm`: Normalized (0–1) connection duration.
7. `bytes_sent_norm`: Normalized (0–1) bytes sent.
8. `bytes_received_norm`: Normalized (0–1) bytes received.

#### SPL for Feature Engineering

index=shap_demo sourcetype=cisco:combined_demo
| eval is_suspicious_process=if(process_name IN ("psexec.exe", "cmd.exe"), 1, 0)
| eval is_high_risk_port=if(port IN (445, 3389), 1, 0)
| eval is_suspicious_domain=if(domain IN ("unknown.com", "suspicious.org") OR domain="", 1, 0)
| eval high_data_transfer=if(bytes_sent > 800 OR bytes_received > 400, 1, 0)
| eval high_dns_query_count=if(dns_query_count > 10, 1, 0)
| eval connection_duration_norm=connection_duration / 300
| eval bytes_sent_norm=bytes_sent / 1100
| eval bytes_received_norm=bytes_received / 600
| eval alert_label_binary=if(alert_label="malicious", 1, 0)
| table _time, host, user, is_suspicious_process, is_high_risk_port, is_suspicious_domain, high_data_transfer, high_dns_query_count, connection_duration_norm, bytes_sent_norm, bytes_received_norm, alert_label_binary
| outputcsv shap_features.csv

- **Explanation**: Normalizes continuous features (max values: 300, 1100, 600). `alert_label_binary` (1 for malicious) supports SHAP.

### Generate SHAP Values in Python
#### Objective
Compute SHAP values to explain feature contributions.

#### Python Code
Use the .py files
- **Explanation**: Random Forest predicts `alert_label_binary`. SHAP values for the malicious class are saved to `shap_values_output.csv`.

### Ingest SHAP Values into Splunk
#### Objective
Combine SHAP results with original data.

#### SPL to Ingest SHAP Values
| inputlookup shap_values_output.csv
| fields _time, host, user, shap_is_suspicious_process, shap_is_high_risk_port, shap_is_suspicious_domain, shap_high_data_transfer, shap_high_dns_query_count, shap_connection_duration_norm, shap_bytes_sent_norm, shap_bytes_received_norm
| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%S.%N%z")
| outputlookup shap_values.csv


#### Detection with SHAP
index=shap_demo sourcetype=cisco:combined_demo
| eval is_suspicious_process=if(process_name IN ("psexec.exe", "cmd.exe"), 1, 0)
| eval is_high_risk_port=if(port IN (445, 3389), 1, 0)
| eval is_suspicious_domain=if(domain IN ("unknown.com", "suspicious.org") OR domain="", 1, 0)
| eval high_data_transfer=if(bytes_sent > 800 OR bytes_received > 400, 1, 0)
| eval high_dns_query_count=if(dns_query_count > 10, 1, 0)
| eval threat_score = (is_suspicious_process * 0.3) + (is_high_risk_port * 0.25) + (is_suspicious_domain * 0.25) + (high_data_transfer * 0.15) + (high_dns_query_count * 0.05)
| join type=left _time, host, user
[ inputlookup shap_values.csv
| fields _time, host, user, shap_is_suspicious_process, shap_is_high_risk_port, shap_is_suspicious_domain, shap_high_data_transfer, shap_high_dns_query_count, shap_connection_duration_norm, shap_bytes_sent_norm, shap_bytes_received_norm ]
| eval total_shap = shap_is_suspicious_process + shap_high_risk_port + shap_is_suspicious_domain + shap_high_data_transfer + shap_high_dns_query_count + shap_connection_duration_norm + shap_bytes_sent_norm + shap_bytes_received_norm
| eval confidence = round(total_shap * 100, 0) . "%"
| eval top_risk_factors = case(
shap_is_suspicious_domain >= 0.3, "Unknown Domain Communication: +" . round(shap_is_suspicious_domain, 2) . " (CRITICAL)",
shap_is_suspicious_process >= 0.3, "Suspicious Process Execution: +" . round(shap_is_suspicious_process, 2) . " (SUSPICIOUS)",
shap_high_risk_port >= 0.3, "High-Risk Port Activity: +" . round(shap_high_risk_port, 2) . " (ANOMALOUS)",
shap_high_data_transfer >= 0.2, "Elevated Data Transfer: +" . round(shap_high_data_transfer, 2) . " (MALICIOUS)",
shap_high_dns_query_count >= 0.1, "Abnormal Query Patterns: +" . round(shap_high_dns_query_count, 2) . " (ELEVATED)",
1=1, ""
)
| eval investigation_priority = if(threat_score >= 0.85, "#1 - Critical Lateral Movement", if(threat_score >= 0.7, "#2 - RDP Compromise Vector", "#3 - Low Priority"))
| eval next_steps = case(
host="host1", "Isolate host1, analyze psexec.exe payload, investigate unknown.com domain, check SMB/port 445 connections",
host="host2", "Check RDP sessions on port 3389, investigate suspicious.org domain, analyze cmd.exe activity, review user2 privilege escalation",
1=1, "Review host activity and network connections"
)
| table _time, host, user, threat_score, confidence, top_risk_factors, investigation_priority, next_steps
| sort -threat_score

- **Explanation**: Joins SHAP values with logs, computes `total_shap` and `confidence`, and provides prioritized investigation steps.

