# OpenIOCCollector

Automated daily collection of Indicators of Compromise (IOCs) from public threat intelligence feeds.

This project collects, organizes, and stores IOCs from multiple open-source threat intelligence sources. It is designed for personal use in a detection engineering / SOC home lab environment and can be integrated with tools such as Wazuh.

## Features

- Collects IOCs from multiple public feeds
- Organizes output by year and month
- Runs automatically on a schedule
- Pushes results to GitHub
- Integrates selected IOCs into Wazuh CDB lists and custom rules

## Feeds Currently Collected

| Feed | Type | Format | Status | Notes |
| --- | --- | --- | --- | --- |
| URLhaus | Malware Distribution URLs | CSV | Active | abuse.ch recently observed malware URLs |
| ThreatFox | Malware IOCs | JSON | Active | abuse.ch high confidence malware IOCs |
| SSL Blacklist | Malicious SSL Certificates | CSV | Active | abuse.ch SHA1 fingerprints of bad certs |
| Feodo Tracker | Botnet C2 IPs | TXT/CSV | Empty | Currently no active C2s |
| Top Malicious IPs | Suspicious / Malicious IPs | CSV/TXT | Active | Aggregated malicious IP list |

## Architecture

```mermaid
flowchart TB
  FEEDS[Public feeds] --> KALI[Kali collector and cron]
  KALI --> OUT[Daily Output folders]
  OUT --> GH[GitHub]
  OUT --> CDB[Wazuh CDB lists]
  CDB --> RULES[Custom detection rules]
  RULES --> DASH[Wazuh Dashboard]Daily collector on Kali pulls public threat intelligence feeds, organizes the output, pushes it to GitHub, and updates Wazuh CDB lists used by custom detection rules.
```
## Project Structure

OpenIOCCollector/
├── Output/
├── tweetfeed.py
├── run_andpush.sh
├── requirements.txt
└── README.md

## How to Run

git clone https://github.com/jaguarmayan8/OpenIOCCollector.git
cd OpenIOCCollector
sudo apt install -y python3-requests
python3 tweetfeed.py

## Wazuh Integration
Selected IOCs are converted into Wazuh CDB lists and used by custom rules:

Malicious IPs: rule 100100
Malicious domains: rules 100101 / 100102
Malicious hashes: rules 100110 / 100111

The daily collector updates the IP list automatically.

## Future Improvements

 Convert collected IOCs into Wazuh CDB lists
 Add basic statistics
 Improve error handling for empty feeds
 Add Docker support
 Create a simple summary dashboard

Author
Jorge Tejada

Cybersecurity | Detection Engineering | Home Lab
License
GPL-3.0
