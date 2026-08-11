# TwitterIoCsfeed

Automated daily collection of Indicators of Compromise (IOCs) from public threat intelligence feeds.

This project collects, organizes, and stores IOCs from multiple open-source threat intelligence sources. It is designed for personal use in a detection engineering / SOC home lab environment and can be integrated with tools such as Wazuh.

## Features

- Collects IOCs from multiple public feeds
- Organizes output by year and month
- Runs automatically on a schedule
- Pushes results to GitHub
- Designed for easy integration with detection platforms (Wazuh, etc.)

## Feeds Currently Collected

| Feed              | Type                        | Format     | Status    | Notes                                      |
|-------------------|-----------------------------|------------|-----------|--------------------------------------------|
| URLhaus           | Malware Distribution URLs   | CSV        | Active    | abuse.ch – recently observed malware URLs  |
| ThreatFox         | Malware IOCs                | JSON       | Active    | abuse.ch – high confidence malware IOCs    |
| SSL Blacklist     | Malicious SSL Certificates  | CSV        | Active    | abuse.ch – SHA1 fingerprints of bad certs  |
| Feodo Tracker     | Botnet C2 IPs               | TXT/CSV    | Empty     | Currently no active C2s (post-takedowns)   |
| Top Malicious IPs | Suspicious / Malicious IPs  | CSV/TXT    | Active    | Aggregated malicious IP list               |

## Project Structure

```text
TwitterIoCsfeed/
├── Output/
│   └── 2026/
│       └── 2026-08/
├── tweetfeed.py
├── requirements.txt
└── README.md

How to Run

git clone https://github.com/jaguarmayan8/TwitterIoCsfeed.git
cd TwitterIoCsfeed
pip install -r requirements.txt
python3 tweetfeed.py

Wazuh Integration (Planned / In Progress)
This project is designed to support a detection engineering workflow in a home SOC lab.
Current idea:

Convert selected IOC files (especially IPs, domains, and hashes) into Wazuh CDB lists.
Use those lists in custom rules for detection and enrichment.
Eventually automate the process so new IOCs are regularly pushed into Wazuh.

Example use cases:

Block or alert on known malicious IPs from ThreatFox / SSLBL
Enrich alerts with context from collected feeds
Maintain an updated local threat intelligence source inside the lab

Future Improvements

 Convert collected IOCs into Wazuh CDB lists
 Add basic statistics (number of IOCs collected per day)
 Improve error handling for dead/empty feeds
 Add Docker support
 Create a simple summary dashboard

Author
Jorge Tejada
Cybersecurity | Detection Engineering | Home Lab
License
GPL-3.0
