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

| Feed              | Type                       | Format  | Status | Notes                                     |
| ----------------- | -------------------------- | ------- | ------ | ----------------------------------------- |
| URLhaus           | Malware Distribution URLs  | CSV     | Active | abuse.ch – recently observed malware URLs |
| ThreatFox         | Malware IOCs               | JSON    | Active | abuse.ch – high confidence malware IOCs   |
| SSL Blacklist     | Malicious SSL Certificates | CSV     | Active | abuse.ch – SHA1 fingerprints of bad certs |
| Feodo Tracker     | Botnet C2 IPs              | TXT/CSV | Empty  | Currently no active C2s (post-takedowns)  |
| Top Malicious IPs | Suspicious / Malicious IPs | CSV/TXT | Active | Aggregated malicious IP list              |

## Architecture

```mermaid
flowchart LR
  subgraph Feeds["Public Threat Feeds"]
    UH[URLhaus]
    TF[ThreatFox]
    SB[SSL Blacklist]
    IP[IPsum]
  end

  subgraph Kali["Kali VM - Collector"]
    CRON["Cron 8:30 AM CT"]
    SCRIPT["tweetfeed.py"]
    OUT["Output/YYYY/YYYY-MM/YYYYMMDD"]
    BUILD["Build CDB lists"]
    GIT["GitHub push"]
  end

  subgraph PVE["Proxmox Host"]
    subgraph Wazuh["Ubuntu - Wazuh Manager"]
      CDB["CDB lists: IPs / domains / hashes"]
      RULES["Custom rules 100100 / 100101 / 100110"]
      DASH["Wazuh Dashboard"]
    end
    Kali
  end

  UH --> SCRIPT
  TF --> SCRIPT
  SB --> SCRIPT
  IP --> SCRIPT
  CRON --> SCRIPT
  SCRIPT --> OUT
  OUT --> BUILD
  BUILD --> CDB
  CDB --> RULES
  RULES --> DASH
  OUT --> GIT
Daily collector on Kali pulls public threat intelligence feeds, organizes the output, pushes it to GitHub, and updates Wazuh CDB lists used by custom detection rules.
Project Structure
textOpenIOCCollector/
├── Output/
│   └── 2026/
│       └── 2026-08/
├── tweetfeed.py
├── run_andpush.sh
├── requirements.txt
└── README.md
How to Run
Bashgit clone https://github.com/jaguarmayan8/OpenIOCCollector.git
cd OpenIOCCollector
sudo apt install -y python3-requests
python3 tweetfeed.py
Wazuh Integration
Selected IOCs are converted into Wazuh CDB lists and used by custom rules:

Malicious IPs → rule 100100
Malicious domains → rules 100101 / 100102
Malicious hashes → rules 100110 / 100111

The daily collector updates the IP list automatically.
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
textThen:

```bash
