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

| Feed              | Type                  | Status      | Notes                     |
|-------------------|-----------------------|-------------|---------------------------|
| URLhaus           | Malware URLs          | Active      | abuse.ch                  |
| ThreatFox         | Malware IOCs          | Active      | abuse.ch                  |
| SSL Blacklist     | Malicious certificates| Active      | abuse.ch                  |
| Feodo Tracker     | Botnet C2 IPs         | Empty       | Currently no active C2s   |
| Top Malicious IPs | IP blocklist          | Active      | -                         |

## Project Structure

```text
TwitterIoCsfeed/
├── Output/
│   └── 2026/
│       └── 2026-08/
├── tweetfeed.py
├── requirements.txt
└── README.md
How It Works

The script downloads the latest IOCs from configured feeds.
Files are saved into daily folders.
Folders are later organized into Year/Year-Month structure.
Results are pushed to this repository.

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
text---

### How to use it:

1. On your Kali box, go to the project folder:
```bash
cd ~/TwitterIoCsfeed
