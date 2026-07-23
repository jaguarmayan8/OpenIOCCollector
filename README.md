# TwitterIoCsfeed

Automated daily collection of Indicators of Compromise (IOCs) from public threat intelligence feeds.

## Features

- Collects IOCs from multiple reliable sources (URLhaus, ThreatFox, Feodo Tracker, SSL Blacklist, etc.)
- Organizes files into daily folders (`Output/YYYYMMDD/`)
- Runs automatically every day at 8:00 AM Central Time
- Pushes new files to this GitHub repository

## Feeds Included

- URLhaus (malware URLs)
- ThreatFox (malware IOCs)
- Feodo Tracker (C2 IPs)
- SSL Blacklist
- Top malicious IP list

## Quick Start

```bash
git clone https://github.com/jaguarmayan8/TwitterIoCsfeed.git
cd TwitterIoCsfeed
docker compose build
docker compose run --rm iocsfeed
Daily Automation
A cron job runs every day at 8:00 AM Central Time.
Output
Files are saved in the Output/ folder, organized by date, and automatically pushed to this repository.
Author
Jorge Tejada 
License
GPL-3.0
