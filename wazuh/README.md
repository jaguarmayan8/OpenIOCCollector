# Wazuh Integration

This folder contains the integration pieces between the daily IOC feed and the Wazuh Manager running on the Ubuntu lab box.

## Overview

- **Collector (Kali)**: Gathers IOCs daily and pushes them to the main repository
- **Wazuh Manager (Ubuntu)**: Ingests selected IOC files for detection and threat hunting

## Current Integration Method

IOCs are currently consumed from the `Output/YYYYMMDD/` folders in this repository.

Common approaches used in this lab:

- Loading selected IOC files into Wazuh **CDB lists**
- Custom **decoder + rule** pairs for specific feeds (e.g. URLhaus, ThreatFox, Feodo)
- Manual or scripted pull of the latest daily files into the Wazuh manager

## Folder Contents

| Path          | Purpose                              |
|---------------|--------------------------------------|
| `rules/`      | Custom Wazuh rules                   |
| `lists/`      | CDB lists or processed IOC feeds     |
| `scripts/`    | Helper scripts for ingest / updates  |

## Notes

- The Wazuh Manager and Dashboard run on a dedicated Ubuntu VM
- This integration is intended for lab/practice use (detection engineering, rule tuning, and hunting)
- Future improvements may include automated ingestion via API or active response
