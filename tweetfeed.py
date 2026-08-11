from datetime import datetime
from pathlib import Path
import sys
import requests

print("=== IOC Collector Started ===")

today = datetime.now().strftime("%Y%m%d")
OUTPUT_DIR = Path("Output") / today
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

feeds = [
    ("ssl_blacklist.csv", "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"),
    ("urlhaus.csv", "https://urlhaus.abuse.ch/downloads/csv_online/"),
    # Feodo Tracker is currently empty due to successful takedowns
    ("feodo_tracker.txt", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    ("threatfox_recent.json", "https://threatfox.abuse.ch/export/json/recent/"),
    ("top_malicious.txt", "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"),
]

success_count = 0
summary = [f"# Daily IOC Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}", ""]

for filename, url in feeds:
    print(f"[*] Downloading {filename}...")
    try:
        r = requests.get(url, timeout=45)
        r.raise_for_status()

        content = r.content
        size_kb = len(content) / 1024
        path = OUTPUT_DIR / filename

        with open(path, "wb") as f:
            f.write(content)

        if size_kb < 1:  # Less than 1 KB
            print(f"[!] {filename}: Empty or nearly empty ({size_kb:.1f} KB) - this may be expected")
            summary.append(f"- **{filename}**: Empty ({size_kb:.1f} KB)")
        else:
            print(f"[+] Saved {filename} ({size_kb:.1f} KB)")
            summary.append(f"- **{filename}**: {size_kb:.1f} KB")
            success_count += 1

    except Exception as e:
        print(f"[!] Error downloading {filename}: {e}")
        summary.append(f"- **{filename}**: Error - {e}")

# Write summary report
report_path = OUTPUT_DIR / "daily_summary.md"
with open(report_path, "w") as f:
    f.write("\n".join(summary))
    f.write(f"\n\n**Success rate:** {success_count}/{len(feeds)} feeds with data")

print(f"\n[+] Summary report saved: {report_path.name}")
print(f"[+] Successfully downloaded {success_count}/{len(feeds)} feeds with data")
print("=== IOC Collector Finished ===")

# Exit with error only if almost everything failed
if success_count < 2:
    print("[!] Too many failures - exiting with error")
    sys.exit(1)
else:
    sys.exit(0)
