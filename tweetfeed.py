from datetime import datetime
from pathlib import Path
import sys
import requests
import json

print("=== IOC Collector Started ===")

now = datetime.now()
today = now.strftime("%Y%m%d")
year = now.strftime("%Y")
year_month = now.strftime("%Y-%m")

# New organized path: Output/2026/2026-08/20260811/
OUTPUT_DIR = Path("Output") / year / year_month / today
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
total_iocs = 0
summary = [f"# Daily IOC Report - {now.strftime('%Y-%m-%d %H:%M')}", ""]

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

        # Simple IOC counting (line-based)
        try:
            text = content.decode("utf-8", errors="ignore")
            lines = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
            ioc_count = len(lines)
        except:
            ioc_count = 0

        total_iocs += ioc_count

        if size_kb < 1:
            print(f"[!] {filename}: Empty or nearly empty ({size_kb:.1f} KB) - this may be expected")
            summary.append(f"- **{filename}**: Empty ({size_kb:.1f} KB)")
        else:
            print(f"[+] Saved {filename} ({size_kb:.1f} KB) - ~{ioc_count} entries")
            summary.append(f"- **{filename}**: {size_kb:.1f} KB | ~{ioc_count} entries")
            success_count += 1

    except Exception as e:
        print(f"[!] Error downloading {filename}: {e}")
        summary.append(f"- **{filename}**: Error - {e}")


# MalwareBazaar recent samples (hashes + metadata, no binaries)
print("[*] Querying MalwareBazaar get_recent...")
mb_name = "malwarebazaar_recent.json"
mb_path = OUTPUT_DIR / mb_name
try:
    key_file = Path(".abusech_auth_key")
    auth_key = key_file.read_text(encoding="utf-8").strip() if key_file.exists() else ""
    if not auth_key:
        raise RuntimeError("missing .abusech_auth_key")
    r = requests.post(
        "https://mb-api.abuse.ch/api/v1/",
        headers={"Auth-Key": auth_key},
        data={"query": "get_recent", "selector": "100"},
        timeout=45,
    )
    r.raise_for_status()
    payload = r.json()
    mb_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    rows = payload.get("data") or []
    ioc_count = len(rows) if payload.get("query_status") == "ok" else 0
    size_kb = mb_path.stat().st_size / 1024
    total_iocs += ioc_count
    if ioc_count:
        success_count += 1
        print(f"[+] Saved {mb_name} ({size_kb:.1f} KB) - ~{ioc_count} entries")
        summary.append(f"- **{mb_name}**: {size_kb:.1f} KB | ~{ioc_count} entries")
    else:
        print(f"[!] {mb_name}: no samples ({payload.get('query_status')})")
        summary.append(f"- **{mb_name}**: Empty ({payload.get('query_status')})")
except Exception as e:
    print(f"[!] Error querying MalwareBazaar: {e}")
    summary.append(f"- **{mb_name}**: Error - {e}")



# Write summary report
report_path = OUTPUT_DIR / "daily_summary.md"
feed_total = len(feeds) + 1
with open(report_path, "w") as f:
    f.write("\n".join(summary))
    f.write(f"\n\n**Success rate:** {success_count}/{feed_total} feeds with data")
    f.write(f"\n**Approximate total IOCs collected:** {total_iocs}")

print(f"\n[+] Files saved to: {OUTPUT_DIR}")
print(f"[+] Summary report saved: {report_path.name}")
print(f"[+] Successfully downloaded {success_count}/{feed_total} feeds with data")
print("=== IOC Collector Finished ===")

if success_count < 2:
    print("[!] Too many failures - exiting with error")
    sys.exit(1)
else:
    sys.exit(0)
