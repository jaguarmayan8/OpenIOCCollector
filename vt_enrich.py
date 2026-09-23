#!/usr/bin/env python3
import json
import time
from datetime import datetime
from pathlib import Path
import requests

BASE = Path("/home/chap/OpenIOCCollector")
KEY_FILE = BASE / ".vt_api_key"
MAX_HASHES = 20
SLEEP_SECONDS = 16  # free API: 4 requests/minute

def latest_threatfox():
    files = sorted(BASE.glob("Output/*/*/*/threatfox_recent.json"))
    if not files:
        raise SystemExit("No ThreatFox file found")
    return files[-1]

def extract_hashes(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    hashes = []
    seen = set()
    for entries in data.values():
        for item in entries:
            ioc_type = item.get("ioc_type", "")
            value = (item.get("ioc_value") or "").lower()
            if ioc_type in ("md5_hash", "sha1_hash", "sha256_hash") and value and value not in seen:
                seen.add(value)
                hashes.append({
                    "hash": value,
                    "type": ioc_type,
                    "malware": item.get("malware_printable") or item.get("malware") or "",
                    "confidence": item.get("confidence_level"),
                })
    return hashes[:MAX_HASHES]

def vt_lookup(api_key, file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    r = requests.get(url, headers={"x-apikey": api_key}, timeout=30)
    if r.status_code == 404:
        return {"hash": file_hash, "found": False, "malicious": 0, "suspicious": 0, "undetected": 0, "label": ""}
    r.raise_for_status()
    attrs = r.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    label = ""
    classification = attrs.get("popular_threat_classification") or {}
    label = classification.get("suggested_threat_label") or ""
    return {
        "hash": file_hash,
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "label": label,
    }

def main():
    api_key = KEY_FILE.read_text(encoding="utf-8").strip()
    tf_path = latest_threatfox()
    items = extract_hashes(tf_path)
    print(f"Enriching {len(items)} hashes from {tf_path}")

    results = []
    for i, item in enumerate(items, 1):
        print(f"[{i}/{len(items)}] {item['hash']}")
        try:
            result = vt_lookup(api_key, item["hash"])
            result["threatfox_malware"] = item["malware"]
            results.append(result)
        except Exception as e:
            results.append({"hash": item["hash"], "error": str(e)})
        if i < len(items):
            time.sleep(SLEEP_SECONDS)

    out_dir = tf_path.parent
    json_path = out_dir / "vt_enrichment.json"
    md_path = out_dir / "vt_enrichment.md"
    json_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    lines = [
        f"# VirusTotal Enrichment - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        f"Sample size: {len(results)} hashes from ThreatFox",
        "",
        "| Hash | Found | Malicious | Suspicious | VT label | ThreatFox malware |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in results:
        lines.append(
            f"| `{row.get('hash','')}` | {row.get('found','')} | {row.get('malicious','')} | {row.get('suspicious','')} | {row.get('label','')} | {row.get('threatfox_malware','')} |"
        )
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")

if __name__ == "__main__":
    main()
