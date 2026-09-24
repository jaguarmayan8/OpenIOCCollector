#!/usr/bin/env python3
from pathlib import Path
from datetime import datetime
import json
import re

BASE = Path("/home/chap/OpenIOCCollector")
OUT_HTML = BASE / "docs" / "index.html"
REPO = "https://github.com/jaguarmayan8/OpenIOCCollector"

def latest_day_dir():
    days = sorted(BASE.glob("Output/*/*/[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]"))
    if not days:
        raise SystemExit("No daily output folders found")
    return days[-1]

def count_lines(path):
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip())

def parse_summary(path):
    feeds = []
    success = "n/a"
    total = "n/a"
    run_time = path.stat().st_mtime
    if path.exists():
        text = path.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r"Daily IOC Report - (.+)", text)
        run_label = m.group(1).strip() if m else datetime.fromtimestamp(run_time).strftime("%Y-%m-%d %H:%M")
        for line in text.splitlines():
            m = re.search(r"\*\*(.+?)\*\*:\s*(.+)", line)
            if m and "Success rate" not in m.group(1) and "Approximate" not in m.group(1):
                name, detail = m.group(1), m.group(2)
                status = "empty" if "Empty" in detail else "ok"
                feeds.append({"name": name, "detail": detail, "status": status})
        m = re.search(r"Success rate:\*\*\s*(.+)", text)
        if m:
            success = m.group(1).strip()
        m = re.search(r"Approximate total IOCs collected:\*\*\s*(.+)", text)
        if m:
            total = m.group(1).strip()
    else:
        run_label = datetime.fromtimestamp(run_time).strftime("%Y-%m-%d %H:%M")
    return run_label, feeds, success, total

def vt_rows(json_path, md_path):
    rows = []
    if json_path.exists():
        data = json.loads(json_path.read_text(encoding="utf-8"))
        for item in data:
            rows.append({
                "hash": item.get("hash", ""),
                "found": str(item.get("found", "")),
                "malicious": item.get("malicious", ""),
                "suspicious": item.get("suspicious", ""),
                "label": item.get("label", "") or "",
                "malware": item.get("threatfox_malware", "") or "",
            })
        return rows
    if md_path.exists():
        for line in md_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("| `"):
                parts = [p.strip().strip("`") for p in line.strip("|").split("|")]
                if len(parts) >= 6:
                    rows.append({
                        "hash": parts[0],
                        "found": parts[1],
                        "malicious": parts[2],
                        "suspicious": parts[3],
                        "label": parts[4],
                        "malware": parts[5],
                    })
    return rows

def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def main():
    day = latest_day_dir()
    run_label, feeds, success, total = parse_summary(day / "daily_summary.md")
    ips = count_lines(BASE / "malicious-ips.txt")
    domains = count_lines(BASE / "malicious-domains.txt")
    hashes = count_lines(BASE / "malicious-hashes.txt")
    vt = vt_rows(day / "vt_enrichment.json", day / "vt_enrichment.md")

    feed_html = "\n".join(
        f'<div class="feed {f["status"]}"><b>{esc(f["name"])}</b><span>{esc(f["detail"])}</span></div>'
        for f in feeds
    ) or "<p>No feed summary found.</p>"

    vt_html = "\n".join(
        f"<tr><td class='hash'>{esc(r['hash'][:16])}…</td><td>{esc(r['found'])}</td>"
        f"<td>{esc(r['malicious'])}</td><td>{esc(r['suspicious'])}</td>"
        f"<td>{esc(r['label'])}</td><td>{esc(r['malware'])}</td></tr>"
        for r in vt
    ) or "<tr><td colspan='6'>No VirusTotal sample yet.</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenIOCCollector Dashboard</title>
<style>
  :root {{
    --bg:#0b1220; --card:#121a2b; --line:#243049; --text:#e8eefc;
    --muted:#9aa8c7; --ok:#3ddc97; --bad:#ff6b6b; --accent:#6ea8fe;
  }}
  * {{ box-sizing:border-box; }}
  body {{
    margin:0; font-family:Verdana, Geneva, sans-serif; background:var(--bg); color:var(--text);
  }}
  header, main {{ max-width:1100px; margin:0 auto; padding:24px; }}
  header {{ padding-top:36px; }}
  h1 {{ margin:0 0 8px; font-size:28px; }}
  .sub {{ color:var(--muted); }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin:24px 0; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:14px; padding:18px; }}
  .num {{ font-size:28px; font-weight:700; }}
  .label {{ color:var(--muted); margin-top:6px; font-size:13px; }}
  .feeds {{ display:grid; gap:10px; }}
  .feed {{ display:flex; justify-content:space-between; gap:12px; background:#0f1726; padding:12px 14px; border-radius:10px; }}
  .ok {{ border-left:4px solid var(--ok); }}
  .empty {{ border-left:4px solid var(--bad); }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ text-align:left; padding:10px 8px; border-bottom:1px solid var(--line); }}
  th {{ color:var(--muted); font-weight:600; }}
  .hash {{ font-family:monospace; }}
  a {{ color:var(--accent); }}
</style>
</head>
<body>
<header>
  <h1>OpenIOCCollector</h1>
  <p class="sub">Home-lab threat intel dashboard · last run {esc(run_label)}</p>
</header>
<main>
  <section class="grid">
    <div class="card"><div class="num">{ips:,}</div><div class="label">Malicious IPs</div></div>
    <div class="card"><div class="num">{domains:,}</div><div class="label">Malicious domains</div></div>
    <div class="card"><div class="num">{hashes:,}</div><div class="label">Malicious hashes</div></div>
    <div class="card"><div class="num">{esc(success)}</div><div class="label">Feeds with data</div></div>
  </section>

  <section class="card">
    <h2>Today's feeds</h2>
    <div class="feeds">{feed_html}</div>
    <p class="sub">Approximate total IOCs collected: {esc(total)}</p>
  </section>

  <section class="card" style="margin-top:16px;">
    <h2>VirusTotal sample</h2>
    <table>
      <thead>
        <tr><th>Hash</th><th>Found</th><th>Malicious</th><th>Suspicious</th><th>VT label</th><th>ThreatFox</th></tr>
      </thead>
      <tbody>
        {vt_html}
      </tbody>
    </table>
  </section>

  <p style="margin-top:24px;">
    <a href="{REPO}">GitHub repository</a> ·
    <a href="{REPO}/tree/main/{day.relative_to(BASE).as_posix()}">Today's raw output</a>
  </p>
</main>
</body>
</html>
"""
    OUT_HTML.parent.mkdir(parents=True, exist_ok=True)
    OUT_HTML.write_text(html, encoding="utf-8")
    print(f"Wrote {OUT_HTML}")

if __name__ == "__main__":
    main()
