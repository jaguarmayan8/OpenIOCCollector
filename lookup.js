/* In-page IOC lookup - no backend.
 *
 * On first keystroke the three CDB lists are fetched once from the repo's raw
 * URLs (raw.githubusercontent.com answers `access-control-allow-origin: *`,
 * verified against the live files), indexed into a Map, and queried locally.
 * Nothing typed is ever sent anywhere.
 *
 * The parser accepts both list formats, because the published lists may carry
 * either:
 *     1.2.3.4:                  CDB terminator, no metadata
 *     1.2.3.4:threatfox:100     value, source, confidence
 * IPv6 needs care: `2001:db8::1:` ends in a colon that is the CDB terminator,
 * not a separator, so a tail is only read as metadata when it looks like one.
 *
 * Normalisation mirrors ioc_extract.py's extract_host(): a pasted URL, port,
 * userinfo, trailing dot or `www.` prefix must not turn a listed indicator into
 * a false "not in today's lists".
 */
(function () {
  "use strict";

  var CFG = /*__CONFIG__*/ {};
  var root = (typeof window !== "undefined") ? window : globalThis;

  function fmt(n) {
    return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }

  function isIpv4(s) {
    var p = s.split(".");
    if (p.length !== 4) { return false; }
    for (var i = 0; i < 4; i++) {
      if (!/^\d{1,3}$/.test(p[i])) { return false; }
      if (+p[i] > 255) { return false; }
      /* 01.2.3.4 is a different string to the feed's 1.2.3.4, not a match. */
      if (p[i].length > 1 && p[i].charAt(0) === "0") { return false; }
    }
    return true;
  }

  function isIpv6(s) {
    if (s.indexOf(":") < 0) { return false; }
    if (!/^[0-9a-f:.]+$/.test(s)) { return false; }
    /* "2001:db8::1:" is a CDB terminator artifact, not an address. */
    if (s.charAt(s.length - 1) === ":" && s.slice(-2) !== "::") { return false; }
    return s.indexOf(":") !== s.lastIndexOf(":");
  }

  function isDomain(s) {
    if (s.length > 253) { return false; }
    if (!/^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/.test(s)) { return false; }
    /* an all-numeric last label is an IP, not a TLD */
    return /^[a-z0-9-]{2,}$/.test(s.slice(s.lastIndexOf(".") + 1));
  }

  function isValue(s) {
    return isIpv4(s) || isIpv6(s) || isHash(s) || isDomain(s);
  }

  function isTagLike(s) { return /^[A-Za-z0-9_.|,\-:]+$/.test(s); }

  function isHash(s) {
    return /^[0-9a-f]{32}$/.test(s) ||
           /^[0-9a-f]{40}$/.test(s) ||
           /^[0-9a-f]{64}$/.test(s);
  }

  /* Strip everything a user may paste around the indicator itself. */
  function strip(raw) {
    var s = String(raw == null ? "" : raw).trim().slice(0, 2048);
    if (!s) { return ""; }
    s = s.replace(/\s+/g, "");
    s = s.replace(/^[A-Za-z][A-Za-z0-9+.\-]*:\/\//, ""); /* scheme:// incl. hxxp:// */
    s = s.replace(/^\/\//, "");
    s = s.replace(/^[^@\/]*@/, "");                      /* userinfo@ */
    return s;
  }

  function hostOf(s) {
    var m = /^\[([^\]]+)\]/.exec(s);
    if (m) { return m[1]; }                              /* [2001:db8::1]:80 */
    var i = s.search(/[\/?#]/);
    return i < 0 ? s : s.slice(0, i);
  }

  function dropPort(s) {
    var p = s.split(":");
    return (p.length === 2 && /^\d{1,5}$/.test(p[1])) ? p[0] : s;
  }

  /* -> {value, kind, candidates} or null.
     Candidates exist because `www.` is listed sometimes and omitted sometimes;
     both forms are checked rather than picking one and guessing. */
  function normalize(raw) {
    var s = strip(raw);
    if (!s) { return null; }
    var host = dropPort(hostOf(s)).replace(/\.+$/, "").toLowerCase();
    if (!host) { return null; }
    var kind = "domain";
    if (isIpv4(host) || isIpv6(host)) { kind = "ip"; }
    else if (isHash(host)) { kind = "hash"; }
    var candidates = [host];
    if (kind === "domain" && host.indexOf("www.") === 0 && host.length > 4) {
      candidates.push(host.slice(4));
    }
    return { value: host, kind: kind, candidates: candidates };
  }

  /* One list line -> {value, tag} or null. */
  function parseLine(line) {
    if (!line) { return null; }
    var v = String(line).replace(/^\s+/, "").replace(/\s+$/, "");
    if (!v || v.charAt(0) === "#") { return null; }

    /* "value:" - the plain CDB form. Tested FIRST, because splitting
       "2001:db8::1:" on its last colon would yield value "2001:db8::" tag "1". */
    if (v.charAt(v.length - 1) === ":" && isValue(v.slice(0, -1))) {
      return { value: v.slice(0, -1), tag: "" };
    }
    if (isValue(v)) { return { value: v, tag: "" }; }

    /* "value:source:confidence" - split at a colon whose LEFT side is a whole
       indicator, so "1.2.3.4:threatfox:100" gives value "1.2.3.4" and tag
       "threatfox:100" rather than value "1.2.3.4:threatfox" and tag "100". */
    for (var i = v.lastIndexOf(":"); i > 0; i = v.lastIndexOf(":", i - 1)) {
      var head = v.slice(0, i);
      if (!isValue(head)) { continue; }
      var rest = v.slice(i + 1);
      if (rest === "") { return { value: head, tag: "" }; }
      if (isTagLike(rest)) { return { value: head, tag: rest }; }
    }
    /* A URL-valued list (proxy/Suricata) keeps its full value. */
    return { value: v, tag: "" };
  }

  /* "threatfox:100" -> {source:"threatfox", confidence:"100"}
     Multi-feed entries arrive as "threatfox:100|urlhaus" (strongest first);
     the verdict names the strongest one. */
  function parseTag(tag) {
    if (!tag) { return { source: "", confidence: "" }; }
    var parts = String(tag).split("|");
    var best = { source: "", confidence: "" };
    var bestScore = -1;
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i].trim();
      if (!p) { continue; }
      var seg = p.split(":");
      var src = p;
      var conf = "";
      if (seg.length >= 2 && /^\d{1,3}$/.test(seg[seg.length - 1])) {
        conf = seg[seg.length - 1];
        src = seg.slice(0, -1).join(":");
      }
      var score = conf === "" ? 0 : parseInt(conf, 10);
      if (score > bestScore) { bestScore = score; best = { source: src, confidence: conf }; }
    }
    return best;
  }

  function buildIndex(text) {
    var lines = String(text).split("\n");
    var map = new Map();
    for (var i = 0; i < lines.length; i++) {
      var row = parseLine(lines[i]);
      if (row) { map.set(row.value, row.tag); }
    }
    return map;
  }

  function lookup(indices, norm) {
    var hits = [];
    if (!indices || !norm) { return hits; }
    for (var k in indices) {
      if (!Object.prototype.hasOwnProperty.call(indices, k)) { continue; }
      var map = indices[k];
      for (var i = 0; i < norm.candidates.length; i++) {
        var v = norm.candidates[i];
        if (map.has(v)) {
          var t = parseTag(map.get(v));
          hits.push({ list: k, value: v, source: t.source, confidence: t.confidence });
          break;
        }
      }
    }
    return hits;
  }

  function vtUrl(norm) {
    if (norm.kind === "hash") { return "https://www.virustotal.com/gui/file/" + norm.value; }
    if (norm.kind === "ip") { return "https://www.virustotal.com/gui/ip-address/" + norm.value; }
    return "https://www.virustotal.com/gui/domain/" + norm.value;
  }

  /* Exposed so the parser can be unit-tested under node (tests/test_lookup.py).
     A wrong normalisation silently turns a real IOC into "not found", which is
     worse than having no lookup at all. */
  root.IOCLookup = {
    normalize: normalize,
    parseLine: parseLine,
    parseTag: parseTag,
    buildIndex: buildIndex,
    lookup: lookup,
    isIpv4: isIpv4,
    isIpv6: isIpv6,
    isHash: isHash
  };

  if (typeof document === "undefined") { return; }
  var form = document.getElementById("ioc-lookup-form");
  if (!form) { return; }

  var input = document.getElementById("ioc-input");
  var statusEl = document.getElementById("ioc-lookup-status");
  var resultEl = document.getElementById("ioc-lookup-result");
  var indices = null;
  var loading = null;
  var failed = null;
  var timer = null;

  function setStatus(text, cls) {
    statusEl.textContent = text;
    statusEl.className = "status" + (cls ? " " + cls : "");
  }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) { n.className = cls; }
    if (text !== undefined && text !== null) { n.textContent = text; }
    return n;
  }

  function labelFor(key) {
    for (var i = 0; i < CFG.lists.length; i++) {
      if (CFG.lists[i].key === key) { return CFG.lists[i].label; }
    }
    return key;
  }

  function loadedCount() {
    var t = 0;
    for (var k in indices) {
      if (Object.prototype.hasOwnProperty.call(indices, k)) { t += indices[k].size; }
    }
    return t;
  }

  function expectedCount() {
    var t = 0;
    for (var k in CFG.counts) {
      if (Object.prototype.hasOwnProperty.call(CFG.counts, k)) { t += CFG.counts[k] || 0; }
    }
    return t;
  }

  function downloadLinks(parent) {
    CFG.lists.forEach(function (l, i) {
      if (i) { parent.appendChild(document.createTextNode(" · ")); }
      var a = el("a", "", l.path);
      a.href = CFG.raw + l.path;
      parent.appendChild(a);
    });
    return parent;
  }

  /* ---------------------------------------------------------------------
   * Cache + progress
   *
   * The IP list is ~3 MB and it changes once a day, so without a cache every
   * visit re-downloads all of it before the first lookup can answer - on a
   * phone that is a multi-second freeze that looks like a broken page.
   * IndexedDB keeps the text keyed by the date it belongs to: a second visit
   * is instant, a new day misses the cache and refetches. A browser that
   * refuses IndexedDB (private mode, storage disabled) takes the plain fetch
   * path - the cache is an optimisation, never a requirement.
   * ------------------------------------------------------------------- */
  var DB_NAME = "openiocollector";
  var DB_STORE = "lists";

  function openDb() {
    if (typeof indexedDB === "undefined") { return Promise.resolve(null); }
    return new Promise(function (resolve) {
      var req;
      try { req = indexedDB.open(DB_NAME, 1); } catch (e) { return resolve(null); }
      req.onupgradeneeded = function () {
        var db = req.result;
        if (!db.objectStoreNames.contains(DB_STORE)) { db.createObjectStore(DB_STORE, { keyPath: "path" }); }
      };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { resolve(null); };
      req.onblocked = function () { resolve(null); };
    });
  }

  function cacheRead(paths, day) {
    return openDb().then(function (db) {
      if (!db) { return null; }
      return new Promise(function (resolve) {
        var out = {}, pending = paths.length;
        if (!pending) { return resolve(null); }
        var tx;
        try { tx = db.transaction(DB_STORE, "readonly"); } catch (e) { return resolve(null); }
        var store = tx.objectStore(DB_STORE);
        paths.forEach(function (path) {
          var req = store.get(path);
          req.onsuccess = function () {
            var row = req.result;
            /* A row from another day is a miss: a stale index would answer
               "not in today's lists" for something added today. */
            if (row && row.day === day && typeof row.text === "string") { out[path] = row.text; }
            pending -= 1;
            if (!pending) { resolve(Object.keys(out).length === paths.length ? out : null); }
          };
          req.onerror = function () { pending -= 1; if (!pending) { resolve(null); } };
        });
      });
    }).catch(function () { return null; });
  }

  function cacheWrite(items, day) {
    openDb().then(function (db) {
      if (!db) { return; }
      try {
        var tx = db.transaction(DB_STORE, "readwrite");
        var store = tx.objectStore(DB_STORE);
        items.forEach(function (it) { store.put({ path: it.path, day: day, text: it.text }); });
      } catch (e) { /* quota or a locked DB - the next visit re-downloads */ }
    }).catch(function () {});
  }

  /* Fetch with a real percentage. raw.githubusercontent sends
     content-length, so the reader can report bytes received; without a body
     stream (older browsers) this falls back to a plain r.text(). */
  function fetchText(path, onProgress) {
    return fetch(CFG.raw + path, { mode: "cors" }).then(function (r) {
      if (!r.ok) { throw new Error(path + " -> HTTP " + r.status); }
      var total = parseInt(r.headers.get("content-length") || "0", 10);
      if (!r.body || typeof r.body.getReader !== "function" || !total) { return r.text(); }
      var reader = r.body.getReader();
      var chunks = [], received = 0;
      return (function pump() {
        return reader.read().then(function (step) {
          if (step.done) {
            var all = new Uint8Array(received), off = 0;
            for (var i = 0; i < chunks.length; i++) { all.set(chunks[i], off); off += chunks[i].byteLength; }
            return new TextDecoder("utf-8").decode(all);
          }
          chunks.push(step.value);
          received += step.value.byteLength;
          onProgress(Math.min(1, received / total));
          return pump();
        });
      })();
    });
  }

  function load() {
    if (indices) { return Promise.resolve(indices); }
    if (loading) { return loading; }
    var day = CFG.dataDate || "";
    var paths = CFG.lists.map(function (l) { return l.path; });
    var acc = {};
    var done = 0;

    setStatus("Loading " + fmt(expectedCount()) + " indicators\u2026", "");

    loading = cacheRead(paths, day).then(function (hit) {
      if (hit) {
        CFG.lists.forEach(function (l) { acc[l.key] = buildIndex(hit[l.path]); });
        setStatus("Loading lists\u2026 cached copy", "");
        return acc;
      }
      var texts = [];
      return Promise.all(CFG.lists.map(function (l) {
        return fetchText(l.path, function (p) {
          setStatus(
            "Loading " + l.path + "\u2026 " + Math.round(p * 100) + "% (" +
            (done + 1) + "/" + CFG.lists.length + " files)", ""
          );
        }).then(function (text) {
          texts.push({ path: l.path, text: text });
          acc[l.key] = buildIndex(text);
          done += 1;
          setStatus(
            "Loading lists\u2026 " + done + "/" + CFG.lists.length +
            " (" + fmt(acc[l.key].size) + " " + labelFor(l.key).toLowerCase() + ")",
            ""
          );
          return acc;
        });
      })).then(function () {
        cacheWrite(texts, day);
        return acc;
      });
    }).then(function () {
      indices = acc;
      var stale = CFG.stale
        ? " · STALE: the nightly run failed, these lists are from " + CFG.dataDate
        : "";
      setStatus(
        "Ready · " + fmt(loadedCount()) + " indicators · data for " + CFG.dataDate + stale,
        CFG.stale ? "err" : ""
      );
      return indices;
    }).catch(function (err) {
      failed = err;
      loading = null;
      setStatus(
        "Lookup unavailable: " + err.message +
        ". The lists could not be fetched (offline, blocked, or the repo is private).", "err"
      );
      var p = el("p", "hint", "Download them directly: ");
      downloadLinks(p);
      resultEl.textContent = "";
      resultEl.className = "result miss";
      resultEl.hidden = false;
      resultEl.appendChild(p);
      throw err;
    });
    return loading;
  }

  function show(norm) {
    var hits = lookup(indices, norm);
    var cls = "result " + (hits.length ? "hit" : "miss");
    if (hits.length) {
      var max = 0;
      hits.forEach(function (h) { if (h.confidence) { max = Math.max(max, +h.confidence); } });
      if (max && max < 75) { cls += " low"; }
    }
    resultEl.textContent = "";
    resultEl.className = cls;
    resultEl.hidden = false;

    var verdict;
    if (!hits.length) {
      verdict = "Not in today's lists";
    } else if (hits[0].source) {
      verdict = "Found — " + hits[0].source +
        (hits[0].confidence ? ", confidence " + hits[0].confidence : "");
    } else {
      verdict = "Found in the " + labelFor(hits[0].list);
    }
    resultEl.appendChild(el("div", "verdict", verdict));
    resultEl.appendChild(el("div", "val", norm.value));

    if (hits.length) {
      var dl = el("dl");
      hits.forEach(function (h) {
        dl.appendChild(el("dt", "", "List"));
        dl.appendChild(el("dd", "", labelFor(h.list)));
        if (h.value !== norm.value) {
          dl.appendChild(el("dt", "", "Matched as"));
          dl.appendChild(el("dd", "", h.value));
        }
        dl.appendChild(el("dt", "", "Source"));
        dl.appendChild(el("dd", "", h.source || "not tagged in this list version"));
        if (h.confidence) {
          dl.appendChild(el("dt", "", "Confidence"));
          dl.appendChild(el("dd", "", h.confidence));
        }
      });
      resultEl.appendChild(dl);
      if (!hits[0].source) {
        resultEl.appendChild(el("p", "hint",
          "This list version stores bare values, so the reporting feed is not recorded — " +
          "only that the indicator is in today's published list."));
      }
    } else {
      resultEl.appendChild(el("p", "hint",
        "Checked against " + fmt(loadedCount()) + " indicators for " + CFG.dataDate +
        ". Absent means these feeds have not reported it; that is not a clean bill of health."));
    }

    var a = el("a", "", "Check on VirusTotal ↗");
    a.href = vtUrl(norm);
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    var p = el("p", "hint");
    p.appendChild(a);
    resultEl.appendChild(p);
  }

  function run() {
    var norm = normalize(input.value);
    if (!norm) {
      resultEl.hidden = true;
      setStatus(
        indices ? "Type an IP, domain, URL or file hash."
                : "Type an IP, domain, URL or file hash to load the lists.",
        ""
      );
      return;
    }
    if (failed) { return; }
    if (!indices) {
      load().then(run).catch(function () {});
      return;
    }
    show(norm);
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (timer) { clearTimeout(timer); timer = null; }
    run();
  });

  /* Load on first input, as promised in the UI copy - not on page load, so a
     visitor who never uses the box never pays for 458 KB. */
  input.addEventListener("input", function () {
    if (timer) { clearTimeout(timer); }
    if (!indices && !failed) { load().catch(function () {}); }
    timer = setTimeout(run, 180);
  });
})();
