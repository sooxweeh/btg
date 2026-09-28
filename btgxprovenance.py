#!/usr/bin/env python3
"""
btg_provenance.py - address identification + public-chain provenance reporter.

SCOPE / BOUNDARY
  READ-ONLY. This tool:
    * decodes and validates Base58Check addresses offline,
    * classifies the source chain from the version byte,
    * derives the equivalent address on other chains sharing the same hash160,
    * optionally queries PUBLIC explorers to record whether an address has any
      on-chain history (received / sent / tx count).

  It does NOT derive or guess private keys, search key or seed space, crack
  wallet files, exploit anything, or sign/broadcast transactions. Provenance
  and attribution only. Attacking a wallet requires the key; this tool has no
  key-related code paths and never will.

DEPS
  Python 3 stdlib only. Network steps are strictly opt-in (--btc-check /
  --btg-check); with no flags the tool runs fully offline on supplied data.

USAGE
  python3 btg_provenance.py                       # zero-arg default: selftest +
                                                  # offline report on built-ins
  python3 btg_provenance.py --addresses addrs.txt
  python3 btg_provenance.py --addresses addrs.txt --btc-check
  python3 btg_provenance.py --addresses addrs.txt --btg-check
  python3 btg_provenance.py --addresses addrs.txt --btg-json btg_onchain.json
  python3 btg_provenance.py --selftest

BTG DATA SOURCE
  btgexplorer.com is server-rendered, so it is scraped directly by --btg-check.
  NOTE: btg.tokenview.io is a client-rendered SPA whose index has been
  observed returning 0 transactions for addresses with >100 known transactions
  (observation date 2025; control address and evidence should be archived
  alongside any published claim). Do not rely on it. BTC figures come live
  from Blockstream's public Esplora API.

ORACLE VALIDATION
  Every run with --btg-check first queries a control address known to have
  history (the 2018 BTG attack proceeds address). If the source cannot report
  non-zero for the control, all zero results are flagged UNRELIABLE. Run
  --selftest to check the decode layer, not the oracle.

WHAT THIS DOES *NOT* PROVE (see report section "What this does NOT prove")
  * Does not prove the corresponding private key was never held by anyone.
  * Does not prove the address was never used on chains other than those
    explicitly checked.
  * Does not prove the explorer's index is complete.
  * Version bytes 0x00 and 0x05 are shared by Bitcoin and Bitcoin Cash;
    attribution for those rows is ambiguous at the version-byte level.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.request

ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(ALPH)}

# version byte -> (chain, script type, leading char)
VERSIONS = {
    0x00: ("Bitcoin", "P2PKH", "1"),
    0x05: ("Bitcoin", "P2SH", "3"),
    0x26: ("Bitcoin Gold", "P2PKH", "G"),
    0x17: ("Bitcoin Gold", "P2SH", "A"),
    0x30: ("Litecoin", "P2PKH", "L"),
    0x32: ("Litecoin", "P2SH", "M"),
    0x1e: ("Dogecoin", "P2PKH", "D"),
    0x16: ("Dogecoin", "P2SH", "9"),
    0x24: ("Groestlcoin", "P2PKH", "F"),
    0x6f: ("Bitcoin Testnet", "P2PKH", "m"),
    0xc4: ("Bitcoin Testnet", "P2SH", "2"),
}

AMBIGUOUS_VERSIONS = {
    0x00: "Bitcoin and Bitcoin Cash share this P2PKH version byte",
    0x05: "Bitcoin and Bitcoin Cash share this P2SH version byte",
}

DEFAULT_ADDRESSES = """GTK67VQsQCtueFu6Zo54KfWPPdChxBjmcD
GTjomh2farmDNBJxqPJ7vBB4cBJSj18zaL
GShFHMNkzVsKhNNc5SVwSczAQTQroLXrYC
GKhjHV9PuyP1Py4mmz7tYpC6Q9CMWfZN6k
GfgYHpazi325rvccugYcMpDQi8niXRrVca
GNTyij1FoLr3E43aenRQrFVGmsZKN8D31t
GZ3d6BADNPagYzyG61o5EPeT9Tvmhjmi5k
GQZUnn8BM7NoJYS8PzKU7uLup2QyhYWqDd
GJSQC98gQUNJeAAdvGLQTHPbKnGqHqoERn
GKv1tt6BqdQj6445rpBmwbJ9Kdzz75NTfU"""

UA = "Mozilla/5.0 (provenance-research; read-only address lookup)"
NET_RETRIES = 3
NET_BACKOFF_BASE = 1.0
NET_DELAY_BETWEEN = 0.5


# ----------------------------------------------------------------- base58
def b58decode(s):
    n = 0
    for ch in s:
        idx = _B58_INDEX.get(ch)
        if idx is None:
            raise ValueError("invalid base58 character %r" % ch)
        n = n * 58 + idx
    pad = len(s) - len(s.lstrip("1"))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + body


def b58encode(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = ALPH[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


def encode_address(version, h160):
    payload = bytes([version]) + h160
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + chk)


def decode_check(addr):
    base = {"address": addr, "length": len(addr)}
    try:
        raw = b58decode(addr)
    except ValueError as e:
        base.update({"valid": False, "reason": str(e)})
        return base
    if len(raw) != 25:
        base.update({"valid": False,
                     "reason": "decoded length %d, expected 25" % len(raw)})
        return base
    version, h160, chk = raw[0], raw[1:21], raw[-4:]
    ok = hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == chk
    chain, stype, lead = VERSIONS.get(version, ("unknown", "?", "?"))
    out = {
        "address": addr, "valid": ok, "version": version,
        "version_hex": "0x%02x" % version, "hash160": h160.hex(),
        "chain": chain, "script_type": stype, "leading_char": lead,
        "length": len(addr),
    }
    if version in AMBIGUOUS_VERSIONS:
        out["ambiguous"] = AMBIGUOUS_VERSIONS[version]
    return out


# -------------------------------------------------------------- network
def _get(url, timeout=25, retries=NET_RETRIES):
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:
            last = e
            if attempt < retries - 1:
                time.sleep(NET_BACKOFF_BASE * (2 ** attempt))
    raise last


# -------------------------------------------------------------- chain data
def btc_stats(addr):
    try:
        d = json.loads(_get("https://blockstream.info/api/address/" + addr))
        c, m = d.get("chain_stats", {}), d.get("mempool_stats", {})
        return {
            "chain": "Bitcoin", "tx_count": c.get("tx_count", 0),
            "received": c.get("funded_txo_sum", 0),
            "sent": c.get("spent_txo_sum", 0),
            "mempool_tx_count": m.get("tx_count", 0),
        }
    except Exception as e:
        return {"chain": "Bitcoin", "error": str(e)}


def load_btg_json(path):
    with open(path, "rb") as f:
        blob = f.read()
    ingest_sha = hashlib.sha256(blob).hexdigest()
    doc = json.loads(blob.decode("utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("BTG JSON top level must be an object")
    results = doc.get("results", doc)
    if not isinstance(results, dict):
        raise ValueError("BTG JSON 'results' must be a dict of "
                         "{address: {...}}")
    src = doc.get("source", "supplied file")
    obs = doc.get("observed", "unknown date")
    out = {}
    for a, v in results.items():
        if not isinstance(v, dict):
            continue
        row = dict(v)
        row.setdefault("source", src)
        row.setdefault("observed", obs)
        out[a] = row
    meta = {
        "source": src, "observed": obs,
        "ingest_sha256": ingest_sha,
        "ingest_path": os.path.abspath(path),
        "rows": len(out),
    }
    return out, meta


# ------------------------------------------------- oracle validation
ORACLE_CONTROL = {
    "address": "GTNjvCGssb2rbLnDV1xxsHmunQdvXnY2Ft",
    "expect_min_tx": 100,
    "why": "documented 2018 BTG 51%-attack proceeds address; any working BTG "
           "index must report nonzero history for it",
}

BTG_EXPLORER = "https://btgexplorer.com/address/"


def _parse_number(s):
    if s is None:
        return None
    s = str(s).strip()
    if not s:
        return None
    if "," in s and "." in s:
        if s.rfind(",") > s.rfind("."):
            s = s.replace(".", "").replace(",", ".")
        else:
            s = s.replace(",", "")
    elif "," in s:
        parts = s.split(",")
        if all(len(p) == 3 for p in parts[1:]):
            s = s.replace(",", "")
        else:
            s = s.replace(",", ".")
    elif "." in s:
        parts = s.split(".")
        if all(len(p) == 3 for p in parts[1:]):
            s = s.replace(".", "")
        else:
            s = s.split(".")[0]
    try:
        return int(s)
    except ValueError:
        return None


def btgexplorer_stats(addr, timeout=25):
    try:
        html = _get(BTG_EXPLORER + addr, timeout=timeout)
    except Exception as e:
        return {"chain": "Bitcoin Gold", "source": "btgexplorer.com",
                "error": "fetch failed: %s" % e}

    flat = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))

    def grab(label):
        m = re.search(
            re.escape(label) + r"\s*([0-9][0-9.,]*)\s*BTG",
            flat, re.IGNORECASE)
        return m.group(1) if m else None

    m_tx = re.search(r"Transactions\s*([0-9][0-9.,]*)", flat, re.IGNORECASE)

    raw = {
        "received": grab("Total Received"),
        "sent": grab("Total Sent"),
        "balance": grab("Final Balance"),
        "tx_count": m_tx.group(1) if m_tx else None,
    }

    out = {"chain": "Bitcoin Gold", "source": "btgexplorer.com"}
    missing = []
    for k in ("received", "sent", "balance"):
        if raw[k] is None:
            missing.append(k)
            out[k] = None
        else:
            n = _parse_number(raw[k])
            out[k] = n if n is not None else raw[k]
            if n is None:
                missing.append(k)
    if raw["tx_count"] is None:
        missing.append("tx_count")
        out["tx_count"] = None
    else:
        n = _parse_number(raw["tx_count"])
        out["tx_count"] = n if n is not None else raw["tx_count"]
        if n is None:
            missing.append("tx_count")
    if missing:
        out["error"] = "could not parse: " + ", ".join(missing)
    return out


def validate_oracle():
    try:
        st = btgexplorer_stats(ORACLE_CONTROL["address"])
    except Exception as e:
        return False, {"chain": "Bitcoin Gold", "source": "btgexplorer.com",
                       "error": "control fetch failed: %s" % e}
    if "error" in st:
        return False, st
    n = st.get("tx_count")
    if not isinstance(n, int):
        return False, st
    return n >= ORACLE_CONTROL["expect_min_tx"], st


# ------------------------------------------------------------------- report
def build_report(rows, btc=None, btg=None, note_extra=None,
                 oracle=None, btg_meta=None, addr_source="defaults"):
    btc = btc or {}
    btg = btg or {}
    btg_meta = btg_meta or {}
    note_extra = note_extra or []
    t = time.strftime("%Y-%m-%d %H:%M:%S")

    L = ["# BTG Address Provenance Report", "",
         "Generated: %s" % t,
         "Address source: %s" % addr_source,
         "Method: Base58Check decode + public explorer lookups. Read-only; "
         "no key derivation, no key/seed search, no wallet cracking.", ""]

    valid = [r for r in rows if r.get("valid")]
    L += ["## Summary", ""]
    L.append("- Addresses inspected: %d (valid: %d, invalid: %d)"
             % (len(rows), len(valid), len(rows) - len(valid)))
    if btc:
        nz = [r for r in rows if isinstance(btc.get(r["address"]), dict)
              and btc[r["address"]].get("tx_count", 0) > 0]
        L.append("- BTC history: %d of %d have non-zero transaction count"
                 % (len(nz), len(rows)))
    if btg:
        nz_btg = []
        for r in rows:
            b = btg.get(r["address"], {})
            tc = b.get("tx_count")
            if isinstance(tc, int) and tc > 0:
                nz_btg.append(r)
        L.append("- BTG history: %d of %d have non-zero transaction count"
                 % (len(nz_btg), len(rows)))
    L.append("")

    L += ["## Address identification", "",
          "| address | len | version | chain | type | checksum | note |",
          "|---|---|---|---|---|---|---|"]
    for r in rows:
        note = r.get("ambiguous", "")
        L.append("| `%s` | %d | %s | %s | %s | %s | %s |"
                 % (r["address"], r["length"],
                    r.get("version_hex", "-"),
                    r.get("chain", "-"),
                    r.get("script_type", "-"),
                    "VALID" if r.get("valid") else "INVALID",
                    note))
    if any(not r.get("valid") for r in rows):
        L += ["", "Rows marked INVALID failed Base58Check decoding; they are "
                  "excluded from derived and explorer sections below."]

    valid_rows = [r for r in rows if r.get("valid") and "hash160" in r]
    if valid_rows:
        L += ["", "## BTC-equivalent keys (same hash160)", "",
              "These encode the identical hash160 under Bitcoin's version byte, "
              "so the same key would control them. Used as a cross-chain "
              "provenance signal.", "",
              "| BTG address | hash160 | BTC equivalent |",
              "|---|---|---|"]
        for r in valid_rows:
            L.append("| `%s` | `%s` | `%s` |"
                     % (r["address"], r["hash160"],
                        encode_address(0x00, bytes.fromhex(r["hash160"]))))

    if btc:
        L += ["", "## Bitcoin chain history (equivalent keys)", "",
              "| BTC equivalent | tx_count | received (sat) | sent (sat) |",
              "|---|---|---|---|"]
        for r in valid_rows:
            b = btc.get(r["address"], {})
            eq = encode_address(0x00, bytes.fromhex(r["hash160"]))
            if "error" in b:
                L.append("| `%s` | error: %s | - | - |" % (eq, b["error"]))
            else:
                L.append("| `%s` | %s | %s | %s |"
                         % (eq, b.get("tx_count"), b.get("received"),
                            b.get("sent")))

    if oracle is not None:
        ok, ost = oracle
        L += ["", "## Oracle validation (positive control)", "",
              "A zero-transaction result is only meaningful if the data source "
              "can be shown to report NON-zero for an address known to have "
              "history. Control: `%s` - %s."
              % (ORACLE_CONTROL["address"], ORACLE_CONTROL["why"]), "",
              "| control address | reported transactions | expected | verdict |",
              "|---|---|---|---|"]
        reported = ost.get("tx_count")
        if "error" in ost:
            verdict = "FAIL - control fetch errored: %s" % ost["error"]
        elif isinstance(reported, int) and reported >= ORACLE_CONTROL["expect_min_tx"]:
            verdict = "PASS - negatives below are credible"
        else:
            verdict = "FAIL - NEGATIVES BELOW ARE UNRELIABLE"
        L.append("| `%s` | %s | >= %d | %s |"
                 % (ORACLE_CONTROL["address"],
                    reported if reported is not None else "-",
                    ORACLE_CONTROL["expect_min_tx"], verdict))
        if not ok:
            L += ["", "**WARNING:** the BTG data source FAILED the positive "
                      "control. The zero-history rows below may reflect a "
                      "broken or incomplete index rather than genuinely unused "
                      "addresses. Do not rely on them until a source passes "
                      "this control."]

    if btg:
        srcs = sorted({str(v.get("source", "?"))
                       for v in btg.values() if v.get("source")})
        obs = sorted({str(v.get("observed", "?"))
                      for v in btg.values() if v.get("observed")})
        hdr = "Source: %s" % (", ".join(srcs) or "?")
        if obs:
            hdr += " | observed: " + ", ".join(obs)
        L += ["", "## Bitcoin Gold chain history", "", hdr]
        if btg_meta.get("ingest_sha256"):
            L += ["", "Ingest file: `%s`  " % btg_meta.get("ingest_path", "?"),
                  "SHA-256: `%s`" % btg_meta["ingest_sha256"]]
        L += ["",
              "| address | received | sent | balance | transactions |",
              "|---|---|---|---|---|"]
        for r in valid_rows:
            b = btg.get(r["address"], {})
            if "error" in b:
                L.append("| `%s` | error: %s | - | - | - |"
                         % (r["address"], b["error"]))
            else:
                L.append("| `%s` | %s BTG | %s BTG | %s BTG | %s |"
                         % (r["address"],
                            b.get("received", "-"),
                            b.get("sent", "-"),
                            b.get("balance", "-"),
                            b.get("tx_count", "-")))

    L += ["", "## What this does NOT prove", "",
          "- Does **not** prove the corresponding private key was never held "
          "by anyone.",
          "- Does **not** prove the address was never used on chains other "
          "than those explicitly checked here.",
          "- Does **not** prove the explorer's index is complete; a pruned or "
          "lagging node can under-report.",
          "- Version bytes `0x00` and `0x05` are shared by Bitcoin and Bitcoin "
          "Cash; attribution for those rows is ambiguous at the version-byte "
          "level.",
          "- A passing oracle control means the source can report history; it "
          "does not mean every negative row is complete."]

    if note_extra:
        L += ["", "## Notes", ""] + ["- " + n for n in note_extra]

    L += ["", "---", "",
          "Tool: `btg_provenance.py` (read-only). Not implemented by design: "
          "key derivation, key/seed search, wallet cracking, exploit code, "
          "transaction signing or broadcast.", ""]
    return "\n".join(L)


# ---------------------------------------------------------------- selftest
def selftest(quiet=False):
    if not quiet:
        print("SELFTEST")
    ok = True

    def chk(name, cond):
        nonlocal ok
        ok = ok and cond
        if not quiet:
            print("  [%s] %s" % ("PASS" if cond else "FAIL", name))

    a = "GTK67VQsQCtueFu6Zo54KfWPPdChxBjmcD"
    d = decode_check(a)
    chk("known BTG address decodes", d["valid"])
    chk("version byte is 0x26", d.get("version_hex") == "0x26")
    chk("classified as Bitcoin Gold P2PKH",
        d.get("chain") == "Bitcoin Gold" and d.get("script_type") == "P2PKH")
    chk("round-trips through encode",
        encode_address(d["version"], bytes.fromhex(d["hash160"])) == a)
    chk("BTC equivalent has version 0x00",
        decode_check(encode_address(0x00, bytes.fromhex(d["hash160"]))).get("version") == 0)
    chk("checksum rejects a tampered address",
        not decode_check(a[:-1] + ("D" if a[-1] != "D" else "E")).get("valid"))
    try:
        b58decode("0OIl")
        chk("decoder rejects invalid base58 chars", False)
    except ValueError:
        chk("decoder rejects invalid base58 chars", True)
    short = decode_check("1abc")
    chk("short address rejected with no hash160 populated",
        (not short.get("valid")) and ("hash160" not in short))
    bad = decode_check("0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl")
    chk("non-base58 address rejected",
        (not bad.get("valid")) and ("hash160" not in bad))
    for v, (chain, stype, lead) in VERSIONS.items():
        addr_v = encode_address(v, bytes.fromhex("00" * 20))
        back = decode_check(addr_v)
        chk("round-trip version 0x%02x (%s %s)" % (v, chain, stype),
            back.get("valid") and back.get("version") == v)
    p2sh = encode_address(0x05, bytes.fromhex("11" * 20))
    chk("P2SH address decodes as Bitcoin P2SH",
        decode_check(p2sh).get("script_type") == "P2SH")
    chk("_parse_number('1,234') == 1234", _parse_number("1,234") == 1234)
    chk("_parse_number('1.234') == 1234", _parse_number("1.234") == 1234)
    chk("_parse_number('1234') == 1234", _parse_number("1234") == 1234)
    chk("_parse_number('') is None", _parse_number("") is None)
    chk("_parse_number('abc') is None", _parse_number("abc") is None)

    if not quiet:
        print("RESULT: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


# -------------------------------------------------------------------- main
def _load_addresses(path):
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f
                if l.strip() and not l.startswith("#")]


def _run_report(addrs, addr_source, btc_check, btg_check, btg_json,
                extra_notes, out_md, out_json):
    """Run the full provenance pipeline and write outputs."""
    rows = [decode_check(a) for a in addrs]
    valid_rows = [r for r in rows if r.get("valid") and "hash160" in r]
    if not valid_rows:
        print("ERROR: no valid addresses to inspect.", file=sys.stderr)
        return 2

    btc, btg, notes = {}, {}, []
    btg_meta = {}

    if btc_check:
        for r in valid_rows:
            eq = encode_address(0x00, bytes.fromhex(r["hash160"]))
            btc[r["address"]] = btc_stats(eq)
            print("BTC %s -> %s" % (eq, btc[r["address"]]))
            time.sleep(NET_DELAY_BETWEEN)

    oracle = None
    if btg_check:
        oracle = validate_oracle()
        print("oracle control %s -> %s transactions : %s"
              % (ORACLE_CONTROL["address"], oracle[1].get("tx_count"),
                 "PASS" if oracle[0] else "FAIL"))
        if not oracle[0]:
            print("WARNING: positive control FAILED - zero-history results "
                  "will be marked unreliable")
        for r in valid_rows:
            btg[r["address"]] = btgexplorer_stats(r["address"])
            print("BTG %s -> %s" % (r["address"], btg[r["address"]]))
            time.sleep(NET_DELAY_BETWEEN)

    if btg_json:
        try:
            btg, btg_meta = load_btg_json(btg_json)
        except Exception as e:
            print("ERROR: could not ingest %s: %s" % (btg_json, e),
                  file=sys.stderr)
            return 2
        print("ingested BTG data for %d address(es) from %s (sha256 %s)"
              % (len(btg), btg_meta.get("ingest_path"),
                 btg_meta.get("ingest_sha256", "?")[:16]))

    if btc:
        if all(v.get("tx_count") == 0 for v in btc.values() if "error" not in v):
            notes.append("Every BTC-equivalent key has zero transactions: "
                         "these keys have never been used on Bitcoin.")
    if btg:
        vals = [v for v in btg.values() if "error" not in v]
        zero = bool(vals) and all(v.get("tx_count") in ("0", 0) for v in vals)
        if zero and (oracle is None or oracle[0]):
            notes.append("Every address shows zero BTG transactions and zero "
                         "BTG received: never used on the Bitcoin Gold chain. "
                         "The source passed the positive control, so this "
                         "negative is credible.")
        elif zero:
            notes.append("Every address shows zero BTG transactions, BUT the "
                         "positive control failed, so this negative is NOT "
                         "credible and must not be treated as evidence that "
                         "the addresses are unused.")
    notes.extend(extra_notes or [])

    md = build_report(rows, btc, btg, notes, oracle,
                      btg_meta=btg_meta, addr_source=addr_source)
    with open(out_md, "w", encoding="utf-8", newline="\n") as f:
        f.write(md)
    with open(out_json, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                   "address_source": addr_source,
                   "addresses": rows, "btc": btc, "btg": btg,
                   "btg_meta": btg_meta,
                   "oracle": ({"ok": oracle[0], "stats": oracle[1]}
                              if oracle is not None else None),
                   "notes": notes}, f, indent=2)
    print("wrote %s and %s" % (out_md, out_json))
    return 0


def main():
    ap = argparse.ArgumentParser(
        prog="btg_provenance.py",
        description="Address identification + public-chain provenance "
                    "reporter (read-only). No arguments = offline report on "
                    "the built-in address list.")
    ap.add_argument("--addresses", help="file of addresses, one per line")
    ap.add_argument("--btc-check", action="store_true",
                    help="query public BTC explorer for the equivalent keys")
    ap.add_argument("--btg-check", action="store_true",
                    help="query the BTG chain via btgexplorer.com and first "
                         "validate it against a known-active control address")
    ap.add_argument("--btg-json",
                    help="instead of --btg-check, ingest BTG results from "
                         "supplied data (see docstring)")
    ap.add_argument("--note", action="append", default=[],
                    help="extra attribution note to include (repeatable)")
    ap.add_argument("--out-md", default="btg_provenance_report.md")
    ap.add_argument("--out-json", default="btg_provenance.json")
    ap.add_argument("--allow-defaults", action="store_true",
                    help="(kept for compatibility; zero-arg mode is now the "
                         "default behavior)")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    # Zero-argument default mode: selftest, then offline report on built-ins.
    no_args = (not args.addresses and not args.btc_check and not args.btg_check
               and not args.btg_json and not args.note)

    if no_args:
        print("btg_provenance - no arguments given, running default mode")
        print("  1) selftest")
        rc = selftest(quiet=False)
        if rc != 0:
            print("Selftest failed; aborting default report.", file=sys.stderr)
            return rc
        print()
        print("  2) offline report on built-in address list")
        print("     (network checks skipped; use --btc-check / --btg-check "
              "to enable)")
        print()
        return _run_report(
            addrs=DEFAULT_ADDRESSES.split(),
            addr_source="built-in default list",
            btc_check=False,
            btg_check=False,
            btg_json=None,
            extra_notes=None,
            out_md=args.out_md,
            out_json=args.out_json,
        )

    # Explicit modes
    if args.addresses:
        if not os.path.exists(args.addresses):
            print("ERROR: address file not found: %s" % args.addresses,
                  file=sys.stderr)
            return 2
        addrs = _load_addresses(args.addresses)
        addr_source = "file: %s" % os.path.abspath(args.addresses)
    elif args.allow_defaults:
        addrs = DEFAULT_ADDRESSES.split()
        addr_source = "built-in default list (--allow-defaults)"
    else:
        print("ERROR: no --addresses file supplied. Use --allow-defaults to "
              "run against the built-in list, or run with no arguments for "
              "the offline default mode.", file=sys.stderr)
        return 2

    return _run_report(
        addrs=addrs,
        addr_source=addr_source,
        btc_check=args.btc_check,
        btg_check=args.btg_check,
        btg_json=args.btg_json,
        extra_notes=args.note,
        out_md=args.out_md,
        out_json=args.out_json,
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
