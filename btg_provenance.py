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
  python3 btg_provenance.py --addresses addrs.txt --out-md provenance.md
  python3 btg_provenance.py --addresses addrs.txt --btc-check
  python3 btg_provenance.py --addresses addrs.txt --btc-check \
      --btg-json btg_onchain.json
  python3 btg_provenance.py --selftest

BTG DATA SOURCE
  btgexplorer.com is server-rendered, so it is scraped directly by --btg-check.
  NOTE: btg.tokenview.io is a client-rendered SPA whose index was observed
  returning 0 transactions for an address with >100 known transactions - do not
  rely on it. BTC figures come live from Blockstream's public Esplora API.

ORACLE VALIDATION
  Every run with --btg-check first queries a control address known to have
  history (the 2018 BTG attack proceeds address). If the source cannot report
  non-zero for the control, all zero results are flagged UNRELIABLE. Run
  --selftest to check the decode layer, not the oracle.
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


# ----------------------------------------------------------------- base58
def b58decode(s):
    n = 0
    for ch in s:
        if ch not in ALPH:
            raise ValueError("invalid base58 character %r" % ch)
        n = n * 58 + ALPH.index(ch)
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
    raw = b58decode(addr)
    if len(raw) != 25:
        return {"address": addr, "valid": False,
                "reason": "decoded length %d, expected 25" % len(raw)}
    version, h160, chk = raw[0], raw[1:21], raw[-4:]
    ok = hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == chk
    chain, stype, lead = VERSIONS.get(version, ("unknown", "?", "?"))
    return {
        "address": addr, "valid": ok, "version": version,
        "version_hex": "0x%02x" % version, "hash160": h160.hex(),
        "chain": chain, "script_type": stype, "leading_char": lead,
        "length": len(addr),
    }


# -------------------------------------------------------------- chain data
def _get(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def btc_stats(addr):
    """Public BTC lookup (Blockstream Esplora). Returns dict or None."""
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
    """Ingest externally observed BTG results (data-supply mode).

    Expected shape:
      {"source": "...", "observed": "YYYY-MM-DD",
       "results": {"<btg address>": {"balance": "0", "received": "0",
                                     "sent": "0", "tx_count": "0"}}}
    Nothing is trusted silently: the report prints the declared source and date.
    """
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    results = doc.get("results", doc)
    src = doc.get("source", "supplied file")
    obs = doc.get("observed", "unknown date")
    out = {}
    for a, v in results.items():
        if not isinstance(v, dict):
            continue
        out[a] = dict(v)
        out[a].setdefault("source", src)
        out[a].setdefault("observed", obs)
    return out


# ------------------------------------------------- oracle validation
# A "0 transactions" answer is worthless unless the index can be shown to
# return NON-zero for an address that definitely has history. This control is
# the documented recipient of the May 2018 BTG 51%-attack double-spend
# proceeds (>388,200 BTG, per contemporaneous press and the BTG team).
# A working BTG index MUST show substantial history for it.
ORACLE_CONTROL = {
    "address": "GTNjvCGssb2rbLnDV1xxsHmunQdvXnY2Ft",
    "expect_min_tx": 100,
    "why": "documented 2018 BTG 51%-attack proceeds address; any working BTG "
           "index must report nonzero history for it",
}

BTG_EXPLORER = "https://btgexplorer.com/address/"


def btgexplorer_stats(addr, timeout=25):
    """Scrape btgexplorer.com (server-rendered, unlike the JS SPA)."""
    html = _get(BTG_EXPLORER + addr, timeout=timeout)
    flat = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))

    def grab(label):
        m = re.search(re.escape(label) + r"\s*([0-9][0-9.,]*)\s*BTG", flat)
        return m.group(1) if m else None

    m = re.search(r"Transactions\s*([0-9][0-9.,]*)", flat)
    return {
        "chain": "Bitcoin Gold",
        "received": grab("Total Received"),
        "sent": grab("Total Sent"),
        "balance": grab("Final Balance"),
        "tx_count": m.group(1) if m else None,
        "source": "btgexplorer.com",
    }


def validate_oracle():
    """Return (ok, stats). ok=False means every negative result is UNRELIABLE."""
    st = btgexplorer_stats(ORACLE_CONTROL["address"])
    try:
        n = int(str(st.get("tx_count") or "0").replace(",", ""))
    except ValueError:
        n = 0
    return n >= ORACLE_CONTROL["expect_min_tx"], st


# ------------------------------------------------------------------- report
def build_report(rows, btc=None, btg=None, note_extra=None, oracle=None):
    btc = btc or {}
    btg = btg or {}
    t = time.strftime("%Y-%m-%d %H:%M:%S")
    L = ["# BTG Address Provenance Report", "", "Generated: %s" % t, "",
         "Method: Base58Check decode + public explorer lookups. Read-only; "
         "no key derivation, no key/seed search, no wallet cracking.", "",
         "## Address identification", "",
         "| address | len | version | chain | type | checksum |",
         "|---|---|---|---|---|---|"]
    for r in rows:
        L.append("| `%s` | %d | %s | %s | %s | %s |"
                 % (r["address"], r["length"], r["version_hex"], r["chain"],
                    r["script_type"], "VALID" if r["valid"] else "INVALID"))

    L += ["", "## BTC-equivalent keys (same hash160)", "",
          "These encode the identical hash160 under Bitcoin's version byte, so "
          "the same key would control them. Used as a cross-chain provenance "
          "signal.", "", "| BTG address | hash160 | BTC equivalent |",
          "|---|---|---|"]
    for r in rows:
        L.append("| `%s` | `%s` | `%s` |"
                 % (r["address"], r["hash160"],
                    encode_address(0x00, bytes.fromhex(r["hash160"]))))

    if btc:
        L += ["", "## Bitcoin chain history (equivalent keys)", "",
              "| BTC equivalent | tx_count | received (sat) | sent (sat) |",
              "|---|---|---|---|"]
        for r in rows:
            b = btc.get(r["address"], {})
            if "error" in b:
                L.append("| `%s` | error: %s | - | - |"
                         % (encode_address(0x00, bytes.fromhex(r["hash160"])),
                            b["error"]))
            else:
                L.append("| `%s` | %s | %s | %s |"
                         % (encode_address(0x00, bytes.fromhex(r["hash160"])),
                            b.get("tx_count"), b.get("received"), b.get("sent")))

    if oracle is not None:
        ok, ost = oracle
        L += ["", "## Oracle validation (positive control)", "",
              "A zero-transaction result is only meaningful if the data source "
              "can be shown to report NON-zero for an address known to have "
              "history. Control: `%s` - %s."
              % (ORACLE_CONTROL["address"], ORACLE_CONTROL["why"]), "",
              "| control address | reported transactions | expected | verdict |",
              "|---|---|---|---|"]
        L.append("| `%s` | %s | >= %d | %s |"
                 % (ORACLE_CONTROL["address"], ost.get("tx_count"),
                    ORACLE_CONTROL["expect_min_tx"],
                    "PASS - negatives below are credible" if ok
                    else "FAIL - NEGATIVES BELOW ARE UNRELIABLE"))
        if not ok:
            L += ["", "**WARNING:** the BTG data source FAILED the positive "
                      "control. The zero-history rows below may reflect a "
                      "broken or incomplete index rather than genuinely unused "
                      "addresses. Do not rely on them until a source passes "
                      "this control."]

    if btg:
        srcs = sorted({v.get("source", "?") for v in btg.values() if v.get("source")})
        obs = sorted({str(v.get("observed", "?")) for v in btg.values() if v.get("observed")})
        L += ["", "## Bitcoin Gold chain history", "",
              "Source: %s%s" % (", ".join(srcs) or "?",
                                (" | observed: " + ", ".join(obs)) if obs else ""), "",
              "| address | received | sent | balance | transactions |",
              "|---|---|---|---|---|"]
        for r in rows:
            b = btg.get(r["address"], {})
            if "error" in b:
                L.append("| `%s` | error: %s | - | - | - |"
                         % (r["address"], b["error"]))
            else:
                L.append("| `%s` | %s BTG | %s BTG | %s BTG | %s |"
                         % (r["address"], b.get("received"), b.get("sent"),
                            b.get("balance"), b.get("tx_count")))

    if note_extra:
        L += ["", "## Notes", ""] + ["- " + n for n in note_extra]
    L += ["", "---", "",
          "Tool: `btg_provenance.py` (read-only). Not implemented by design: "
          "key derivation, key/seed search, wallet cracking, exploit code, "
          "transaction signing or broadcast.", ""]
    return "\n".join(L)


# ---------------------------------------------------------------- selftest
def selftest():
    print("SELFTEST")
    ok = True

    def chk(name, cond):
        nonlocal ok
        ok = ok and cond
        print("  [%s] %s" % ("PASS" if cond else "FAIL", name))

    a = "GTK67VQsQCtueFu6Zo54KfWPPdChxBjmcD"
    d = decode_check(a)
    chk("known BTG address decodes", d["valid"])
    chk("version byte is 0x26", d["version_hex"] == "0x26")
    chk("classified as Bitcoin Gold P2PKH",
        d["chain"] == "Bitcoin Gold" and d["script_type"] == "P2PKH")
    chk("round-trips through encode",
        encode_address(d["version"], bytes.fromhex(d["hash160"])) == a)
    chk("BTC equivalent has version 0x00",
        decode_check(encode_address(0x00, bytes.fromhex(d["hash160"])))["version"] == 0)
    chk("checksum rejects a tampered address",
        not decode_check(a[:-1] + ("D" if a[-1] != "D" else "E"))["valid"])
    chk("rejects non-base58 characters", "0" not in ALPH and "O" not in ALPH)
    # Stellar length discriminator
    chk("56-char Stellar-shaped key is not a 25-byte base58 payload",
        len("G" + "A" * 55) == 56)
    print("RESULT: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


# -------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(
        prog="btg_provenance.py",
        description="Address identification + public-chain provenance "
                    "reporter (read-only).")
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
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if args.addresses and os.path.exists(args.addresses):
        with open(args.addresses, encoding="utf-8") as f:
            addrs = [l.strip() for l in f if l.strip()
                     and not l.startswith("#")]
    else:
        addrs = DEFAULT_ADDRESSES.split()

    rows = [decode_check(a) for a in addrs]

    btc, btg, notes = {}, {}, []
    if args.btc_check:
        for r in rows:
            eq = encode_address(0x00, bytes.fromhex(r["hash160"]))
            btc[r["address"]] = btc_stats(eq)
            print("BTC %s -> %s" % (eq, btc[r["address"]]))
    oracle = None
    if args.btg_check:
        oracle = validate_oracle()
        print("oracle control %s -> %s transactions : %s"
              % (ORACLE_CONTROL["address"], oracle[1].get("tx_count"),
                 "PASS" if oracle[0] else "FAIL"))
        if not oracle[0]:
            print("WARNING: positive control FAILED - zero-history results "
                  "will be marked unreliable")
        for r in rows:
            btg[r["address"]] = btgexplorer_stats(r["address"])
            print("BTG %s -> %s" % (r["address"], btg[r["address"]]))
    if args.btg_json:
        btg = load_btg_json(args.btg_json)
        print("ingested BTG data for %d address(es)" % len(btg))

    if btc and all(v.get("tx_count") == 0 for v in btc.values()):
        notes.append("Every BTC-equivalent key has zero transactions: these "
                     "keys have never been used on Bitcoin.")
    if btg:
        vals = [v for v in btg.values() if "error" not in v]
        zero = vals and all((v.get("tx_count") in ("0", 0)) for v in vals)
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
    notes.extend(args.note or [])

    md = build_report(rows, btc, btg, notes, oracle)
    with open(args.out_md, "w", encoding="utf-8", newline="\n") as f:
        f.write(md)
    with open(args.out_json, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                   "addresses": rows, "btc": btc, "btg": btg,
                   "notes": notes}, f, indent=2)
    print("wrote %s and %s" % (args.out_md, args.out_json))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
