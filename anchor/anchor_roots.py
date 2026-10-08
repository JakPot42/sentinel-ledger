#!/usr/bin/env python3
"""Deliver the recorder's anchor statements. docs/SPEC.md section 7.5.

    anchor_roots.py submit  --dir DATA --witness HOST:PORT
    anchor_roots.py request --dir DATA
    anchor_roots.py fetch   --dir DATA --freetsa
    anchor_roots.py verify  --dir DATA --ca FILE [--untrusted FILE] [--max-lag-seconds N]

The recorder writes a statement of the journal's root to DATA/anchors/ every few records.
This program, which is not the recorder and runs outside the command path, sends those
statements where the operator cannot rewrite them:

  submit   sends each statement to a witness and keeps the witness's reply beside it.
  request  makes an RFC 3161 timestamp request for each statement (openssl, no network).
           The request carries the statement's SHA-256 and nothing else.
  fetch    sends each request to FreeTSA and saves the token. This is the only command
           that leaves the machine, and it refuses to run without --freetsa.
  verify   checks every statement has a token that openssl accepts for that statement
           under the given CA, and reports how long after the last record it was stamped.

The method: openssl ts -query with -cert, POST to https://freetsa.org/tsr, openssl
ts -verify against the timestamping authority's CA.

A timestamp token shows a statement existed at a time. On its own it does not stop
someone stamping a rewritten journal later. That is what --max-lag-seconds is for: a
token much later than the records it covers is a finding.

Exit codes: 0 done and nothing wrong, 2 a finding (refused by the witness, a missing or
invalid token, stamped too late), 1 usage or I/O error.
"""
import argparse
import datetime
import glob
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import urllib.request

FREETSA_URL = "https://freetsa.org/tsr"


def statements(data_dir):
    return sorted(p for p in glob.glob(os.path.join(data_dir, "anchors", "*.json"))
                  if re.fullmatch(r"\d{8}\.json", os.path.basename(p)))


def openssl(*args):
    exe = shutil.which("openssl")
    if exe is None:
        raise OSError("openssl is not on the PATH")
    return subprocess.run([exe, *args], capture_output=True, text=True)


def submit(args):
    host, _, port = args.witness.rpartition(":")
    refused = 0
    for path in statements(args.dir):
        reply_path = path[:-5] + ".witness.json"
        if os.path.exists(reply_path):
            continue
        with open(path, "rb") as fh:
            line = fh.read().strip() + b"\n"
        with socket.create_connection((host, int(port)), timeout=5) as conn:
            conn.sendall(line)
            reply = json.loads(conn.makefile("r", encoding="utf-8").readline())
        if reply.get("stored"):
            with open(reply_path, "w", encoding="utf-8") as fh:
                json.dump(reply, fh, sort_keys=True)
            print("stored   %s" % os.path.basename(path))
        else:
            refused += 1
            print("REFUSED  %s: %s" % (os.path.basename(path), reply.get("refused")))
    return 2 if refused else 0


def request(args):
    for path in statements(args.dir):
        query = path[:-5] + ".tsq"
        if os.path.exists(query):
            continue
        with open(path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        done = openssl("ts", "-query", "-digest", digest, "-sha256", "-cert", "-out", query)
        if done.returncode != 0:
            raise OSError("openssl ts -query failed: " + done.stderr.strip())
        print("request  %s" % os.path.basename(query))
    return 0


def fetch(args):
    if not args.freetsa:
        print("error: fetch contacts freetsa.org. Pass --freetsa to allow it.", file=sys.stderr)
        return 1
    for path in statements(args.dir):
        query, token = path[:-5] + ".tsq", path[:-5] + ".tsr"
        if os.path.exists(token) or not os.path.exists(query):
            continue
        with open(query, "rb") as fh:
            req = urllib.request.Request(FREETSA_URL, data=fh.read(),
                                         headers={"Content-Type": "application/timestamp-query"})
        with urllib.request.urlopen(req, timeout=30) as response:
            body = response.read()
        with open(token, "wb") as fh:
            fh.write(body)
        print("token    %s" % os.path.basename(token))
    return 0


def token_time(token):
    text = openssl("ts", "-reply", "-in", token, "-text").stdout
    found = re.search(r"Time stamp: (\w{3})\s+(\d+) (\d\d:\d\d:\d\d)(?:\.\d+)? (\d{4}) GMT", text)
    if not found:
        return None
    stamp = datetime.datetime.strptime(" ".join(found.groups()), "%b %d %H:%M:%S %Y")
    return stamp.replace(tzinfo=datetime.timezone.utc)


def verify(args):
    findings = 0
    paths = statements(args.dir)
    for path in paths:
        name, token = os.path.basename(path), path[:-5] + ".tsr"
        if not os.path.exists(token):
            findings += 1
            print("NOT_TIMESTAMPED  %s: no token" % name)
            continue
        command = ["ts", "-verify", "-data", path, "-in", token, "-CAfile", args.ca]
        if args.untrusted:
            command += ["-untrusted", args.untrusted]
        if openssl(*command).returncode != 0:
            findings += 1
            print("TOKEN_INVALID    %s: the token is not a valid timestamp of this statement under this CA" % name)
            continue
        with open(path, "r", encoding="utf-8") as fh:
            last_at = json.load(fh)["last_at"]
        stamped = token_time(token)
        covered = datetime.datetime.strptime(last_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        lag = int((stamped - covered).total_seconds()) if stamped else None
        if lag is None or (args.max_lag_seconds is not None and not 0 <= lag <= args.max_lag_seconds):
            findings += 1
            print("STAMPED_LATE     %s: last record %s, stamped %s (%s s later)" % (name, last_at, stamped, lag))
        else:
            print("timestamped      %s: last record %s, stamped %s (%d s later)"
                  % (name, last_at, stamped.strftime("%Y-%m-%dT%H:%M:%SZ"), lag))
    print("%d statement(s), %d finding(s)" % (len(paths), findings))
    return 2 if findings else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Deliver anchor statements to a witness or a timestamping authority.")
    sub = ap.add_subparsers(dest="command", required=True)
    for name in ("submit", "request", "fetch", "verify"):
        p = sub.add_parser(name)
        p.add_argument("--dir", required=True, help="the recorder's data directory")
        if name == "submit":
            p.add_argument("--witness", required=True, help="HOST:PORT of a witness")
        if name == "fetch":
            p.add_argument("--freetsa", action="store_true", help="allow the network call to freetsa.org")
        if name == "verify":
            p.add_argument("--ca", required=True, help="the timestamping authority's CA certificate (PEM)")
            p.add_argument("--untrusted", help="the authority's signing certificate, if the token omits it")
            p.add_argument("--max-lag-seconds", type=int,
                           help="a token more than this long after the last record it covers is a finding")
    args = ap.parse_args(argv)
    try:
        return {"submit": submit, "request": request, "fetch": fetch, "verify": verify}[args.command](args)
    except (OSError, ValueError, KeyError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
