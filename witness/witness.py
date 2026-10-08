#!/usr/bin/env python3
"""A witness. docs/SPEC.md section 7.5.

    witness.py serve --store FILE [--port N]
    witness.py show --store FILE

A separate process that does one thing: it stores the anchor statements it receives,
with the time it received them, and never changes or removes one. It is meant to be run
by someone other than the machine's operator. Run by the operator it proves nothing,
because the operator could rewrite the store.

It listens on localhost. A client sends one statement as a line of JSON and gets one line
back. It refuses a statement that gives a different root for a journal and entry count it
already holds: that would be two histories of the same journal, and the first one stays.

It shares no code with the recorder, the verifier or the gate. Standard library only.
It does not check that a root is the root of anything. It has never seen the journal.
"""
import argparse
import datetime
import json
import os
import re
import socketserver
import sys

SCHEMA = "sentinel-ledger/anchor/0"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def read_store(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def receive(store_path, statement):
    """Apply the witness's rule to one statement. Returns the reply."""
    good = (isinstance(statement, dict) and statement.get("schema") == SCHEMA
            and isinstance(statement.get("journal_id"), str) and HEX64.match(statement["journal_id"])
            and isinstance(statement.get("root"), str) and HEX64.match(statement["root"])
            and type(statement.get("entry_count")) is int and statement["entry_count"] > 0
            and isinstance(statement.get("last_at"), str))
    if not good:
        return {"stored": False, "refused": "not an anchor statement"}
    for held in read_store(store_path):
        if (held["journal_id"], held["entry_count"]) == (statement["journal_id"], statement["entry_count"]):
            if held["root"] == statement["root"]:
                return {"stored": True, "already_held": True, "received_at": held["received_at"]}
            return {"stored": False,
                    "refused": "a different root is already held for this journal at this entry count"}
    kept = {k: statement[k] for k in ("journal_id", "entry_count", "root", "last_at")}
    kept["received_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(store_path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(kept, sort_keys=True, separators=(",", ":")) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return {"stored": True, "already_held": False, "received_at": kept["received_at"]}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Witness: stores the roots it receives.")
    sub = ap.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--store", required=True)
    serve.add_argument("--port", type=int, default=0, help="0 picks a free port and prints it")
    show = sub.add_parser("show")
    show.add_argument("--store", required=True)
    args = ap.parse_args(argv)

    if args.command == "show":
        for held in read_store(args.store):
            print(json.dumps(held, sort_keys=True))
        return 0

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                statement = json.loads(self.rfile.readline().decode("utf-8"))
            except ValueError:
                statement = None
            self.wfile.write((json.dumps(receive(args.store, statement), sort_keys=True) + "\n").encode("utf-8"))

    with socketserver.TCPServer(("127.0.0.1", args.port), Handler) as server:
        print(json.dumps({"listening": server.server_address[1]}), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
