#!/usr/bin/env python3
"""Convert functions.go JSONL into REA's private-module function-entry seeds.

Input is static metadata, not a recovered call graph or accurate Go signatures.
Only the closed module's original names and entry addresses are supplied.
"""
import argparse
import json
import pathlib

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("functions", type=pathlib.Path)
parser.add_argument("output", type=pathlib.Path)
args = parser.parse_args()
rows = []
for line in args.functions.read_text().splitlines():
    function = json.loads(line)
    name, address = function["name"], function["entry"]
    if name.startswith("github.com/iniwex5/vowifi-go/"):
        if not isinstance(address, int) or address <= 0 or any(c in name for c in "\t\r\n"):
            raise ValueError("invalid function seed")
        rows.append(f"0x{address:x}\tfunction\t{name}\n")
args.output.write_text("".join(rows))
print(f"Wrote {len(rows)} function entries")
