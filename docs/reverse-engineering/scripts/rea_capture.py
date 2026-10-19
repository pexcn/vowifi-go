#!/usr/bin/env python3
"""Capture REA's unmodified MCP responses and export Evidence; never run the target.

Uses the installed `rea mcp` process and Python's standard library only.
Exit status is nonzero on any tool/RPC/cleanup error. The output directory must
be new, so a retry cannot overwrite or accidentally skip earlier failures.
"""
import argparse
import hashlib
import json
import pathlib
import queue
import subprocess
import threading

EXPECTED = "2b080980c72fede3dbad1c9f8830bb51d0bc368b4acb576c4f2d27f9182eb59f"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--rea", default="rea", help="REA launcher (in PATH or absolute)")
    parser.add_argument("--procedure", action="append", default=[], help="native address/symbol to decompile")
    args = parser.parse_args()
    target, output = args.binary.resolve(), args.output.resolve()
    if hashlib.sha256(target.read_bytes()).hexdigest() != EXPECTED:
        parser.error("unexpected target SHA-256")
    output.mkdir(parents=True, exist_ok=False)
    inbox = queue.Queue()
    failed = False
    sequence = 0
    with (output / "rea.stderr.log").open("w") as errors:
        process = subprocess.Popen([args.rea, "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=errors, text=True, bufsize=1)

        def reader():
            try:
                for line in process.stdout:
                    try:
                        inbox.put(json.loads(line))
                    except ValueError:
                        pass
            finally:
                inbox.put(None)

        threading.Thread(target=reader, daemon=True).start()

        def rpc(method, params):
            nonlocal sequence
            sequence += 1
            process.stdin.write(json.dumps({"jsonrpc":"2.0","id":sequence,"method":method,"params":params}) + "\n")
            process.stdin.flush()
            while True:
                message = inbox.get(timeout=1800)
                if message is None:
                    raise RuntimeError("REA exited before its response")
                if message.get("id") == sequence:
                    if "error" in message:
                        raise RuntimeError("JSON-RPC error: " + json.dumps(message["error"]))
                    return message.get("result")

        def call(label, name, arguments):
            nonlocal failed
            response = rpc("tools/call", {"name":name,"arguments":arguments})
            (output / (label + ".json")).write_text(json.dumps(response, ensure_ascii=False, indent=2) + "\n")
            body = response.get("structuredContent")
            if body is None:
                for block in response.get("content", []):
                    if block.get("type") == "text":
                        try:
                            body = json.loads(block["text"])
                            break
                        except ValueError:
                            pass
            error = response.get("isError", False) or isinstance(body, dict) and "error" in body
            failed |= bool(error)
            print(label, "ERROR" if error else "OK", flush=True)
            return not error

        try:
            rpc("initialize", {"protocolVersion":"2025-11-25","capabilities":{},
                               "clientInfo":{"name":"vohive-static-capture","version":"1"}})
            process.stdin.write(json.dumps({"jsonrpc":"2.0","method":"notifications/initialized"}) + "\n")
            process.stdin.flush()
            call("001-build-info", "inspect_go_binary", {"path":str(target)})
            if args.procedure and call("002-open", "open_binary", {"path":str(target),"provider_id":"ghidra"}):
                for index, procedure in enumerate(args.procedure, 3):
                    if not call(f"{index:03d}-procedure", "procedure_pseudo_code", {"procedure":procedure}):
                        break  # A failed native request may invalidate the ephemeral session.
        except (OSError, RuntimeError, queue.Empty) as error:
            failed = True
            (output / "client-error.txt").write_text(str(error) + "\n")
        finally:
            if process.poll() is None:
                for label, name, arguments in [
                    ("900-export","export_evidence_bundle",{"path":str(output / "evidence-bundle.json")}),
                    ("901-close","close_binary",{}),
                ]:
                    try:
                        call(label, name, arguments)
                    except (OSError, RuntimeError, queue.Empty) as error:
                        failed = True
                        (output / (label + "-error.txt")).write_text(str(error) + "\n")
                process.stdin.close()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                failed = True
                process.terminate()  # This script's own child only; no external process discovery/kill.
                process.wait(timeout=30)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
