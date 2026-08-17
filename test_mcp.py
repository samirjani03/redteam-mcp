#!/usr/bin/env python3
"""
Simple MCP client test for RedTeam MCP server over persistent stdio stream
"""
import json
import subprocess
import sys
import time

def main():
    print("Testing RedTeam MCP Server over stdio stream...")
    print("=" * 60)

    # Command to run server inside container or locally
    cmd = [
        'docker', 'exec', '-i', 'redteam-mcp',
        '/app/.venv/bin/python', '/app/src/server.py'
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            encoding='utf-8'
        )
    except Exception as exc:
        print(f"[ERROR] Failed to start process: {exc}")
        sys.exit(1)

    def send_recv(req):
        payload = json.dumps(req)
        print(f"\n---> Sending JSON-RPC: {req.get('method')}")
        proc.stdin.write(payload + "\n")
        proc.stdin.flush()

        line = proc.stdout.readline()
        if not line:
            err = proc.stderr.read()
            print(f"[!] Server closed stream. Stderr output:\n{err}")
            return None
        try:
            resp = json.loads(line)
            print(f"<--- Received Response (id={resp.get('id')}):")
            print(json.dumps(resp, indent=2)[:500] + ("..." if len(json.dumps(resp)) > 500 else ""))
            return resp
        except Exception as parse_err:
            print(f"[!] Failed to parse JSON response line: {line.strip()} ({parse_err})")
            return None

    # Step 1: Initialize
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}, "resources": {}},
            "clientInfo": {"name": "test-client", "version": "1.0.0"}
        }
    }
    resp1 = send_recv(init_req)

    # Step 2: Send initialized notification if needed
    if resp1 and "result" in resp1:
        notif = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }
        print(f"\n---> Sending Notification: notifications/initialized")
        proc.stdin.write(json.dumps(notif) + "\n")
        proc.stdin.flush()

    # Step 3: List tools
    list_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }
    resp2 = send_recv(list_req)

    # Terminate process
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except Exception:
        proc.kill()

    print("\n" + "=" * 60)
    if resp2 and "result" in resp2:
        tools = resp2["result"].get("tools", [])
        print(f"SUCCESS! FastMCP Server active with {len(tools)} registered tools:")
        for t in tools[:10]:
            print(f"  - {t.get('name')}: {t.get('description', '')[:60]}...")
        if len(tools) > 10:
            print(f"  ... and {len(tools) - 10} more tools.")
    else:
        print("Test failed or server closed prematurely.")

if __name__ == "__main__":
    main()