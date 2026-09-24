#!/usr/bin/env python3
"""Dependency-free mock MCP server over Streamable HTTP.

Implements just enough of MCP 2025-11-25 to smoke-test a client:
initialize -> notifications/initialized -> tools/list (paginated) -> tools/call,
with special endpoints for a one-shot session 404, a list-changed SSE event,
redirect hard-error, and DELETE teardown.

Run with:
    python scripts/mcp-smoke-server.py [PORT]
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

# ─── test configuration ────────────────────────────────────────────────────

TEST_SESSION_ID = "00000000-0000-0000-0000-000000000001"

ALL_TOOLS = [
    {
        "name": "echo",
        "title": "Echo",
        "description": "Return the provided message unchanged.",
        "inputSchema": {
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "required": ["message"],
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    },
    {
        "name": "get_time",
        "title": "Get Time",
        "description": "Return the current server time.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "read_file",
        "title": "Read File",
        "description": "Read a file path (mock). Returns a short fixed string.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "make_error",
        "title": "Make Error",
        "description": "Always return an tool result with isError set.",
        "inputSchema": {
            "type": "object",
            "properties": {"reason": {"type": "string"}},
            "required": ["reason"],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "image_cat",
        "title": "Image Cat",
        "description": "Return a tiny fake PNG as a binary resource.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True},
    },
]


# ─── helpers ───────────────────────────────────────────────────────────────


def canonical_pin(tool: dict) -> str:
    """Canonical JSON pin hash over the fields the real client pins."""
    pin = {
        "name": tool.get("name"),
        "title": tool.get("title"),
        "description": tool.get("description"),
        "inputSchema": tool.get("inputSchema"),
        "annotations": tool.get("annotations"),
    }
    return hashlib.sha256(
        json.dumps(pin, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def jsonrpc_response(req_id, result=None, error=None):
    body = {"jsonrpc": "2.0", "id": req_id}
    if error is not None:
        body["error"] = error
    else:
        body["result"] = result
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Quieter logs; the startup banner already names the endpoint.
        pass

    def _send_json(self, status: int, body: bytes, extra_headers=None):
        self.send_response(status)
        for h, v in (extra_headers or {}).items():
            self.send_header(h, v)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # /mcp-redirect must 302 to exercise redirect hard-error handling.
        if self.path == "/mcp-redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9999/mcp")
            self.end_headers()
            return
        self.send_error(404)

    def do_DELETE(self):
        # Vault-lock teardown: any DELETE /mcp with the session id succeeds.
        session_id = self.headers.get("Mcp-Session-Id", "")
        print(f"[DELETE] session={session_id}")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def do_POST(self):
        path = self.path
        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length)

        # The client POSTs everything (initialize/test-connection is a POST),
        # so /mcp-redirect must answer the POST with a 302 - a GET-only
        # redirect would never be seen by the app. Body is discarded.
        if path == "/mcp-redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9999/mcp")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # Special endpoint: inject notifications/tools/list_changed into SSE stream.
        if path == "/mcp-listchanged":
            self._handle_listchanged_stream(raw)
            return

        # Normal /mcp traffic only.
        if path != "/mcp":
            self.send_error(404)
            return

        session_id = self.headers.get("Mcp-Session-Id", TEST_SESSION_ID)

        # One-shot re-init path: a known test session id 404s once.
        if session_id == "00000000-0000-0000-0000-000000000404":
            if self._404_once(session_id):
                return
            # already fired - fall through to serve this request normally

        try:
            req = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError:
            self._send_json(400, jsonrpc_response(None, error={"code": -32700, "message": "Parse error"}))
            return

        method = req.get("method")
        req_id = req.get("id")
        params = req.get("params", {})

        if method == "initialize":
            self._handle_initialize(req_id, params, session_id)
        elif method == "notifications/initialized":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif method == "tools/list":
            self._handle_tools_list(req_id, params, session_id)
        elif method == "tools/call":
            self._handle_tools_call(req_id, params, session_id)
        else:
            self._send_json(
                200,
                jsonrpc_response(
                    req_id,
                    error={"code": -32601, "message": f"Method {method} not found"},
                ),
            )

    def _404_once(self, session_id: str):
        # One-shot per session id: the first request 404s (the client must
        # re-initialize), everything after it is served normally - otherwise
        # the "retry after re-init" leg can never be observed.
        fired = getattr(Handler, "_404_fired", None)
        if fired is None:
            fired = Handler._404_fired = set()
        if session_id in fired:
            print(f"[404-once] session={session_id} already expired -> serving normally")
            return False
        fired.add(session_id)
        print(f"[404-once] session={session_id}")
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "27")
        self.end_headers()
        self.wfile.write(b'{"error":"session expired"}')
        return True

    def _handle_initialize(self, req_id, params, session_id: str):
        protocol = params.get("protocolVersion") if params else None
        # Prefer 2025-11-25, accept the other approved versions.
        if protocol in {"2025-11-25", "2025-06-18", "2025-03-26"}:
            pv = protocol
        else:
            pv = "2025-11-25"
        result = {
            "protocolVersion": pv,
            "serverInfo": {"name": "sshpan-mcp-smoke", "version": "0.0.1"},
            "capabilities": {
                "tools": {},
                "logging": {},
            },
        }
        headers = {"Mcp-Session-Id": session_id}
        self._send_json(200, jsonrpc_response(req_id, result=result), extra_headers=headers)

    def _handle_tools_list(self, req_id, params, session_id: str):
        cursor = (params or {}).get("cursor")
        page_size = 2
        # Cursor is an integer into ALL_TOOLS.
        try:
            start = int(cursor) if cursor is not None else 0
        except (TypeError, ValueError):
            start = 0

        paginated = ALL_TOOLS[start : start + page_size]
        next_start = start + page_size
        next_cursor = str(next_start) if next_start < len(ALL_TOOLS) else None

        result = {
            "tools": paginated,
            "nextCursor": next_cursor,
        }
        self._send_json(200, jsonrpc_response(req_id, result=result))

    def _handle_tools_call(self, req_id, params, session_id: str):
        name = (params or {}).get("name")
        arguments = (params or {}).get("arguments", {})
        meta = (params or {}).get("_meta", {})
        stream = meta.get("stream", False) if isinstance(meta, dict) else False

        # Return application/json unless caller asks for text/event-stream.
        if stream:
            self._stream_tools_call(req_id, name, arguments)
            return

        result = self._run_tool(name, arguments)
        body = {
            "content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}],
            "isError": result.get("isError", False),
        }
        self._send_json(200, jsonrpc_response(req_id, result=body))

    def _run_tool(self, name: str, arguments: dict):
        if name == "echo":
            return {"ok": True, "echoed": arguments.get("message", "")}
        if name == "get_time":
            import datetime

            return {"ok": True, "iso": datetime.datetime.now().isoformat()}
        if name == "read_file":
            return {"ok": True, "path": arguments.get("path"), "content": "hello from mock"}
        if name == "make_error":
            return {"ok": False, "isError": True, "error": arguments.get("reason", "boom")}
        if name == "image_cat":
            # Return as an image resource object.
            return {
                "ok": True,
                "resource": {
                    "type": "image",
                    "mimeType": "image/png",
                    "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGfCMuP4w==",
                },
            }
        return {"ok": False, "error": f"unknown tool: {name}"}

    def _stream_tools_call(self, req_id, name: str, arguments: dict):
        # text/event-stream with a tiny JSON result at the end.
        result = self._run_tool(name, arguments)
        event_id = "evt-1"
        lines = [
            f"id: {event_id}\n",
            "event: message\n",
            f"data: {json.dumps({'progress': 'started'}, separators=(',', ':'))}\n\n",
            f"id: {event_id}\n",
            "event: message\n",
            f"data: {json.dumps({'progress': 'finished', 'result': result}, separators=(',', ':'))}\n\n",
        ]
        payload = "".join(lines).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(payload)

    def _handle_listchanged_stream(self, raw: bytes):
        # Same as a tools/call but first injects a notification event.
        try:
            req = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError:
            req = {}
        req_id = req.get("id")
        result = self._run_tool(req.get("params", {}).get("name"), req.get("params", {}).get("arguments", {}))
        event_id = "evt-listchanged"
        lines = [
            f"id: {event_id}\n",
            "event: notification\n",
            "data: {\"method\":\"notifications/tools/list_changed\",\"params\":{}}\n\n",
            f"id: {event_id}\n",
            "event: message\n",
            f"data: {json.dumps({'ok': True, 'result': result}, separators=(',', ':'))}\n\n",
        ]
        payload = "".join(lines).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(payload)


def main():
    parser = argparse.ArgumentParser(description="Mock MCP Streamable-HTTP server")
    parser.add_argument("port", nargs="?", type=int, default=int(os.environ.get("PORT", "8777")))
    args = parser.parse_args()

    server = HTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}"
    sys.stdout.write(f"[mcp-smoke-server] listening on {url}\n")
    sys.stdout.write("[mcp-smoke-server] Test here: /mcp (POST), /mcp-listchanged (SSE), /mcp-redirect (302)\n")
    sys.stdout.write("                 Expect: initialize, tools/list pagination, tools/call JSON/SSE,\n")
    sys.stdout.write("                 one-shot 404 session, redirect hard-error, DELETE teardown.\n")
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[mcp-smoke-server] shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
