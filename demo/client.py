# SPDX-License-Identifier: MIT-0
"""Minimal MCP client for the demo. Prints one JSON object on stdout.

  python client.py token                 # env TOKEN_URL, CLIENT_ID, CLIENT_SECRET -> {"token": ...}
  python client.py list [--schemas]      # env GATEWAY_URL, BEARER_TOKEN -> {"tools": [...]}
  python client.py call NAME 'JSON'      # -> {"result": ...} or {"error": {"code", "message"}}
"""
import asyncio
import json
import os
import sys

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.exceptions import McpError


def token() -> dict:
    url = os.environ["TOKEN_URL"]
    if not url.startswith("https://"):
        sys.exit("TOKEN_URL must be https")
    r = httpx.post(url, data={"grant_type": "client_credentials"},
                   auth=(os.environ["CLIENT_ID"], os.environ["CLIENT_SECRET"]), timeout=15)
    r.raise_for_status()
    return {"token": r.json()["access_token"]}


async def mcp(argv: list[str]) -> dict:
    headers = {"Authorization": f'Bearer {os.environ["BEARER_TOKEN"]}'}
    async with streamablehttp_client(os.environ["GATEWAY_URL"], headers, timeout=60) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            if argv[0] == "list":
                tools = (await s.list_tools()).tools
                if "--schemas" in argv:
                    return {"tools": [{"name": t.name, "inputSchema": t.inputSchema} for t in tools]}
                return {"tools": [t.name for t in tools]}
            try:
                res = await s.call_tool(argv[1], json.loads(argv[2]) if len(argv) > 2 else {})
            except McpError as e:
                return {"error": {"code": e.error.code, "message": e.error.message}}
            if res.isError:
                return {"error": {"code": None, "message": " ".join(getattr(c, "text", "") for c in res.content)}}
            text = " ".join(getattr(c, "text", "") for c in res.content)
            try:
                return {"result": json.loads(text)}
            except ValueError:
                return {"result": text}


if __name__ == "__main__":
    args = sys.argv[1:] or ["list"]
    print(json.dumps(token() if args[0] == "token" else asyncio.run(mcp(args))))
