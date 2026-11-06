# SPDX-License-Identifier: MIT-0
"""AgentCore Gateway interceptor: per-caller tool access keyed on OAuth scopes.

One Lambda attached at both interception points (lib/stack.ts):
  REQUEST  - a `tools/call` for a tool the caller's scopes don't allow is answered with a JSON-RPC
             error (-32000 "Forbidden: ...") and never reaches the target (Kong / the API).
  RESPONSE - `tools/list` results, and semantic-search `structuredContent.tools` if present, are
             filtered to the tools the caller may use.
The event carries `mcp.gatewayResponse` only at RESPONSE; that is how the two points are told apart.
Contract: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-types.html

Policy: env TOOL_POLICY = {"<full scope>": ["<target>___<tool>", ...]}. Exact tool names only.

TRUST: the Gateway's CUSTOM_JWT authorizer validates signature, issuer, expiry and client_id before
any interceptor runs. This function only base64url-DECODES the token payload to read `scope`; it does
NOT verify the signature. That is safe because its decisions only take effect inside the Gateway: the
stack grants lambda:InvokeFunction only to the Gateway role, and only the Gateway holds Kong's key. A
principal in the account with broad Lambda permissions could invoke the function directly, but would
only get back a filtered list or an error, not access to the API. Put it behind anything other than a
CUSTOM_JWT Gateway and you must add JWKS verification here.

Fail closed: missing header (passRequestHeaders must be true), undecodable/expired token, no matching
scope, unknown tool, a batched (JSON array) or other non-object request body, a malformed tools/list
or search response, or any exception => deny / hide. The token is never logged. Stdlib only.
"""
from __future__ import annotations

import base64
import copy
import json
import logging
import os
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)

VERSION = "1.0"
SEARCH_TOOL = "x_amz_bedrock_agentcore_search"  # results are filtered at RESPONSE, so it can't leak
DENY_CODE = -32000  # JSON-RPC server-error range; MCP defines no authorization code
INVALID_REQUEST = -32600  # JSON-RPC "Invalid Request"


def _policy() -> dict[str, set[str]]:
    try:
        raw = json.loads(os.environ.get("TOOL_POLICY", "{}"))
        return {str(k): {str(v) for v in vals} for k, vals in raw.items() if isinstance(vals, list)}
    except (ValueError, AttributeError, TypeError):
        logger.error("TOOL_POLICY is not a JSON object of lists; denying everything")
        return {}


def _bearer(gateway_request: dict) -> str | None:
    for k, v in (gateway_request.get("headers") or {}).items():
        if isinstance(k, str) and k.lower() == "authorization" and isinstance(v, str):
            parts = v.split(None, 1)
            if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].strip():
                return parts[1].strip()
    return None


def _claims(token: str | None) -> dict | None:
    """Decode (NOT verify, see module docstring) the JWT payload. None on any problem."""
    if not token:
        return None
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        claims = json.loads(base64.urlsafe_b64decode((parts[1] + "=" * (-len(parts[1]) % 4)).encode("ascii")))
    except (ValueError, UnicodeError):
        return None
    if not isinstance(claims, dict):
        return None
    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and exp < time.time():  # defence in depth; Gateway checks too
        return None
    return claims


def _allowed(claims: dict | None) -> set[str]:
    """Tool names the caller's scopes unlock. No claims / no scopes => nothing."""
    raw = (claims or {}).get("scope", "")
    if isinstance(raw, str):
        scopes = set(raw.split())
    elif isinstance(raw, list):
        scopes = {s for s in raw if isinstance(s, str)}
    else:
        scopes = set()
    policy = _policy()
    return set().union(*(policy.get(s, set()) for s in scopes))


def _caller(claims: dict | None) -> str:
    return str((claims or {}).get("client_id") or (claims or {}).get("sub") or "unknown")


def _pass_request(body: dict) -> dict:
    return {"interceptorOutputVersion": VERSION, "mcp": {"transformedGatewayRequest": {"body": body}}}


def _respond(body: dict, status: int = 200) -> dict:
    return {"interceptorOutputVersion": VERSION, "mcp": {"transformedGatewayResponse": {"statusCode": status, "body": body}}}


def _deny(body: dict, tool: object) -> dict:
    """HTTP 200 + JSON-RPC error (not 403), so MCP clients surface a normal tool error."""
    return _respond({"jsonrpc": "2.0", "id": body.get("id"),
                     "error": {"code": DENY_CODE, "message": f"Forbidden: tool {tool!r} is not permitted for this caller"}})


def _pass_response(gateway_response: dict) -> dict:
    out: dict = {"body": gateway_response.get("body")}
    if "statusCode" in gateway_response:
        out["statusCode"] = gateway_response["statusCode"]
    return {"interceptorOutputVersion": VERSION, "mcp": {"transformedGatewayResponse": out}}


def _closed(body: dict) -> dict:
    """Fail-closed RESPONSE: an empty tools/list, or a JSON-RPC error for a tools/call."""
    if body.get("method") == "tools/list":
        return _respond({"jsonrpc": "2.0", "id": body.get("id"), "result": {"tools": []}})
    return _respond({"jsonrpc": "2.0", "id": body.get("id"),
                     "error": {"code": DENY_CODE, "message": "Forbidden: interceptor error"}})


def _on_request(body: dict, claims: dict | None) -> dict:
    if body.get("method") != "tools/call":
        return _pass_request(body)  # initialize, ping, tools/list, notifications/* ...
    name = (body.get("params") or {}).get("name")
    allowed = (name == SEARCH_TOOL and claims is not None) or (isinstance(name, str) and name in _allowed(claims))
    logger.info(json.dumps({"point": "REQUEST", "method": "tools/call", "tool": name,
                            "caller": _caller(claims), "decision": "allow" if allowed else "deny"}))
    return _pass_request(body) if allowed else _deny(body, name)


def _filter(tools: object, allowed: set[str]) -> list:
    return [t for t in tools if isinstance(t, dict) and t.get("name") in allowed] if isinstance(tools, list) else []


def _on_response(req_body: dict, gateway_response: dict, claims: dict | None) -> dict:
    method = req_body.get("method")
    is_search = method == "tools/call" and (req_body.get("params") or {}).get("name") == SEARCH_TOOL
    if method != "tools/list" and not is_search:
        return _pass_response(gateway_response)  # other methods: no tool list to filter
    resp_body = gateway_response.get("body")
    if isinstance(resp_body, dict) and isinstance(resp_body.get("error"), dict) and "result" not in resp_body:
        return _pass_response(gateway_response)  # a JSON-RPC error carries no tools
    if not isinstance(resp_body, dict) or not isinstance(resp_body.get("result"), dict):
        logger.warning(json.dumps({"point": "RESPONSE", "method": method, "search": is_search,
                                   "caller": _caller(claims), "decision": "fail closed: unexpected response body"}))
        return _closed(req_body)  # never pass an unrecognized shape through unfiltered

    allowed = _allowed(claims)
    new_body = copy.deepcopy(resp_body)  # keep jsonrpc / id / nextCursor
    result = new_body["result"]
    before = after = 0
    for holder in (result, result.get("structuredContent")):
        if isinstance(holder, dict) and "tools" in holder:
            before += len(holder["tools"]) if isinstance(holder["tools"], list) else 0
            holder["tools"] = _filter(holder["tools"], allowed)
            after += len(holder["tools"])
    if is_search:  # the same list may be serialized in a text block; rewrite it so it can't leak
        for block in result.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "text":
                try:
                    parsed = json.loads(block.get("text", ""))
                except (ValueError, TypeError):
                    continue
                if isinstance(parsed, dict) and "tools" in parsed:
                    parsed["tools"] = _filter(parsed["tools"], allowed)
                    block["text"] = json.dumps(parsed)
    logger.info(json.dumps({"point": "RESPONSE", "method": method, "search": is_search,
                            "caller": _caller(claims), "tools_in": before, "tools_out": after}))
    return _respond(new_body, gateway_response.get("statusCode", 200))


def lambda_handler(event, context):
    mcp = (event or {}).get("mcp") or {}
    gateway_request = mcp.get("gatewayRequest") or {}
    raw_body = gateway_request.get("body")
    body = raw_body if isinstance(raw_body, dict) else {}
    gateway_response = mcp.get("gatewayResponse")
    if raw_body is not None and not isinstance(raw_body, dict):
        # A JSON-RPC batch (a JSON array, allowed by MCP 2025-03-26) or any other non-object body is refused
        # at both points, so nothing inside it can skip the per-tool checks.
        logger.info(json.dumps({"point": "REQUEST" if gateway_response is None else "RESPONSE",
                                "decision": "deny", "reason": "non-object request body"}))
        return _respond({"jsonrpc": "2.0", "id": None, "error": {
            "code": INVALID_REQUEST, "message": "Invalid Request: send one JSON-RPC request per call"}})
    try:
        claims = _claims(_bearer(gateway_request))
        if gateway_response is not None:
            return _on_response(body, gateway_response, claims)
        return _on_request(body, claims)
    except Exception:  # noqa: BLE001 - any bug must fail closed, not open
        logger.exception("interceptor error; failing closed")
        if gateway_response is not None:
            if body.get("method") in ("tools/list", "tools/call"):
                return _closed(body)
            return _pass_response(gateway_response if isinstance(gateway_response, dict) else {})
        if body.get("method") == "tools/call":
            return _deny(body, (body.get("params") or {}).get("name"))
        return _pass_request(body)
