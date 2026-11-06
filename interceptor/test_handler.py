# SPDX-License-Identifier: MIT-0
"""Unit tests for the interceptor. Run: pytest interceptor -q
Events follow the documented MCP interceptor payloads (gateway-interceptors-types.html)."""
import base64
import json
import time

import pytest

import handler

RS = "kta-api"
GET = "kta-sites___getSite"
SET = "kta-sites___setSiteStatus"
POLICY = {f"{RS}/sites.read": [GET], f"{RS}/sites.write": [SET]}
READER = f"{RS}/sites.read"
OPERATOR = f"{RS}/sites.read {RS}/sites.write"
ALL_TOOLS = [{"name": n, "inputSchema": {"type": "object"}} for n in (GET, SET)]
LIST_REQ = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
LIST_RESP = {"jsonrpc": "2.0", "id": 1, "result": {"tools": ALL_TOOLS, "nextCursor": "abc"}}


@pytest.fixture(autouse=True)
def _policy(monkeypatch):
    monkeypatch.setenv("TOOL_POLICY", json.dumps(POLICY))


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def token(scope: str, **extra) -> str:
    claims = {"client_id": "synthetic-client", "scope": scope, "exp": int(time.time()) + 600, **extra}
    return f"{_b64({'alg': 'RS256'})}.{_b64(claims)}.c2lnbmF0dXJl"


def request_event(body: dict, tok: str | None = None) -> dict:
    gr = {"path": "/mcp", "httpMethod": "POST", "body": body}
    if tok is not None:
        gr["headers"] = {"Authorization": f"Bearer {tok}"}
    return {"interceptorInputVersion": "1.0", "mcp": {"rawGatewayRequest": {"body": json.dumps(body)}, "gatewayRequest": gr}}


def response_event(req_body: dict, resp_body: dict, tok: str | None = None) -> dict:
    ev = request_event(req_body, tok)
    ev["mcp"]["gatewayResponse"] = {"statusCode": 200, "headers": {"Mcp-Session-Id": "s"}, "body": resp_body}
    return ev


def call_req(name) -> dict:
    return {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": name, "arguments": {"siteId": "SITE-001"}}}


def listed(out: dict) -> list[str]:
    assert out["interceptorOutputVersion"] == "1.0"
    return [t["name"] for t in out["mcp"]["transformedGatewayResponse"]["body"]["result"]["tools"]]


def denied(out: dict) -> bool:
    return "transformedGatewayRequest" not in out["mcp"] and \
        out["mcp"]["transformedGatewayResponse"]["body"]["error"]["code"] == handler.DENY_CODE


# ---------- RESPONSE: tools/list ----------

def test_reader_sees_only_get_site():
    out = handler.lambda_handler(response_event(LIST_REQ, LIST_RESP, token(READER)), None)
    assert listed(out) == [GET]
    body = out["mcp"]["transformedGatewayResponse"]["body"]
    assert body["id"] == 1 and body["result"]["nextCursor"] == "abc"


def test_operator_sees_both():
    assert listed(handler.lambda_handler(response_event(LIST_REQ, LIST_RESP, token(OPERATOR)), None)) == [GET, SET]


def test_input_not_mutated():
    ev = response_event(LIST_REQ, LIST_RESP, token(READER))
    handler.lambda_handler(ev, None)
    assert len(ev["mcp"]["gatewayResponse"]["body"]["result"]["tools"]) == 2


def test_lowercase_header_and_list_scope_claim():
    ev = response_event(LIST_REQ, LIST_RESP, None)
    ev["mcp"]["gatewayRequest"]["headers"] = {"authorization": f"Bearer {token([f'{RS}/sites.write'])}"}
    assert listed(handler.lambda_handler(ev, None)) == [SET]


def test_match_is_exact_not_prefix():
    tools = [{"name": GET + "Admin"}, {"name": "kta-sites"}, {"name": GET}]
    resp = {"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}}
    assert listed(handler.lambda_handler(response_event(LIST_REQ, resp, token(READER)), None)) == [GET]


@pytest.mark.parametrize("tok", [None, "not-a-jwt", "a.%%%.c", f"x.{_b64(['list'])}.y"])
def test_missing_or_malformed_token_lists_nothing(tok):
    assert listed(handler.lambda_handler(response_event(LIST_REQ, LIST_RESP, tok), None)) == []


def test_expired_token_lists_nothing():
    tok = token(OPERATOR, exp=int(time.time()) - 5)
    assert listed(handler.lambda_handler(response_event(LIST_REQ, LIST_RESP, tok), None)) == []


def test_unknown_scope_lists_nothing():
    assert listed(handler.lambda_handler(response_event(LIST_REQ, LIST_RESP, token(f"{RS}/other")), None)) == []


def test_malformed_policy_fails_closed(monkeypatch):
    monkeypatch.setenv("TOOL_POLICY", "not json")
    assert listed(handler.lambda_handler(response_event(LIST_REQ, LIST_RESP, token(OPERATOR)), None)) == []


def test_response_header_cannot_grant_scopes():
    ev = response_event(LIST_REQ, LIST_RESP, None)
    ev["mcp"]["gatewayResponse"]["headers"]["Authorization"] = f"Bearer {token(OPERATOR)}"
    assert listed(handler.lambda_handler(ev, None)) == []


def test_semantic_search_results_filtered():
    req = call_req(handler.SEARCH_TOOL)
    resp = {"jsonrpc": "2.0", "id": 7, "result": {
        "structuredContent": {"tools": ALL_TOOLS},
        "content": [{"type": "text", "text": json.dumps({"tools": ALL_TOOLS})}],
    }}
    result = handler.lambda_handler(response_event(req, resp, token(READER)), None)["mcp"]["transformedGatewayResponse"]["body"]["result"]
    assert [t["name"] for t in result["structuredContent"]["tools"]] == [GET]
    assert [t["name"] for t in json.loads(result["content"][0]["text"])["tools"]] == [GET]


def test_semantic_search_call_needs_a_token():
    assert "transformedGatewayRequest" in handler.lambda_handler(request_event(call_req(handler.SEARCH_TOOL), token(READER)), None)["mcp"]
    assert denied(handler.lambda_handler(request_event(call_req(handler.SEARCH_TOOL), None), None))


# ---------- REQUEST: tools/call ----------

def test_reader_get_site_passes_through_unchanged():
    req = call_req(GET)
    assert handler.lambda_handler(request_event(req, token(READER)), None) == \
        {"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayRequest": {"body": req}}}


def test_reader_set_status_denied_with_jsonrpc_error():
    out = handler.lambda_handler(request_event(call_req(SET), token(READER)), None)
    assert denied(out)
    resp = out["mcp"]["transformedGatewayResponse"]
    assert resp["statusCode"] == 200 and resp["body"]["id"] == 7 and "result" not in resp["body"]
    assert resp["body"]["error"]["message"].startswith("Forbidden:") and SET in resp["body"]["error"]["message"]


def test_operator_set_status_allowed():
    assert "transformedGatewayRequest" in handler.lambda_handler(request_event(call_req(SET), token(OPERATOR)), None)["mcp"]


@pytest.mark.parametrize("tok", [None, "garbage", "a.b"])
def test_bad_token_call_denied(tok):
    assert denied(handler.lambda_handler(request_event(call_req(GET), tok), None))


@pytest.mark.parametrize("name", ["unknown", "", None, 42, "kta-sites"])
def test_unknown_tool_denied(name):
    assert denied(handler.lambda_handler(request_event(call_req(name), token(OPERATOR)), None))


def test_non_bearer_scheme_denied():
    ev = request_event(call_req(GET), None)
    ev["mcp"]["gatewayRequest"]["headers"] = {"Authorization": f"Basic {token(OPERATOR)}"}
    assert denied(handler.lambda_handler(ev, None))


def test_exception_fails_closed(monkeypatch):
    monkeypatch.setattr(handler, "_allowed", lambda _c: 1 / 0)
    assert denied(handler.lambda_handler(request_event(call_req(GET), token(OPERATOR)), None))
    assert listed(handler.lambda_handler(response_event(LIST_REQ, LIST_RESP, token(OPERATOR)), None)) == []


@pytest.mark.parametrize("resp", [None, "not json", [], {"jsonrpc": "2.0", "id": 1},
                                  {"jsonrpc": "2.0", "id": 1, "result": "tools"},
                                  {"jsonrpc": "2.0", "id": 1, "result": None}])
def test_malformed_list_response_fails_closed(resp):
    out = handler.lambda_handler(response_event(LIST_REQ, resp, token(OPERATOR)), None)
    assert listed(out) == []
    assert out["mcp"]["transformedGatewayResponse"]["body"]["id"] == 1


def test_list_error_response_passes_through():
    resp = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message": "Internal error"}}
    out = handler.lambda_handler(response_event(LIST_REQ, resp, token(OPERATOR)), None)
    assert out["mcp"]["transformedGatewayResponse"] == {"body": resp, "statusCode": 200}


def test_malformed_search_response_fails_closed():
    out = handler.lambda_handler(response_event(call_req(handler.SEARCH_TOOL), "oops", token(READER)), None)
    assert out["mcp"]["transformedGatewayResponse"]["body"]["error"]["code"] == handler.DENY_CODE


def _invalid(out: dict) -> bool:
    return "transformedGatewayRequest" not in out["mcp"] and \
        out["mcp"]["transformedGatewayResponse"]["body"]["error"]["code"] == handler.INVALID_REQUEST


@pytest.mark.parametrize("body", [[call_req(SET)], [call_req(GET), call_req(SET)], [], "tools/call", 7])
def test_batch_or_non_object_request_rejected(body):
    assert _invalid(handler.lambda_handler(request_event(body, token(OPERATOR)), None))
    assert _invalid(handler.lambda_handler(response_event(body, LIST_RESP, token(OPERATOR)), None))


# ---------- passthrough ----------

@pytest.mark.parametrize("method", ["initialize", "ping", "notifications/initialized", "tools/list"])
def test_request_non_call_methods_pass_through(method):
    body = {"jsonrpc": "2.0", "id": 3, "method": method, "params": {}}
    assert handler.lambda_handler(request_event(body, None), None) == \
        {"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayRequest": {"body": body}}}


def test_response_for_call_passes_through():
    req = call_req(GET)
    resp = {"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": "{}"}]}}
    out = handler.lambda_handler(response_event(req, resp, token(READER)), None)
    assert out["mcp"]["transformedGatewayResponse"] == {"body": resp, "statusCode": 200}


def test_token_never_logged(caplog):
    tok = token(READER)
    with caplog.at_level("INFO"):
        handler.lambda_handler(request_event(call_req(SET), tok), None)
        handler.lambda_handler(response_event(LIST_REQ, LIST_RESP, tok), None)
    assert caplog.records and tok not in caplog.text and tok.split(".")[1] not in caplog.text
