#!/usr/bin/env bash
# SPDX-License-Identifier: MIT-0
# Four-step demo: same Gateway, two Cognito M2M callers, different visible + callable tools.
#   1 reader   tools/list           -> getSite only
#   2 operator tools/list           -> getSite + setSiteStatus
#   3 reader   call setSiteStatus   -> JSON-RPC -32000 Forbidden from the REQUEST interceptor (API never called)
#   4 operator call setSiteStatus   -> status flipped via Gateway -> Lattice -> ALB -> Kong key-auth -> API
# Tokens are decoded locally to show scopes; they are never printed. Needs: aws CLI, python3 with
# demo/requirements.txt, and credentials for the account the stack is in.
set -euo pipefail
STACK="${STACK:-KtaToolAccess}"
PY="${PYTHON:-python3}"
# A relative interpreter path (the README uses PYTHON=.venv/bin/python) is relative to where you ran the
# script, so make it absolute before changing into demo/.
if [[ "$PY" == */* && "$PY" != /* ]]; then PY="$PWD/$PY"; fi
cd "$(dirname "$0")"
GET_TOOL="kta-sites___getSite"
SET_TOOL="kta-sites___setSiteStatus"
SET_ARGS='{"siteId":"SITE-001","status":"paused"}'

if [[ -t 1 ]]; then B=$'\e[1m'; D=$'\e[2m'; G=$'\e[32m'; R=$'\e[31m'; X=$'\e[0m'; else B=""; D=""; G=""; R=""; X=""; fi
rule() { printf '%s\n' "${D}────────────────────────────────────────────────────────────────────────${X}"; }
kv()   { printf '  %-8s %s\n' "$1" "$2"; }
json() { "$PY" -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

out() { aws cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }
export GATEWAY_URL; GATEWAY_URL=$(out GatewayUrl)
TOKEN_URL=$(out TokenUrl); POOL=$(out UserPoolId); LOGS=$(out InterceptorLogGroup)

get_token() { # $1 client id. The client secret goes from the AWS API straight into the child's env.
  CLIENT_ID="$1" TOKEN_URL="$TOKEN_URL" CLIENT_SECRET="$(aws cognito-idp describe-user-pool-client \
    --user-pool-id "$POOL" --client-id "$1" --query UserPoolClient.ClientSecret --output text)" \
    "$PY" client.py token | json 'd["token"]'
}
scopes() { TOKEN="$1" "$PY" -c 'import base64,json,os; p=os.environ["TOKEN"].split(".")[1]
c=json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4))); print(" ".join(sorted(c.get("scope","").split())))'; }
mcp() { BEARER_TOKEN="$1" "$PY" client.py "${@:2}"; }

# Latest interceptor decision for this caller since $1 (ms). CloudWatch can lag a few seconds.
evidence() { # $1 start_ms $2 client_id $3 REQUEST|RESPONSE
  local line=""
  for _ in 1 2 3 4 5 6; do
    line=$(aws logs filter-log-events --log-group-name "$LOGS" --start-time "$1" \
      --filter-pattern "{ \$.caller = \"$2\" && \$.point = \"$3\" }" --query 'events[].message' --output json \
      | "$PY" -c 'import json,sys
for m in json.load(sys.stdin) or []:
    d = json.loads(m.strip().split("\t")[-1])
    print("decision=%s tool=%s" % (d["decision"], d["tool"]) if d["point"] == "REQUEST"
          else "tools/list filtered %s -> %s" % (d["tools_in"], d["tools_out"]))' | tail -1)
    [[ -n "$line" ]] && break; sleep 5
  done
  kv "Log" "${D}interceptor:${X} ${line:-(no log line yet)}"
}

PASS=0; ROWS=()
result() { # $1 n $2 caller $3 action $4 ok(0/1)
  if [[ "$4" == 0 ]]; then PASS=$((PASS + 1)); ROWS+=("$1|$2|$3|${G}PASS${X}"); kv "Result" "${G}${B}PASS${X}"
  else ROWS+=("$1|$2|$3|${R}FAIL${X}"); kv "Result" "${R}${B}FAIL${X}"; fi; echo
}

echo; echo "${B}Per-agent tool access: AgentCore Gateway interceptor + Kong key-auth${X}"; rule
kv "Gateway" "$GATEWAY_URL"
kv "Layers" "IdP scopes (who) -> Gateway interceptor (which tools) -> Kong key-auth (which APIs)"; echo

READER_ID=$(out ReaderClientId); OPERATOR_ID=$(out OperatorClientId)
READER=$(get_token "$READER_ID"); OPERATOR=$(get_token "$OPERATOR_ID")
echo "${B}Callers${X} ${D}(client-credentials tokens decoded locally, never printed)${X}"
printf '  %-9s %-28s %s\n' reader "$READER_ID" "$(scopes "$READER")" operator "$OPERATOR_ID" "$(scopes "$OPERATOR")"; echo
echo "${B}Policy${X} ${D}(interceptor TOOL_POLICY: scope -> tools)${X}"
aws lambda get-function-configuration --function-name kta-tool-interceptor --query 'Environment.Variables.TOOL_POLICY' --output text \
  | json '"\n".join("  %-22s -> %s" % (k, ", ".join(v)) for k, v in sorted(d.items()))'; echo

now_ms() { "$PY" -c 'import time; print(int(time.time()*1000))'; }

echo "${B}1. reader -> tools/list${X}"; rule; kv "Expect" "$GET_TOOL only"
T=$(now_ms); TOOLS=$(mcp "$READER" list | json '" ".join(d["tools"])'); kv "Got" "$TOOLS"
evidence "$T" "$READER_ID" RESPONSE
[[ "$TOOLS" == "$GET_TOOL" ]] && P=0 || P=1; result 1 reader "tools/list" $P

echo "${B}2. operator -> tools/list${X}"; rule; kv "Expect" "$GET_TOOL + $SET_TOOL"
T=$(now_ms); TOOLS=$(mcp "$OPERATOR" list | json '" ".join(sorted(d["tools"]))'); kv "Got" "$TOOLS"
evidence "$T" "$OPERATOR_ID" RESPONSE
[[ "$TOOLS" == "$GET_TOOL $SET_TOOL" ]] && P=0 || P=1; result 2 operator "tools/list" $P

echo "${B}3. reader -> tools/call $SET_TOOL${X} ${D}(a tool it was never shown)${X}"; rule
kv "Call" "$SET_ARGS"; kv "Expect" "JSON-RPC -32000 Forbidden; Kong and the API are never called"
T=$(now_ms); R3=$(mcp "$READER" call "$SET_TOOL" "$SET_ARGS"); kv "Got" "$R3"
evidence "$T" "$READER_ID" REQUEST
[[ $(json 'd.get("error",{}).get("code")' <<<"$R3") == "-32000" ]] && P=0 || P=1; result 3 reader "call setSiteStatus" $P

echo "${B}4. operator -> tools/call $SET_TOOL${X}"; rule
BEFORE=$(mcp "$OPERATOR" call "$GET_TOOL" '{"siteId":"SITE-001"}' | json 'd["result"]["status"]')
NEW=$([[ "$BEFORE" == paused ]] && echo active || echo paused)   # always a real change, even on re-runs
ARGS4="{\"siteId\":\"SITE-001\",\"status\":\"$NEW\"}"
kv "Call" "$ARGS4  ${D}(getSite before: status=$BEFORE)${X}"
kv "Path" "Gateway -> VPC Lattice -> internal ALB -> Kong key-auth -> API"; kv "Expect" "status=$NEW"
T=$(now_ms); R4=$(mcp "$OPERATOR" call "$SET_TOOL" "$ARGS4"); kv "Got" "$R4"
evidence "$T" "$OPERATOR_ID" REQUEST
[[ $(json 'd.get("result",{}).get("status") if isinstance(d.get("result"),dict) else None' <<<"$R4") == "$NEW" ]] && P=0 || P=1
result 4 operator "call setSiteStatus" $P

echo "${B}Summary${X}"; rule
for r in "${ROWS[@]}"; do IFS='|' read -r n who act res <<<"$r"; printf '  %-2s %-9s %-22s %s\n' "$n" "$who" "$act" "$res"; done
echo; echo "  ${B}${PASS}/4 PASS${X}"; echo
[[ "$PASS" == 4 ]]
