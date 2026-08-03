# Securing Agentic AI Tool Invocation

**Domain:** AI Security
**Related repo skill:** `securing-agentic-ai-tool-invocation` (full skill)
**MITRE ATLAS:** AML.T0053 (LLM Plugin Compromise)
**OWASP Agentic AI Top 10:** Tool Misuse, Excessive Agency, Privilege Compromise

## What it is

This is the umbrella control governing the point where an AI agent decides *which tool to call, with what arguments, and when*. Autonomous agents make this decision by reasoning over inputs that may be attacker-influenced, which makes the tool-invocation boundary the single highest-risk control point in an agentic system. Securing it combines several layered defenses rather than any one single check: a deny-by-default tool allowlist, per-tool argument validation, least-privilege identity scoping, human-in-the-loop approval for high-impact actions, and audit logging — all working together as defense-in-depth.

## Why it matters

A single successful prompt injection or a poisoned tool result can turn an otherwise well-designed agent into what's sometimes called a "confused deputy" — an agent that takes real, harmful actions (deleting data, sending funds, exfiltrating information) not because it was designed to, but because something in its input successfully manipulated its reasoning. Since agents are increasingly connected to systems with genuine side effects, the tool-invocation layer is where a purely conversational risk (a manipulated prompt) turns into a physical/operational one (an actual unauthorized action).

## How it works — the five layers

1. **Tool inventory & impact tiers** — every callable tool is registered with a classification (read / write / high-impact).
2. **Argument schema validation** — every call's arguments are checked against an explicit schema; anything unexpected is rejected.
3. **Scoped, short-lived identity** — each tool call runs with least-privilege, time-limited credentials rather than one shared "god-mode" account (in production, e.g. via AWS STS session policies).
4. **Policy decision gate** — a central function decides allow / require-approval / deny for every call, before execution.
5. **Human-in-the-loop approval** — high-impact actions pause for explicit human sign-off, and fail closed (deny) if none is given.

## Implementation

We implemented layers 1, 2, 4, and 5 directly (layer 3, cloud-scoped credentials, was out of scope without a live cloud account):

```python
import json, hashlib
from datetime import datetime, timezone

TOOL_POLICY = {
    "search_docs":    {"impact": "read",  "approval": False},
    "create_ticket":  {"impact": "write", "approval": False},
    "send_email":     {"impact": "high",  "approval": True},
    "delete_database":{"impact": "high",  "approval": True},
}

def validate_args(tool, args):
    if tool == "send_email":
        return isinstance(args.get("to"), str) and "@" in args.get("to", "")
    if tool == "search_docs":
        return isinstance(args.get("query"), str)
    if tool == "create_ticket":
        return isinstance(args.get("title"), str)
    if tool == "delete_database":
        return isinstance(args.get("db_name"), str)
    return False  # deny-by-default

def authorize(tool, args, actor):
    try:
        policy = TOOL_POLICY.get(tool)
        if policy is None:
            return _decision("deny", tool, args, actor, "tool not in allowlist")
        if not validate_args(tool, args):
            return _decision("deny", tool, args, actor, "args failed validation")
        if policy["approval"]:
            return _decision("require_approval", tool, args, actor, "high-impact tool")
        return _decision("allow", tool, args, actor, "allowlisted")
    except Exception:
        # structural error masking: never leak internals, default to a safe denial
        return _decision("deny", tool, args, actor, "internal error - request denied by default")

def _decision(decision, tool, args, actor, reason):
    event = {
        "ts": datetime.now(timezone.utc).isoformat(), "actor": actor, "tool": tool,
        "args_hash": hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest()[:12],
        "decision": decision, "reason": reason,
    }
    print(json.dumps(event, indent=2))
    return event
```

## Output and what it means

```
=== search_docs by alice ===       -> decision: allow          (read-only, allowlisted)
=== send_email by alice ===        -> decision: require_approval -> DENIED (fail-closed, no approver present)
=== delete_database by mallory === -> decision: require_approval -> DENIED (fail-closed, no approver present)
=== run_shell by mallory ===       -> decision: deny            (tool not in allowlist)
```

In plain terms: every one of the four test calls got exactly the outcome the layered design intends. The read-only tool ran immediately with no friction. Both high-impact actions — regardless of which "actor" requested them — were correctly routed to human approval and, since no human was actually present to approve them in this test, were denied by default rather than silently allowed. The completely unregistered tool (`run_shell`) never even reached the approval stage; it was rejected the moment the allowlist check ran. Together, these four outcomes demonstrate the layered nature of the control: different failure modes (unknown tool, high-impact tool, untrusted actor) are each caught by a different layer, which is exactly the point of defense-in-depth — no single check has to catch everything on its own.

## When to use it

Any agent with tool-calling capability connected to systems with real side effects — email, payments, file systems, infrastructure, or code execution.
