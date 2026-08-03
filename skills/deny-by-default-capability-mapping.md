# Deny-by-Default Capability Mapping

## What it is

Deny-by-default capability mapping is the practice of explicitly enumerating every tool/capability an AI agent is allowed to use, along with the exact shape of arguments each tool accepts — and rejecting anything that isn't on that list, rather than trying to enumerate and block everything *bad*. Any tool call to something not explicitly allowlisted is denied automatically, with no exceptions.

## Why it matters

Agentic systems are often built by wiring an LLM up to a growing set of tools over time. Without an explicit allowlist, an agent might be able to invoke a tool that was added for one purpose but is dangerous in another context, or an attacker who can influence the agent's tool selection might get it to call something it was never meant to use. Denying by default flips the security posture: instead of trying to anticipate every possible misuse and block it individually, only pre-approved actions are ever possible in the first place.

## How it works

Each known tool is registered with an impact tier (read / write / high-impact) and an explicit schema describing its valid arguments. Any tool call is checked against this registry: if the tool isn't registered, or if its arguments don't match the expected schema, the call is denied immediately — before it ever reaches the point of execution or human review.

## Implementation

```python
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
    return False  # deny-by-default: unknown tools are always rejected

def authorize(tool, args, actor):
    policy = TOOL_POLICY.get(tool)
    if policy is None:
        return _decision("deny", tool, args, actor, "tool not in allowlist")
    if not validate_args(tool, args):
        return _decision("deny", tool, args, actor, "args failed validation")
    if policy["approval"]:
        return _decision("require_approval", tool, args, actor, "high-impact tool")
    return _decision("allow", tool, args, actor, "allowlisted")
```

## Output and what it means

```
=== Tool call: search_docs by alice ===
{ "decision": "allow", "reason": "allowlisted" }

=== Tool call: run_shell by mallory ===
{ "decision": "deny", "reason": "tool not in allowlist" }
```

In plain terms: `search_docs`, a known, read-only, allowlisted tool, was permitted to run immediately. `run_shell` — a tool that was never registered in `TOOL_POLICY` at all — was denied instantly, without even reaching argument validation or the human-approval stage. This is the key behavior deny-by-default is meant to guarantee: an entirely unknown or unregistered capability is never accidentally granted just because an agent asked for it. If a new tool needs to be usable, it has to be deliberately added to the registry first — nothing is available by omission.

## When to use it

Any agentic system with tool-calling capability, especially as the number of available tools grows over time and it becomes easy to lose track of exactly what an agent can and can't do.
