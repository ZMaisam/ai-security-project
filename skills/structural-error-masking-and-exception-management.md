# Structural Error Masking and Exception Management

## What it is

Structural error masking is the practice of ensuring that any internal failure inside a security-critical function — an unexpected exception, a malformed input, a bug — never leaks internal details (stack traces, code paths, system internals) to the caller, and instead always resolves to a safe, generic, deny-by-default outcome. It's "structural" because the safety property is built into the control flow itself (wrapping the whole decision path in error handling), not left to be handled correctly by chance at every individual call site.

## Why it matters

Two separate problems are being solved at once here. First, information leakage: a raw exception message or stack trace can reveal internal implementation details (library versions, file paths, internal logic) that help an attacker understand and probe the system further — this is a form of reconnaissance-enabling information disclosure. Second, and more importantly for a security-critical gate: if an unexpected error causes a policy-enforcement function to crash or return an ambiguous result, the *worst* possible outcome is for the calling code to interpret that ambiguity as "allow." A well-designed authorization function should fail toward denial, not toward permission, no matter what goes wrong internally.

## How it works

The core authorization logic is wrapped in a broad exception handler. If anything inside that logic throws an unexpected error — a malformed argument, a missing key, a bug in a validator — the exception is caught, and the function returns the same structured "deny" decision it would return for any other rejected request, with a generic reason rather than the raw exception text.

## Implementation

```python
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
        # structural error masking: never leak internals, always return a safe generic denial
        return _decision("deny", tool, args, actor, "internal error - request denied by default")
```

## Output and what it means

In our test run, none of the four sample tool calls actually triggered an internal exception — each one resolved cleanly through the normal `if`/`return` branches (allow, require_approval, or deny for the reasons already covered in the tool-invocation control). That's actually the expected and desired outcome for well-formed input: the `except` branch is a safety net for *unexpected* failures, not something that should fire during normal operation.

The important design property to highlight is what *would* happen if something unforeseen went wrong — a malformed argument type that a validator didn't anticipate, a missing dictionary key, or a future code change that introduces a bug. In every one of those cases, the `try/except` wrapper guarantees the function still returns the exact same structured decision object (with `"decision": "deny"`) that a normal, deliberate denial would produce — rather than crashing, returning `None`, or leaking a Python traceback to whatever called `authorize()`. From the caller's point of view, an internal bug and a legitimate policy denial are indistinguishable: both come back as a clean, safe "deny." That indistinguishability is exactly the point — it means a bug in this function can never accidentally result in an unauthorized action being permitted.

## When to use it

Any function acting as a security or policy gate — authentication checks, authorization decisions, input validators — where a failure mode of "silently allow" or "leak internal details" would be worse than a failure mode of "deny and log a generic reason."
