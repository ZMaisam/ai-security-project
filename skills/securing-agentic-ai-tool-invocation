# securing-agentic-ai-tool-invocation

## What it is

Human-in-the-loop (HITL) gatekeeping is a control that pauses an AI agent before it executes a high-impact action, requiring explicit human approval before the action proceeds. "Context-aware" means the decision to require approval depends on what the agent is trying to do — a read-only search doesn't need sign-off, but sending an email or deleting data does.

## Why it matters

Autonomous agents decide which tools to call based on reasoning over input that may be attacker-influenced (a prompt injection, a poisoned document, a manipulated tool result). If an agent can take irreversible, high-impact actions entirely on its own judgment, a single successful manipulation can cause real-world harm before anyone notices. A human approval gate acts as a circuit breaker: even if the agent's reasoning is compromised, a person still has to sign off before anything consequential actually happens.

## How it works

Every tool an agent can call is assigned an impact tier (e.g. read, write, high-impact). Low-impact actions proceed automatically. High-impact actions are routed to a human approver, and — critically — if no approval is received (timeout, no response, explicit denial), the action is denied by default rather than allowed. This "fail-closed" behavior is what makes the gate trustworthy: silence or ambiguity should never be treated as consent.

## Implementation

```python
def request_approval(event):
    # Simulated HITL gate — fail-closed by default
    print(f"\n>> APPROVAL NEEDED for {event['tool']} (actor={event['actor']}, reason={event['reason']})")
    response = "n"  # simulate a human denying it, since this is a non-interactive test run
    approved = response.strip().lower() == "y"
    print(f">> Human decision: {'APPROVED' if approved else 'DENIED (fail-closed default)'}")
    return approved

# Called only when the policy layer has already marked a tool call as "require_approval"
# (i.e. high-impact tools like send_email or delete_database)
for tool, args, actor in test_calls:
    decision = authorize(tool, args, actor)   # returns allow / require_approval / deny
    if decision["decision"] == "require_approval":
        request_approval(decision)
```

## Output and what it means

```
=== Tool call: send_email by alice ===
{ "decision": "require_approval", "reason": "high-impact tool" }

>> APPROVAL NEEDED for send_email (actor=alice, reason=high-impact tool)
>> Human decision: DENIED (fail-closed default)

=== Tool call: delete_database by mallory ===
{ "decision": "require_approval", "reason": "high-impact tool" }

>> APPROVAL NEEDED for delete_database (actor=mallory, reason=high-impact tool)
>> Human decision: DENIED (fail-closed default)
```

In plain terms: both `send_email` and `delete_database` were correctly identified as high-impact actions and routed to a human approval step rather than executing immediately. Since this test ran without an actual human present to approve anything, both actions were correctly denied by default — nothing happened simply because no one was there to say "yes." That's the entire point of the control: an agent should never interpret the absence of a human as a green light. In a real deployment, the approval step would notify an actual person (via Slack, email, a dashboard, etc.) and wait for a genuine response instead of the simulated "n" used here.

## When to use it

Any agentic system where a tool call has a real-world side effect that would be difficult or impossible to undo — sending communications, financial transactions, deleting data, or modifying infrastructure.
