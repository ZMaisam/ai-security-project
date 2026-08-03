# AI Security — 10 Skills, Explained and Implemented

This repository documents my coursework assignment for the **AI Security** track of a cybersecurity skills assignment, based on the [Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) library — an open-source collection of 800+ structured cybersecurity practitioner skills.

## What's inside

Each `.md` file in this repo covers one skill and follows the same structure:

- **What it is** — a plain-language explanation of the security control
- **Why it matters** — the real-world risk it addresses
- **How it works** — the underlying mechanism
- **Implementation** — the actual Python code used to test/demonstrate it
- **Output and what it means** — the real output produced, with a plain-language breakdown of what it shows
- **When to use it** — the practical context where this control applies

## Lab environment

All hands-on testing was performed in a self-hosted lab, not against any third-party or production system:

- **Hypervisor:** Proxmox VE, self-hosted on a repurposed laptop
- **Guest OS:** Ubuntu Server, accessed remotely via SSH from a main laptop
- **Target LLM:** [Ollama](https://ollama.com) running `llama3.2:1b` locally — no external API calls, no data leaving the lab
- **Language/runtime:** Python 3.14, isolated per-skill virtual environments

## A note on implementation choices

Several reference tools named in the source skills (garak, LLM Guard, Presidio/spaCy) failed to install in this lab due to native-extension build incompatibilities between their older Cython-based dependencies and Python 3.14. Rather than lose disproportionate time to environment debugging under a tight deadline, the affected skills (1, 5, 7, 9, and 10 above where applicable) were implemented using direct, hand-written Python scripts that exercise the same underlying security logic the reference tool would (regex-based signature matching instead of an ML-based scanner, for example). This is noted explicitly within each affected skill's file rather than hidden, since it reflects a real and common trade-off in applied security work — a reference tool named in a playbook doesn't always fit a given environment, and the underlying control can often still be demonstrated directly.

## Key findings across all 10 skills

A pattern worth highlighting: several tests didn't just produce a clean "pass" — they surfaced genuine limitations in naive, rule-based detection approaches:

- A persona-based jailbreak was blocked, but a plain instruction-override framing on a dual-use topic got partial compliance (Skill 7 / garak).
- A system-prompt leak-detector based on simple keyword matching produced false positives, and a genuine leak was only achieved through an indirect reframing rather than a direct request (Skill 6).
- A direct-injection classifier missed a textbook injection phrase due to an overly narrow regex pattern (documented in the broader assignment, not filed separately here).

These aren't failures of the exercise — they're the actual point of hands-on testing: static, signature-based security controls are useful and often effective, but they are also brittle in specific, discoverable ways that only show up when you actually run them against real input rather than reason about them in the abstract.

## Attribution

Skill structure and reference workflows are adapted from [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) (Apache 2.0), an independent, community-created project not affiliated with Anthropic PBC. All code, test cases, and output in this repository represent my own implementation and testing work for this assignment.
