# piqrypt-crewai-integration

**Verifiable AI Agent Memory_Cryptographic audit trail for CrewAI agents.**

[![PyPI](https://img.shields.io/pypi/v/piqrypt-langchain)](https://pypi.org/project/piqrypt-langchain/)
[![Downloads](https://img.shields.io/pypi/dm/piqrypt-langchain)](https://pypi.org/project/piqrypt-langchain/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![PiQrypt](https://img.shields.io/badge/powered%20by-PiQrypt-blue)](https://github.com/piqrypt/piqrypt)


Every agent decision, task execution, and crew result — signed, hash-chained, tamper-proof.

```bash
pip install piqrypt-crewai
```

---

## The problem

CrewAI agents make decisions autonomously. When something goes wrong — or needs to be proven right — your logs are editable. PiQrypt fixes that.

---

## Quickstart

```python
from piqrypt_crewai import AuditedAgent, AuditedCrew, stamp_task

# Drop-in replacement for Agent
researcher = AuditedAgent(
    role="Researcher",
    goal="Find accurate information on AI compliance",
    backstory="Expert in regulatory frameworks",
    identity_file="researcher.json"   # piqrypt identity
)

writer = AuditedAgent(
    role="Writer",
    goal="Write clear compliance reports",
    backstory="Technical writer",
    identity_file="writer.json"
)

# Drop-in replacement for Crew
crew = AuditedCrew(
    agents=[researcher, writer],
    tasks=[research_task, write_task],
    identity_file="crew-coordinator.json"
)

result = crew.kickoff(inputs={"topic": "EU AI Act compliance"})

# Export tamper-proof audit trail
crew.export_audit("eu-ai-act-audit.json")
# $ piqrypt verify eu-ai-act-audit.json
```

---

## Decorator pattern — minimal change

```python
from piqrypt_crewai import stamp_task

@stamp_task("research", identity_file="my-agent.json")
def research(topic: str) -> str:
    return your_research_logic(topic)

@stamp_task("write_report", identity_file="my-agent.json")
def write_report(research: str) -> str:
    return your_writing_logic(research)
```

---

## What gets stamped

| Event | When |
|---|---|
| `agent_initialized` | Agent creation |
| `task_start` | Before task execution |
| `task_complete` | After task execution (with result hash) |
| `crew_kickoff` | Before crew runs |
| `crew_complete` | After crew finishes (with result hash) |
| `task_executed` | When using `@stamp_task` decorator |

All events are Ed25519-signed, SHA-256 hash-chained, stored locally.  
No content is stored — only SHA-256 hashes of inputs and outputs.

---

## Verify

```bash
piqrypt verify crewai-audit.json
# ✅ Chain integrity verified — 12 events, 0 forks
```

---

## Scope

| Use case | AISS profile |
|---|---|
| Development / PoC | AISS-1 (Free, included) |
| Non-critical production | AISS-1 (Free) |
| Regulated production | AISS-2 (Pro — `pip install piqrypt[aiss2]`) |

---

## Links

- **PiQrypt core:** [github.com/piqrypt/piqrypt](https://github.com/piqrypt/piqrypt)
- **Integration guide:** [INTEGRATION.md](https://github.com/piqrypt/piqrypt/blob/main/INTEGRATION.md)
- **Issues:** [github.com/piqrypt/piqrypt/issues](https://github.com/piqrypt/piqrypt/issues)

---


