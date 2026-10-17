# Agent Tripwire Threat Model

## 1. System Overview
An LLM agent uses tools through the Model Context Protocol (MCP).
Agent Tripwire is a gateway between the agent and its tool servers.
It logs, detects, and optionally blocks malicious activity.

## 2. Assets
| ID | Asset | Why it matters |
|----|-------|----------------|
| A1 | Files in the agent's workspace | May hold sensitive data |
| A2 | Credentials and API keys reachable by tools | Enable lateral movement |
| A3 | Outbound channels (email, HTTP, webhooks) | Exfiltration paths |
| A4 | The agent's instructions and context | Hijacking changes behavior |
| A5 | Tool definitions (names, descriptions, schemas) | Trusted by the model, so poisonable |
| A6 | Gateway policy and logs | Tampering would blind defenders |

## 3. Actors
| ID | Actor | Capability |
|----|-------|-----------|
| T1 | Malicious content author | Plants instructions in documents, web pages, or tool output |
| T2 | Malicious tool author | Publishes a tool with poisoned descriptions or changes it later |
| T3 | Malicious user | Directly prompts the agent to misuse tools |
| T4 | Compromised agent | Already hijacked; behaves adversarially |

## 4. Trust Boundaries
1. User to agent
2. Agent to gateway
3. Gateway to tool servers
4. Tool output back into the agent's context (the key weakness)

## 5. Attack Scenarios
- S1 Direct prompt injection
- S2 Indirect injection via tool output
- S3 Tool poisoning (malicious description)
- S4 Exfiltration through tool arguments
- S5 Sensitive file access
- S6 Privilege escalation by chaining tools
- S7 Rug pull (tool definition changes)
- S8 Canary or decoy abuse
