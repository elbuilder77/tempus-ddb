# 📐 Tempus DDB Architecture & Product Blueprints

*Comprehensive implementation and architecture blueprints for deploying Bot-to-Agent (B2A) cryptographic toll gates across modern AI agent runtimes and frameworks.*

---

## 🎯 Purpose of These Blueprints

Autonomous AI agents are increasingly entrusted with high-blast-radius external side effects: opening Pull Requests, deploying code, notifying communication channels, updating databases, and moving financial assets.

**Traditional RBAC and API proxies fail against modern agent risks** (such as prompt injection, reasoning errors, hallucinated amounts, and non-deterministic loops) because they keep credentials and decision-making in the same trust domain.

These blueprints provide actionable, battle-tested product and architecture patterns to decouple **Decision** from **Execution** via Tempus DDB's cryptographic toll gate across the industry's leading agent providers and runtimes.

---

## 🗺️ Available Blueprints

| Blueprint | Category | Key Ecosystems & Runtimes | Primary Side Effects |
|---|---|---|---|
| [**DevOps Gate over MCP**](devops-mcp/product-blueprint.md) | DevOps & Infrastructure | **OpenClaw**, **Hermes Agent**, **Cursor**, **Claude Desktop**, **Windsurf**, **OpenHands**, **Aider** | GitHub PRs/Issues, Slack alerts, CI/CD triggers |
| [**Financial Gate for Multi-Agent Crews**](payments-crewai/product-blueprint.md) | Fintech & Payments | **CrewAI**, **LangGraph**, **Microsoft AutoGen**, **LlamaIndex Workflows** | Stripe payments, vendor disbursement, treasury transfers |

---

## 🌐 Supported Agent Runtimes & Providers

Tempus DDB's cryptographic boundary is runtime-agnostic. The patterns in these blueprints are directly applicable across:

### 1. Autonomous Agent Runtimes & MCP Hosts
* **OpenClaw**: Autonomous claw agent runtime with mediated tool execution.
* **Hermes Agent (Nous Research)**: Open-weights function-calling agents with structured tool invocation.
* **Cursor & Windsurf (Codeium)**: AI developer environments running background terminal and MCP actions.
* **Claude Desktop (Anthropic)**: Desktop MCP host with tool isolation boundaries.
* **OpenHands (formerly OpenDevin) & Aider**: Autonomous software engineering agents with git commit and PR privileges.

### 2. Multi-Agent Orchestration Frameworks
* **CrewAI**: Role-playing multi-agent teams dividing research, decision, and execution.
* **LangChain & LangGraph**: State-machine agent graphs with checkpointing and human-in-the-loop validation.
* **Microsoft AutoGen & Semantic Kernel**: Conversational multi-agent workflows.

### 3. Frontier & Open-Weight LLM Providers
* **Anthropic** (Claude 3.5 Sonnet / Haiku / Opus)
* **OpenAI** (GPT-4o, Operator, Function Calling)
* **Nous Research** (Hermes 2, Hermes 3, Function Calling models)
* **Mistral AI** (Codestral, Mistral Large)
* **Meta** (Llama 3.1, 3.2, 3.3 tool-calling lines)

---

## 🏛️ Core Architectural Invariants

Every blueprint in this directory strictly adheres to Tempus DDB's foundational invariants:

1. **Strict Credential Isolation**: The agent process never sees, stores, or handles downstream credentials (`GITHUB_TOKEN`, `SLACK_BOT_TOKEN`, `STRIPE_API_KEY`).
2. **Deterministic Signed Policy**: Evaluated by a dedicated Gate; never inferred by an LLM prompt.
3. **Single-Use Cryptographic Permits**: Permits are consumed atomically; replay attacks or retry loops fail closed.
4. **Dual-Signed Tamper-Evident Receipts**: Both the Gate and the isolated Executor sign the outcome with Ed25519; verified offline without trusting logs.
5. **Universal Failure Closing**: Network partitions, missing credentials, or signature mismatches abort execution safely before any external API is touched.
