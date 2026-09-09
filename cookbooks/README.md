# 📚 Tempus DDB Cookbooks & Integration Recipes

Practical, copy-paste recipes for integrating Tempus DDB B2A security gates into popular AI agent frameworks and LLM environments.

---

## 🍳 Available Recipes

| Recipe | Framework / Environment | Description |
|---|---|---|
| [**OpenClaw, Hermes, Claude & Cursor MCP Guide**](mcp_cursor_claude_quickstart.md) | **OpenClaw**, **Hermes Agent**, **Claude Desktop**, **Cursor**, **Windsurf**, **OpenHands** | Connect Tempus DDB as an autonomous Model Context Protocol (MCP) server in 2 minutes. |
| [**CrewAI Financial Gate**](crewai_action_gate.py) | **CrewAI** / Multi-Agent Teams | Multi-agent delegation where executor agents only disburse funds when presented with a single-use permit. |
| [**LangChain & LangGraph Guard**](langchain_agent_guard.py) | **LangChain** / **LangGraph** | Enforce zero-trust tool execution gates around sensitive actions (database writes, payouts, API calls). |

---

## 📐 Enterprise Architecture & Product Blueprints

Looking to design production B2A toll gates for your organization or client teams? Explore the official blueprints:
* 🛠️ [**DevOps Gate over MCP Blueprint**](../docs/blueprints/devops-mcp/product-blueprint.md) — Threat model, sequence diagrams, and contracts for OpenClaw, Hermes, and developer agents.
* 💳 [**Financial Gate for Multi-Agent Crews Blueprint**](../docs/blueprints/payments-crewai/product-blueprint.md) — Financial toll gates, universal money contracts, and Stripe isolation for CrewAI and LangGraph.
* 🌐 [**Complete Blueprints Directory**](../docs/blueprints/README.md) (Available in English and [Español](../docs/blueprints/es/))

---

## ⚡ Quick Start

```bash
# 1. Install Tempus DDB
pip install tempus-ddb

# 2. Run the LangChain guard recipe
python cookbooks/langchain_agent_guard.py

# 3. Run the CrewAI financial gate recipe
python cookbooks/crewai_action_gate.py
```
