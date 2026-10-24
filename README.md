# 🛡️ Microsoft Sentinel MCP Multi-Collection SOC Hub

A Security Operations Center (SOC) web application that connects to the **3 official Microsoft Sentinel Model Context Protocol (MCP)** tool collections to explore security data, triage incidents, and build Microsoft Security Copilot agents via natural language prompts.

![Microsoft Sentinel Multi-Collection](https://img.shields.io/badge/Sentinel-MCP%203--in--1-0078D4?style=flat-square&logo=microsoftazure)
![MCP Collections](https://img.shields.io/badge/Collections-Data%20Exploration%20|%20Agent%20Creation%20|%20Triage-8B5CF6?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20SOC%20Hub-10B981?style=flat-square)

---

## 🏛️ Supported Microsoft Sentinel MCP Collections

As documented in [Microsoft Sentinel MCP Tools Overview](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-tools-overview#available-collections), this project incorporates all 3 official scenario collections:

| Collection | Description | Server Endpoint URL | Key Tools Included |
|---|---|---|---|
| **[Data exploration](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-data-exploration-tool)** | Explore security data in Microsoft Sentinel data lake by searching for relevant tables, querying the lake, and analyzing entities | `https://sentinel.microsoft.com/mcp/data-exploration` | `search_tables`, `query_lake`, `list_sentinel_workspaces`, `analyze_user_entity`, `analyze_url_entity`, `get_data_graph` |
| **[Security Copilot agent creation](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-agent-creation-tool)** | Create Microsoft Security Copilot agents for complex workflows | `https://sentinel.microsoft.com/mcp/security-copilot-agent-creation` | `search_for_tools`, `create_security_copilot_agent`, `generate_agent_yaml`, `list_copilot_agents`, `deploy_copilot_agent` |
| **[Triage](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-triage-tool)** | Triage incidents rapidly and hunt over your own data easily | `https://sentinel.microsoft.com/mcp/triage` | `ListIncidents`, `GetIncidentById`, `ListAlerts`, `GetAlertByID`, `RunAdvancedHuntingQuery`, `GetDefenderMachine`, `GetDefenderFileInfo`, `GetDefenderIpAlerts`, `ListDefenderIndicators`, `analyze_incident`, `trigger_playbook` |

---

## ⚡ Core Capabilities

1. **Multi-Collection Prompt Assistant**:
   - Prompt in natural language across all 3 collections simultaneously or filter by collection.
   - Automatically determines whether your prompt is for incident triage, data lake table exploration, entity analysis, or Security Copilot agent synthesis.

2. **Data Exploration**:
   - **Semantic Table Discovery (`search_tables`)**: Search through Sentinel data lake schemas and tables (e.g. `SecurityAlert`, `DeviceProcessEvents`, `SigninLogs`, `DeviceNetworkEvents`, `AADRiskyUsers`, `AzureActivity`).
   - **Entity Analyzers (`analyze_user_entity`, `analyze_url_entity`)**: Evaluate users (risk score, anomalies, department context) and URLs (threat intel feeds, reverse proxy detection, SSL certificate age).
   - **Data Lake KQL Query Runner (`query_lake`)**: Run interactive KQL queries against the lake.

3. **Security Copilot Agent Creation (NL2Agent)**:
   - Provide a natural language description (e.g. *"Create an agent that generates a post-incident report from Defender, Purview, and Sentinel"*).
   - MCP tools search for required capabilities (`search_for_tools`), equip the agent with matching skills, and generate the deployable **YAML Agent Manifest**.

4. **Incident Triage & Threat Hunting**:
   - Full kill-chain reconstruction, MITRE ATT&CK matrix alignment, Defender machine and file intelligence lookups (`GetDefenderMachine`, `GetDefenderFileInfo`), and one-click SOAR playbooks (`trigger_playbook`).

5. **Real-Time MCP Wire Protocol Inspector**:
   - Live stream of JSON-RPC 2.0 messages sent and received by the Sentinel MCP Server.

---

## 🚀 Quick Start

### 1. Start the Application
```bash
npm start
```
Or run directly:
```bash
node server/web_server.js
```

### 2. Open the SOC Command Center
Navigate to **`http://localhost:3333`** in your browser.

---

## 💡 Example Prompts to Try

* **Triage**:
  > *"Analyze incident INC-8042: root cause, affected entities, and containment steps"*
  > *"Get Defender machine telemetry for SRV-FIN-SQL01 and check network isolation"*
* **Data Exploration**:
  > *"Search Sentinel data lake tables for authentication, process creation, and network events"*
  > *"Analyze user entity sarah.jenkins@contoso.com and show risk score and anomalies"*
* **Agent Creation**:
  > *"Create an agent that generates a comprehensive post-incident report from Defender, Purview, and Sentinel"*
  > *"Build a Security Copilot agent that monitors ransomware alerts and auto-isolates infected machines"*

---

## 🔌 Using with Claude Desktop / Antigravity / Cursor

Add the Sentinel MCP Server to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "microsoft-sentinel-hub": {
      "command": "node",
      "args": [
        "/Users/deepak/Documents/Sentinel-MCP-UI/mcp/sentinel_mcp_server.js"
      ]
    }
  }
}
```
