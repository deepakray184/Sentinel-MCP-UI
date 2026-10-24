# 🛡️ Microsoft Sentinel MCP Incident Analysis & SOC GUI

A Security Operations Center (SOC) web application that connects to a **Microsoft Sentinel Model Context Protocol (MCP)** server to perform deep incident analysis, threat hunting, and automated containment response via natural language prompts.

![Microsoft Sentinel MCP](https://img.shields.io/badge/Sentinel-MCP%202024--11--05-0078D4?style=flat-square&logo=microsoftazure)
![Node.js](https://img.shields.io/badge/Runtime-Node.js%2020%2B-339933?style=flat-square&logo=node.js)
![Status](https://img.shields.io/badge/Status-Active%20SOC%20Hub-10B981?style=flat-square)

---

## ⚡ Core Features

- **Model Context Protocol (MCP 2024-11-05)**: Full JSON-RPC 2.0 stdio server providing standard tools, resources, and prompt templates for Microsoft Sentinel.
- **Natural Language Incident Prompt Assistant**: Prompt the Sentinel MCP Agent in plain English (e.g. *"Analyze incident INC-8042: What was the root cause and how do we contain it?"*, *"Investigate compromised user sarah.jenkins"*, *"Run KQL query looking for powershell executions"*).
- **Automated SOC Triage & Root Cause Analysis**: Correlates alerts, extracts affected entities (Accounts, Hosts, Malicious IPs, Hashes), calculates blast radius and risk scores, and reconstructs the full kill-chain attack progression.
- **MITRE ATT&CK Matrix Alignment**: Visualizes tactics (Initial Access, Execution, Persistence, Defense Evasion, Lateral Movement, Impact) and techniques.
- **Live MCP Wire Protocol Inspector**: Real-time terminal displaying every raw JSON-RPC message exchanged between the web client and the Sentinel MCP server (`tools/list`, `tools/call`, `initialize`).
- **Interactive KQL Query Runner**: Execute custom Kusto Query Language queries via the MCP `run_kql_query` tool against Sentinel Log Analytics tables (`SecurityAlert`, `DeviceProcessEvents`, `SigninLogs`, `DeviceNetworkEvents`).
- **One-Click SOAR Playbook Execution**: Trigger containment actions directly from the GUI via `trigger_playbook` (e.g., *Isolate Host*, *Revoke Entra ID Sessions*, *Block Malicious IP at Azure Firewall*).
- **Dual Mode Support**:
  - **Emulated High-Fidelity Mode**: Pre-loaded with 5 multi-stage enterprise attack scenarios (Ransomware, Impossible Travel, CI/CD Supply Chain, Data Exfiltration, Kerberoasting) requiring zero cloud setup.
  - **Live Azure Sentinel Mode**: Plug in your Azure Tenant ID, Client ID, Client Secret, and Log Analytics Workspace to interact with real production Sentinel workspaces via Azure Resource Manager REST API.
- **One-Click Report Export**: Download comprehensive incident investigation reports in Markdown (`.md`) format.

---

## 🚀 Quick Start

### 1. Launch the SOC Web Application
```bash
npm start
```
Or run directly:
```bash
node server/web_server.js
```

### 2. Open the GUI Dashboard
Navigate to **`http://localhost:3333`** in your browser.

---

## 🛠️ Sentinel MCP Server Tools

The Sentinel MCP server (`mcp/sentinel_mcp_server.js`) exposes the following tools:

| MCP Tool Name | Description | Key Parameters |
|---|---|---|
| `list_incidents` | Lists active security incidents from Sentinel | `severity`, `status`, `limit` |
| `get_incident_details` | Retrieves full metadata and description for an incident | `incidentId` |
| `get_incident_entities` | Extracts correlated accounts, hosts, IPs, and hashes | `incidentId` |
| `get_incident_alerts` | Retrieves alerts grouped under the incident | `incidentId` |
| `analyze_incident` | Performs automated SOC triage, blast radius & risk score analysis | `incidentId`, `focusArea` |
| `run_kql_query` | Executes KQL queries against Log Analytics workspace | `query`, `timespan` |
| `trigger_playbook` | Triggers automated containment playbooks (SOAR) | `playbookId`, `targetEntity` |
| `update_incident_status` | Updates incident status, severity, and comments | `incidentId`, `status`, `comment` |
| `get_mitre_mapping` | Returns MITRE ATT&CK matrix mapping for incidents | `incidentId` |

---

## 🔌 Connecting to Claude Desktop / Antigravity / Cursor

To use this Sentinel MCP Server with **Claude Desktop**, add it to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "microsoft-sentinel": {
      "command": "node",
      "args": [
        "/Users/deepak/Documents/Sentinel-MCP-UI/mcp/sentinel_mcp_server.js"
      ]
    }
  }
}
```

---

## 📂 Project Architecture

```
Sentinel-MCP-UI/
├── package.json                    # Project configuration and launch scripts
├── mcp/
│   ├── sentinel_mcp_server.js      # Stdio MCP Server (JSON-RPC 2.0 protocol)
│   ├── mock_sentinel_data.js       # Pre-loaded multi-stage threat scenarios
│   └── azure_sentinel_client.js    # Live Azure REST API integration client
├── server/
│   ├── mcp_client.js               # MCP Client managing stdio child process
│   ├── prompt_orchestrator.js      # AI SOC Agent translating prompts into MCP tools
│   └── web_server.js               # HTTP API server & static asset host (Port 3333)
├── public/
│   ├── index.html                  # Cyber SOC command center layout
│   ├── styles.css                  # Futuristic dark cyber SOC styling
│   └── app.js                      # Frontend reactive controller & wire inspector
└── README.md                       # Documentation & usage guide
```

---

## 🛡️ Example Prompts to Try in the GUI

1. **Deep Triage**:
   > *"Analyze incident INC-8042: What was the root cause, what endpoints are affected, and what containment steps are needed?"*

2. **Entity Investigation**:
   > *"Investigate compromised user sarah.jenkins@contoso.com and check for impossible travel or token replay."*

3. **Threat Hunting**:
   > *"Run a KQL query on DeviceProcessEvents looking for vssadmin and powershell execution."*

4. **Containment**:
   > *"Execute containment playbook PB-ISOLATE-HOST on SRV-FIN-SQL01."*

5. **Threat Matrix**:
   > *"Show all MITRE ATT&CK tactics involved across the current incidents."*
