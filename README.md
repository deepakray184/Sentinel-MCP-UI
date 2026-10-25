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

## 🔗 How It Connects to Your Sentinel & Microsoft Defender XDR

This application supports two operating modes:
1. **Emulated High-Fidelity Mode (Default)**: Pre-loaded with 5 multi-stage enterprise attack scenarios for instant zero-setup demonstration.
2. **Live Azure Sentinel & Microsoft Defender XDR Mode**: Connects directly to your live production Azure environment and Defender portal.

```
┌────────────────────────────────────────────────────────┐
│             Web Browser (SOC GUI Dashboard)            │
│                 http://localhost:3333                  │
└───────────────────────────┬────────────────────────────┘
                            │ REST / WebSocket
                            ▼
┌────────────────────────────────────────────────────────┐
│            Node.js Backend & Prompt Agent              │
│               server/web_server.js                     │
│               server/prompt_orchestrator.js            │
└───────────────────────────┬────────────────────────────┘
                            │ Model Context Protocol (JSON-RPC 2.0 stdio)
                            ▼
┌────────────────────────────────────────────────────────┐
│            Sentinel MCP Server (v2.0.0)                │
│               mcp/sentinel_mcp_server.js               │
└───────────────────────────┬────────────────────────────┘
                            │ OAuth 2.0 Client Credentials
                            ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                   Microsoft Cloud APIs & Endpoints                       │
│                                                                          │
│  • Azure Resource Manager (ARM):                                         │
│    management.azure.com/.../providers/Microsoft.SecurityInsights        │
│    (Incident lifecycle, entity graphs, automated playbooks)              │
│                                                                          │
│  • Log Analytics Data Lake KQL Engine:                                   │
│    api.loganalytics.io/v1/workspaces/{workspaceId}/query                 │
│    (Raw security logs, DeviceProcessEvents, SigninLogs)                  │
│                                                                          │
│  • Microsoft Defender XDR (Microsoft Graph Security):                   │
│    graph.microsoft.com/v1.0/security/alerts_v2                           │
│    (Machine health, host isolation, threat intelligence IoCs)            │
└──────────────────────────────────────────────────────────────────────────┘
```

---

### 📋 Step-by-Step Setup Guide: Connecting Your Azure Sentinel & Defender XDR

Follow these 4 steps to connect this project to your live Microsoft Sentinel workspace:

#### Step 1: Register an Application in Microsoft Entra ID (Azure AD)
1. Sign in to the [Azure Portal](https://portal.azure.com/).
2. Navigate to **Microsoft Entra ID** > **App registrations** > **New registration**.
3. Set the name (e.g. `Sentinel-MCP-Connector`).
4. Set Supported account types to **Accounts in this organizational directory only (Single tenant)**.
5. Click **Register**.
6. Copy and save:
   * **Application (client) ID** (e.g. `11111111-2222-3333-4444-555555555555`)
   * **Directory (tenant) ID** (e.g. `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`)

#### Step 2: Create a Client Secret
1. Inside your new App Registration, go to **Certificates & secrets** > **Client secrets** > **New client secret**.
2. Enter a description (e.g. `Sentinel MCP Key`) and set an expiration period.
3. Click **Add**.
4. **Important:** Copy the **Value** column immediately (this secret will not be displayed again).

#### Step 3: Assign Sentinel & Log Analytics RBAC Roles
1. In the Azure Portal, go to your **Log Analytics Workspace** where Microsoft Sentinel is enabled.
2. Select **Access Control (IAM)** > **Add role assignment**.
3. Select one of the following roles:
   * **Microsoft Sentinel Responder** *(Recommended)*: Allows the MCP server to read incidents, fetch entities, and execute containment playbooks.
   * **Microsoft Sentinel Reader**: Provides read-only access to incidents and telemetry.
4. Under **Assign access to**, choose **User, group, or service principal**.
5. Select your registered application (`Sentinel-MCP-Connector`) and click **Review + assign**.

#### Step 4: Grant Defender XDR Permissions (for Machines & Advanced Hunting)
1. In your App Registration, navigate to **API permissions** > **Add a permission** > **Microsoft Graph**.
2. Choose **Application permissions** and add the following scopes:
   * `SecurityIncident.ReadWrite.All` or `SecurityIncident.Read.All`
   * `SecurityAlert.Read.All`
   * `ThreatHunting.Read.All` (for Defender Advanced Hunting queries)
   * `Machine.Read.All` (for Defender machine telemetry and isolation status)
   * `Machine.Isolate` (for one-click endpoint isolation)
3. Click **Add permissions**, then select **Grant admin consent for [Your Organization]**.

---

### ⚙️ Providing Credentials to the Application

You can connect using either method below:

#### Method 1: Using the Web GUI (No Restart Required)
1. Start the server (`npm start`) and navigate to **`http://localhost:3333`**.
2. Click the **"Workspace"** button in the top-right navigation bar.
3. Switch **Operation Mode** to **`Azure Sentinel Live REST`**.
4. Enter your:
   * **Sentinel Workspace Name** (e.g. `law-sentinel-cyber-ops`)
   * **Resource Group** (e.g. `rg-sentinel-prod`)
   * **Subscription ID** (e.g. `00000000-0000-0000-0000-000000000000`)
   * **Tenant ID**
   * **Client ID** and **Client Secret**
5. Click **Save & Reconnect**. The GUI will immediately authenticate and query your live Sentinel workspace!

#### Method 2: Using an Environment File (`.env`)
1. Copy the provided sample template:
   ```bash
   cp .env.example .env
   ```
2. Edit `.env` with your actual Azure credentials:
   ```env
   AZURE_TENANT_ID="your-tenant-id-guid"
   AZURE_CLIENT_ID="your-client-id-guid"
   AZURE_CLIENT_SECRET="your-client-secret-value"
   AZURE_SUBSCRIPTION_ID="your-subscription-id-guid"
   AZURE_RESOURCE_GROUP="your-resource-group-name"
   AZURE_WORKSPACE_NAME="your-log-analytics-workspace-name"
   ```
3. Restart the web server:
   ```bash
   npm start
   ```

---

### 🌐 Connecting to Official Hosted Microsoft MCP Endpoints

Microsoft also hosts remote MCP endpoints for organizations onboarded to the unified Microsoft Defender portal:
* **Triage**: `https://sentinel.microsoft.com/mcp/triage`
* **Data exploration**: `https://sentinel.microsoft.com/mcp/data-exploration`
* **Security Copilot agent creation**: `https://sentinel.microsoft.com/mcp/security-copilot-agent-creation`

When using an MCP-compatible client like **Visual Studio Code**, **Cursor**, or **GitHub Copilot Agent Mode**, you can add the hosted endpoint with your Microsoft Entra credentials:
```json
{
  "mcpServers": {
    "microsoft-sentinel-triage": {
      "url": "https://sentinel.microsoft.com/mcp/triage"
    },
    "microsoft-sentinel-data-exploration": {
      "url": "https://sentinel.microsoft.com/mcp/data-exploration"
    },
    "microsoft-security-copilot": {
      "url": "https://sentinel.microsoft.com/mcp/security-copilot-agent-creation"
    }
  }
}
```

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

## 🔌 Using Local Server with Claude Desktop / Antigravity / Cursor

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
