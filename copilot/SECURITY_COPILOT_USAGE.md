# 🤖 Using Microsoft Sentinel MCP Hub like Security Copilot

Yes! You can use this application **directly as an autonomous Security Copilot**, or plug it into the official **Microsoft Security Copilot** portal.

---

## ⚡ 1. Using this Web Application as your Security Copilot

You don't need any additional software or expensive Copilot licenses to experience Security Copilot. This GUI gives you the **same core workflows**:

| Security Copilot Capability | How It Works in this App | Example Prompt to Try in the UI |
|---|---|---|
| **Incident Summarization** | Aggregates all alerts, extracts blast radius, and drafts an executive summary | *"Summarize incident INC-8042 and explain what happened"* |
| **Root Cause & Kill-Chain** | Reconstructs the chronological attack path mapped to MITRE ATT&CK | *"What was the root cause and initial access vector for INC-8042?"* |
| **Entity Forensics** | Automatically looks up compromised users, hosts, IPs, and hashes | *"Show all compromised entities and their risk scores"* |
| **Endpoint Telemetry** | Queries Defender for Endpoint machine health and isolation status | *"Get Defender machine telemetry for SRV-FIN-SQL01"* |
| **KQL Query Generation** | Writes and executes KQL against Log Analytics without manual syntax | *"Run a KQL query on DeviceProcessEvents looking for vssadmin"* |
| **One-Click Remediation** | Triggers automated SOAR playbooks (Isolate Host, Revoke Sessions) | *"Execute containment playbook PB-ISOLATE-HOST on SRV-FIN-SQL01"* |
| **Executive Post-Incident Reporting** | Generates exportable Markdown reports for leadership | *"Export full incident response audit report"* |
| **NL2Agent (Custom Agents)** | Generates Security Copilot YAML agent specifications | *"Create an agent that monitors ransomware and isolates machines"* |

---

## 🎯 2. Try these Prompts in your GUI right now

Open **`http://localhost:3333`** and try these real-world Copilot prompts:

### Incident Triage & Analysis:
> *"Analyze incident INC-8042: What was the initial access, what machines did the attacker pivot to, and how do we contain it?"*

### Identity Threat Investigation:
> *"Investigate user sarah.jenkins@contoso.com: Check for anomalous sign-ins, token replay, and active mailbox rules."*

### Threat Hunting:
> *"Search data lake tables for process executions and query for encoded powershell commands."*

### Agent Creation:
> *"Create a Security Copilot agent named 'Ransomware-Defender' that detects shadow copy deletion and auto-quarantines the machine."*

---

## 🔌 3. Importing into the Official Microsoft Security Copilot Portal

If your organization has access to the official **Microsoft Security Copilot portal** (`securitycopilot.microsoft.com`):

1. Go to **Security Copilot** > click the **Sources / Plugins icon** (bottom right of prompt bar).
2. Select **Custom Plugins** > **Add Plugin**.
3. Choose **Upload a plugin manifest file**.
4. Select the provided manifest file:
   [`copilot/manifest.yaml`](./manifest.yaml)
5. Under settings, point the endpoint to your running MCP server or Azure deployment.
6. Now you can type prompts directly in the official Microsoft Security Copilot chat, and it will invoke this Sentinel MCP server!
