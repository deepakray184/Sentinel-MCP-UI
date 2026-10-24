#!/usr/bin/env node
// Microsoft Sentinel Model Context Protocol (MCP) Server
// Implements MCP 2024-11-05 JSON-RPC protocol over Stdio
// Supporting the 3 Official Microsoft Sentinel MCP Collections:
// 1. Data exploration (https://sentinel.microsoft.com/mcp/data-exploration)
// 2. Security Copilot agent creation (https://sentinel.microsoft.com/mcp/security-copilot-agent-creation)
// 3. Triage (https://sentinel.microsoft.com/mcp/triage)

const readline = require('readline');
const {
  mockWorkspaces,
  mockDataLakeTables,
  mockIncidents,
  mockDefenderMachines,
  mockDefenderFiles,
  mockDefenderIndicators,
  mockEntityAnalysis,
  mockCopilotToolsCatalog,
  mockCopilotAgents
} = require('./mock_sentinel_data');
const AzureSentinelClient = require('./azure_sentinel_client');

class SentinelMCPServer {
  constructor() {
    this.name = 'microsoft-sentinel-mcp-server';
    this.version = '2.0.0';
    this.workspaces = JSON.parse(JSON.stringify(mockWorkspaces));
    this.tables = JSON.parse(JSON.stringify(mockDataLakeTables));
    this.incidents = JSON.parse(JSON.stringify(mockIncidents));
    this.copilotAgents = JSON.parse(JSON.stringify(mockCopilotAgents));
    this.azureClient = new AzureSentinelClient();
    this.isLiveMode = false;
  }

  setAzureConfig(config) {
    this.azureClient = new AzureSentinelClient(config);
    this.isLiveMode = this.azureClient.isConfigured();
    return { isLiveMode: this.isLiveMode };
  }

  getCollections() {
    return [
      {
        id: 'data-exploration',
        name: 'Data exploration',
        description: 'Explore security data in Microsoft Sentinel data lake by searching for relevant tables, querying the lake, and analyzing entities',
        serverUrl: 'https://sentinel.microsoft.com/mcp/data-exploration',
        toolsCount: 6
      },
      {
        id: 'security-copilot-agent-creation',
        name: 'Security Copilot agent creation',
        description: 'Create Microsoft Security Copilot agents for complex workflows',
        serverUrl: 'https://sentinel.microsoft.com/mcp/security-copilot-agent-creation',
        toolsCount: 5
      },
      {
        id: 'triage',
        name: 'Triage',
        description: 'Triage incidents rapidly and hunt over your own data easily',
        serverUrl: 'https://sentinel.microsoft.com/mcp/triage',
        toolsCount: 11
      }
    ];
  }

  getToolDefinitions(filterCollection = null) {
    const allTools = [
      // ==========================================
      // COLLECTION 1: Data exploration
      // Server URL: https://sentinel.microsoft.com/mcp/data-exploration
      // ==========================================
      {
        name: 'search_tables',
        collection: 'data-exploration',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/data-exploration',
        description: '[Data Exploration] Semantic search on Microsoft Sentinel data lake table catalogs and schemas. Finds relevant tables matching keywords or security queries.',
        inputSchema: {
          type: 'object',
          properties: {
            keyword: {
              type: 'string',
              description: 'Search keyword (e.g. "authentication", "process", "network", "cloud audit", "powershell")'
            }
          },
          required: ['keyword']
        }
      },
      {
        name: 'query_lake',
        collection: 'data-exploration',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/data-exploration',
        description: '[Data Exploration] Execute Kusto Query Language (KQL) queries directly against a Microsoft Sentinel data lake workspace.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Valid KQL query string (e.g. "SecurityAlert | where Severity == \'High\' | take 10")'
            },
            workspaceId: {
              type: 'string',
              description: 'Target data lake workspace ID (default: law-sentinel-cyber-ops)'
            },
            timespan: {
              type: 'string',
              description: 'Query timeframe filter (e.g. P1D, P7D)'
            }
          },
          required: ['query']
        }
      },
      {
        name: 'list_sentinel_workspaces',
        collection: 'data-exploration',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/data-exploration',
        description: '[Data Exploration] List and retrieve all available Microsoft Sentinel data lake workspaces, subscriptions, and capacity details.',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      },
      {
        name: 'analyze_user_entity',
        collection: 'data-exploration',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/data-exploration',
        description: '[Data Exploration] Perform AI-driven entity evaluation on a user account, providing risk score, behavioral anomalies, and organizational context.',
        inputSchema: {
          type: 'object',
          properties: {
            userPrincipalName: {
              type: 'string',
              description: 'The user account UPN (e.g. sarah.jenkins@contoso.com, finance-admin@contoso.com)'
            }
          },
          required: ['userPrincipalName']
        }
      },
      {
        name: 'analyze_url_entity',
        collection: 'data-exploration',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/data-exploration',
        description: '[Data Exploration] Evaluate URL entities with threat intelligence verdicts, domain registration age, SSL analysis, and category classifications.',
        inputSchema: {
          type: 'object',
          properties: {
            url: {
              type: 'string',
              description: 'The URL or web address to analyze'
            }
          },
          required: ['url']
        }
      },
      {
        name: 'get_data_graph',
        collection: 'data-exploration',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/data-exploration',
        description: '[Data Exploration] Reason over exposure, hunting, and entity relationship graphs in Microsoft Sentinel data lake.',
        inputSchema: {
          type: 'object',
          properties: {
            entityOrIncidentId: {
              type: 'string',
              description: 'Target Entity (Account, Host, IP) or Incident ID'
            }
          },
          required: ['entityOrIncidentId']
        }
      },

      // ==========================================
      // COLLECTION 2: Security Copilot agent creation
      // Server URL: https://sentinel.microsoft.com/mcp/security-copilot-agent-creation
      // ==========================================
      {
        name: 'search_for_tools',
        collection: 'security-copilot-agent-creation',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/security-copilot-agent-creation',
        description: '[Agent Creation] Search for available Security Copilot tools, skills, plugins, and capabilities that can be used when building custom security agents.',
        inputSchema: {
          type: 'object',
          properties: {
            capabilityNeed: {
              type: 'string',
              description: 'Describe the action or data needed (e.g. "isolate machine", "query logs", "revoke user session", "post-incident report")'
            }
          },
          required: ['capabilityNeed']
        }
      },
      {
        name: 'create_security_copilot_agent',
        collection: 'security-copilot-agent-creation',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/security-copilot-agent-creation',
        description: '[Agent Creation] Create a Microsoft Security Copilot agent from natural language description (NL2Agent) for complex automated workflows.',
        inputSchema: {
          type: 'object',
          properties: {
            agentName: {
              type: 'string',
              description: 'Descriptive identifier for the agent (e.g. Ransomware-Rapid-Responder)'
            },
            workflowPrompt: {
              type: 'string',
              description: 'Natural language workflow description (e.g. "Create an agent that generates a post-incident report from Defender, Purview, and Sentinel")'
            },
            skills: {
              type: 'array',
              items: { type: 'string' },
              description: 'List of tool/skill IDs to equip the agent with'
            }
          },
          required: ['agentName', 'workflowPrompt']
        }
      },
      {
        name: 'generate_agent_yaml',
        collection: 'security-copilot-agent-creation',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/security-copilot-agent-creation',
        description: '[Agent Creation] Synthesizes a valid, deployable YAML manifest specification for a Microsoft Security Copilot agent.',
        inputSchema: {
          type: 'object',
          properties: {
            agentId: {
              type: 'string',
              description: 'Existing agent ID or configuration payload'
            }
          },
          required: ['agentId']
        }
      },
      {
        name: 'list_copilot_agents',
        collection: 'security-copilot-agent-creation',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/security-copilot-agent-creation',
        description: '[Agent Creation] List all configured Microsoft Security Copilot agents in the workspace.',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      },
      {
        name: 'deploy_copilot_agent',
        collection: 'security-copilot-agent-creation',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/security-copilot-agent-creation',
        description: '[Agent Creation] Register and deploy a Security Copilot agent into the tenant runtime.',
        inputSchema: {
          type: 'object',
          properties: {
            agentId: {
              type: 'string',
              description: 'The agent ID to publish'
            }
          },
          required: ['agentId']
        }
      },

      // ==========================================
      // COLLECTION 3: Triage
      // Server URL: https://sentinel.microsoft.com/mcp/triage
      // ==========================================
      {
        name: 'ListIncidents',
        collection: 'triage',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/triage',
        description: '[Triage] List Microsoft Sentinel security incidents with filters for severity, status, and timeframe.',
        inputSchema: {
          type: 'object',
          properties: {
            severity: {
              type: 'string',
              description: 'Filter by severity: High, Medium, Low, Informational, All'
            },
            status: {
              type: 'string',
              description: 'Filter by status: Active, New, Closed, All'
            },
            limit: {
              type: 'number',
              description: 'Max incidents to return'
            }
          }
        }
      },
      {
        name: 'GetIncidentById',
        collection: 'triage',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/triage',
        description: '[Triage] Retrieve comprehensive details, alerts, and timeline for a specific incident.',
        inputSchema: {
          type: 'object',
          properties: {
            incidentId: {
              type: 'string',
              description: 'Incident identifier (e.g. INC-8042)'
            }
          },
          required: ['incidentId']
        }
      },
      {
        name: 'ListAlerts',
        collection: 'triage',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/triage',
        description: '[Triage] List correlated security alerts aggregated under an incident or workspace.',
        inputSchema: {
          type: 'object',
          properties: {
            incidentId: {
              type: 'string',
              description: 'Optional incident ID filter'
            }
          }
        }
      },
      {
        name: 'GetAlertByID',
        collection: 'triage',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/triage',
        description: '[Triage] Fetch detailed forensic context and provider detection evidence for a specific alert.',
        inputSchema: {
          type: 'object',
          properties: {
            alertId: {
              type: 'string',
              description: 'Alert ID (e.g. ALT-99101)'
            }
          },
          required: ['alertId']
        }
      },
      {
        name: 'RunAdvancedHuntingQuery',
        collection: 'triage',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/triage',
        description: '[Triage] Execute an advanced hunting KQL query across integrated Defender XDR and Sentinel data lake tables.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'KQL hunting query'
            }
          },
          required: ['query']
        }
      },
      {
        name: 'GetDefenderMachine',
        collection: 'triage',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/triage',
        description: '[Triage] Retrieve machine endpoint telemetry: OS, IP, isolation status, risk level, and active alerts.',
        inputSchema: {
          type: 'object',
          properties: {
            machineNameOrId: {
              type: 'string',
              description: 'Machine NetBIOS name or Defender ID (e.g. SRV-FIN-SQL01, WKS-FIN-882)'
            }
          },
          required: ['machineNameOrId']
        }
      },
      {
        name: 'GetDefenderFileInfo',
        collection: 'triage',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/triage',
        description: '[Triage] Look up file reputation, SHA256 hashes, global prevalence, and determination.',
        inputSchema: {
          type: 'object',
          properties: {
            fileHash: {
              type: 'string',
              description: 'File SHA256 or MD5 hash'
            }
          },
          required: ['fileHash']
        }
      },
      {
        name: 'GetDefenderIpAlerts',
        collection: 'triage',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/triage',
        description: '[Triage] Fetch threat intelligence and correlated alerts for an external or internal IP address.',
        inputSchema: {
          type: 'object',
          properties: {
            ipAddress: {
              type: 'string',
              description: 'Target IP (e.g. 185.220.101.5)'
            }
          },
          required: ['ipAddress']
        }
      },
      {
        name: 'ListDefenderIndicators',
        collection: 'triage',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/triage',
        description: '[Triage] List custom indicators of compromise (IoCs) configured in Microsoft Defender.',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      },
      {
        name: 'analyze_incident',
        collection: 'triage',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/triage',
        description: '[Triage] Perform automated SOC triage, blast radius evaluation, MITRE ATT&CK kill-chain mapping, and triage recommendations.',
        inputSchema: {
          type: 'object',
          properties: {
            incidentId: {
              type: 'string',
              description: 'Incident ID to analyze'
            }
          },
          required: ['incidentId']
        }
      },
      {
        name: 'trigger_playbook',
        collection: 'triage',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/triage',
        description: '[Triage] Execute automated SOAR containment playbooks (isolate machine, revoke tokens, block IP).',
        inputSchema: {
          type: 'object',
          properties: {
            playbookId: {
              type: 'string',
              description: 'Playbook ID (e.g. PB-ISOLATE-HOST, PB-REVOKE-SESSION, PB-BLOCK-C2-IP)'
            },
            targetEntity: {
              type: 'string',
              description: 'Target entity'
            },
            incidentId: {
              type: 'string',
              description: 'Associated Incident ID'
            }
          },
          required: ['playbookId', 'targetEntity']
        }
      },

      // Global Meta Tool
      {
        name: 'get_available_collections',
        collection: 'core',
        collectionUrl: 'https://sentinel.microsoft.com/mcp',
        description: 'Returns the 3 available Microsoft Sentinel MCP tool collections: Data exploration, Security Copilot agent creation, and Triage.',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      }
    ];

    if (filterCollection) {
      return allTools.filter(t => t.collection === filterCollection || t.collection === 'core');
    }
    return allTools;
  }

  findIncident(incidentId) {
    if (!incidentId) return null;
    const cleanId = String(incidentId).trim().toUpperCase();
    return this.incidents.find(inc => 
      inc.id.toUpperCase() === cleanId || 
      String(inc.incidentNumber) === cleanId ||
      inc.id.toUpperCase().includes(cleanId)
    );
  }

  async executeTool(name, args = {}) {
    // Normalization for aliases
    const toolName = name.trim();

    switch (toolName) {
      // ----------------------------------------------------
      // GLOBAL: Available Collections
      // ----------------------------------------------------
      case 'get_available_collections': {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              status: 'success',
              availableCollections: this.getCollections()
            }, null, 2)
          }]
        };
      }

      // ----------------------------------------------------
      // COLLECTION 1: Data exploration
      // ----------------------------------------------------
      case 'search_tables': {
        const rawKw = (args.keyword || '').toLowerCase();
        const words = rawKw.split(/\s+/).filter(w => w && !['for', 'and', 'the', 'in', 'tables', 'logs', 'search'].includes(w));
        const matches = this.tables.filter(t => {
          if (!words.length) return true;
          return words.some(w => 
            t.name.toLowerCase().includes(w) ||
            t.description.toLowerCase().includes(w) ||
            t.category.toLowerCase().includes(w) ||
            t.columns.some(c => c.name.toLowerCase().includes(w))
          );
        });

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              query: rawKw,
              matchedCount: matches.length,
              tables: matches
            }, null, 2)
          }]
        };
      }

      case 'query_lake':
      case 'run_kql_query': {
        const query = (args.query || '').trim();
        const workspaceId = args.workspaceId || 'law-sentinel-cyber-ops';

        if (this.isLiveMode) {
          try {
            const data = await this.azureClient.executeKql(query, args.timespan || 'P1D');
            return {
              content: [{ type: 'text', text: JSON.stringify(data, null, 2) }]
            };
          } catch (err) {
            return {
              isError: true,
              content: [{ type: 'text', text: `Azure Data Lake Query Error: ${err.message}` }]
            };
          }
        }

        // Mock Data Lake Query
        let matchedTable = 'SecurityAlert';
        if (/DeviceProcessEvents/i.test(query)) matchedTable = 'DeviceProcessEvents';
        else if (/SigninLogs/i.test(query)) matchedTable = 'SigninLogs';
        else if (/DeviceNetworkEvents/i.test(query)) matchedTable = 'DeviceNetworkEvents';
        else if (/AzureActivity/i.test(query)) matchedTable = 'AzureActivity';

        const { mockKqlDatabase } = require('./mock_sentinel_data');
        let rows = (mockKqlDatabase && mockKqlDatabase[matchedTable]) || [];

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              workspaceId,
              executedQuery: query,
              resolvedTable: matchedTable,
              rowCount: rows.length,
              results: rows
            }, null, 2)
          }]
        };
      }

      case 'list_sentinel_workspaces': {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              totalWorkspaces: this.workspaces.length,
              workspaces: this.workspaces
            }, null, 2)
          }]
        };
      }

      case 'analyze_user_entity': {
        const upn = (args.userPrincipalName || '').trim().toLowerCase();
        const analysis = mockEntityAnalysis.users[upn] || {
          userPrincipalName: upn,
          displayName: upn.split('@')[0],
          riskScore: 20,
          riskVerdict: 'Low Risk',
          summary: 'Standard baseline user activity. No anomalous authentications detected.',
          anomalies: [],
          associatedAlertsCount: 0,
          recommendedActions: ['Continue standard MFA monitoring']
        };

        return {
          content: [{
            type: 'text',
            text: JSON.stringify(analysis, null, 2)
          }]
        };
      }

      case 'analyze_url_entity': {
        const url = (args.url || '').trim();
        const analysis = mockEntityAnalysis.urls[url] || {
          url,
          domain: url.replace(/^https?:\/\//, '').split('/')[0],
          riskVerdict: 'Unclassified / Low Risk',
          confidenceScore: 40,
          categories: ['Web Site'],
          ipResolution: 'Dynamic CDN',
          recommendations: ['Monitor outbound proxy traffic']
        };

        return {
          content: [{
            type: 'text',
            text: JSON.stringify(analysis, null, 2)
          }]
        };
      }

      case 'get_data_graph': {
        const target = args.entityOrIncidentId;
        const inc = this.findIncident(target);
        const graph = {
          target,
          type: inc ? 'IncidentCorrelationGraph' : 'EntityRelationshipGraph',
          nodes: inc ? [
            { id: inc.id, type: 'Incident', label: inc.title, severity: inc.severity },
            ...inc.entities.map(e => ({ id: e.name, type: e.type, riskScore: e.properties.threatScore || e.properties.riskLevel }))
          ] : [
            { id: target, type: 'TargetEntity' },
            { id: '185.220.101.5', type: 'ExternalIP', relationship: 'CommunicatedWith' },
            { id: 'SRV-FIN-SQL01', type: 'Host', relationship: 'HostedOn' }
          ],
          edges: inc ? inc.entities.map(e => ({ source: inc.id, target: e.name, relation: 'CorrelatedEntity' })) : []
        };

        return {
          content: [{
            type: 'text',
            text: JSON.stringify(graph, null, 2)
          }]
        };
      }

      // ----------------------------------------------------
      // COLLECTION 2: Security Copilot agent creation
      // ----------------------------------------------------
      case 'search_for_tools': {
        const need = (args.capabilityNeed || '').toLowerCase();
        const matches = mockCopilotToolsCatalog.filter(t => 
          t.name.toLowerCase().includes(need) ||
          t.description.toLowerCase().includes(need) ||
          t.parameters.some(p => p.toLowerCase().includes(need))
        );

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              capabilityQuery: need,
              matchedToolsCount: matches.length > 0 ? matches.length : mockCopilotToolsCatalog.length,
              availableTools: matches.length > 0 ? matches : mockCopilotToolsCatalog
            }, null, 2)
          }]
        };
      }

      case 'create_security_copilot_agent': {
        const { agentName, workflowPrompt, skills = [] } = args;
        const agentId = `agent-${agentName.toLowerCase().replace(/[^a-z0-9]/g, '-')}-${Date.now().toString().slice(-4)}`;
        
        const equippedSkills = skills.length > 0 ? skills : [
          'sentinel_incident_triage',
          'defender_isolate_machine',
          'entra_revoke_user_sessions'
        ];

        const generatedYaml = `name: ${agentName}
version: 1.0.0
description: |
  ${workflowPrompt}
runtime: microsoft-security-copilot
skills:
${equippedSkills.map(s => `  - id: ${s}\n    enabled: true`).join('\n')}
triggers:
  - type: sentinel_incident_creation
    condition: severity in ['High', 'Critical']
autonomous_actions:
  requires_approval_for: ['defender_isolate_machine']
`;

        const newAgent = {
          id: agentId,
          name: agentName,
          description: workflowPrompt,
          status: 'Draft',
          version: '1.0.0',
          triggers: ['Sentinel Incident High/Critical'],
          capabilities: equippedSkills,
          yamlSpec: generatedYaml,
          createdDate: new Date().toISOString()
        };

        this.copilotAgents.push(newAgent);

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              status: 'AgentCreated',
              agent: newAgent
            }, null, 2)
          }]
        };
      }

      case 'generate_agent_yaml': {
        const agent = this.copilotAgents.find(a => a.id === args.agentId || a.name === args.agentId);
        if (!agent) {
          return {
            isError: true,
            content: [{ type: 'text', text: `Agent '${args.agentId}' not found.` }]
          };
        }

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              agentId: agent.id,
              agentName: agent.name,
              yaml: agent.yamlSpec
            }, null, 2)
          }]
        };
      }

      case 'list_copilot_agents': {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              totalAgents: this.copilotAgents.length,
              agents: this.copilotAgents
            }, null, 2)
          }]
        };
      }

      case 'deploy_copilot_agent': {
        const agent = this.copilotAgents.find(a => a.id === args.agentId);
        if (!agent) {
          return {
            isError: true,
            content: [{ type: 'text', text: `Agent '${args.agentId}' not found.` }]
          };
        }
        agent.status = 'Published';
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              status: 'Deployed',
              agentId: agent.id,
              endpoint: `https://securitycopilot.microsoft.com/agents/${agent.id}`,
              deployedAt: new Date().toISOString()
            }, null, 2)
          }]
        };
      }

      // ----------------------------------------------------
      // COLLECTION 3: Triage
      // ----------------------------------------------------
      case 'ListIncidents':
      case 'list_incidents': {
        const severity = args.severity || 'All';
        const status = args.status || 'All';
        const limit = args.limit || 10;

        let filtered = this.incidents;
        if (severity !== 'All') {
          filtered = filtered.filter(i => i.severity.toLowerCase() === severity.toLowerCase());
        }
        if (status !== 'All') {
          filtered = filtered.filter(i => i.status.toLowerCase() === status.toLowerCase());
        }

        const result = filtered.slice(0, limit).map(i => ({
          id: i.id,
          incidentNumber: i.incidentNumber,
          title: i.title,
          severity: i.severity,
          status: i.status,
          tactics: i.tactics,
          createdTimeUtc: i.createdTimeUtc,
          entitiesCount: i.entities ? i.entities.length : 0,
          alertsCount: i.alerts ? i.alerts.length : 0,
          riskScore: i.metrics?.riskScore || 80
        }));

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ count: result.length, incidents: result }, null, 2)
          }]
        };
      }

      case 'GetIncidentById':
      case 'get_incident_details': {
        const incident = this.findIncident(args.incidentId);
        if (!incident) {
          return {
            isError: true,
            content: [{ type: 'text', text: `Incident '${args.incidentId}' not found in Sentinel workspace.` }]
          };
        }
        return {
          content: [{ type: 'text', text: JSON.stringify(incident, null, 2) }]
        };
      }

      case 'ListAlerts':
      case 'get_incident_alerts': {
        const incident = this.findIncident(args.incidentId);
        if (incident) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                incidentId: incident.id,
                totalAlerts: incident.alerts.length,
                alerts: incident.alerts
              }, null, 2)
            }]
          };
        }

        const allAlerts = this.incidents.flatMap(i => i.alerts.map(a => ({ ...a, incidentId: i.id })));
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ totalAlerts: allAlerts.length, alerts: allAlerts }, null, 2)
          }]
        };
      }

      case 'GetAlertByID': {
        const targetId = String(args.alertId || '').toUpperCase();
        for (const inc of this.incidents) {
          const match = inc.alerts.find(a => a.alertId.toUpperCase() === targetId);
          if (match) {
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({ incidentId: inc.id, alert: match }, null, 2)
              }]
            };
          }
        }
        return {
          isError: true,
          content: [{ type: 'text', text: `Alert '${args.alertId}' not found.` }]
        };
      }

      case 'RunAdvancedHuntingQuery': {
        const query = args.query || 'DeviceProcessEvents | take 5';
        return this.executeTool('query_lake', { query });
      }

      case 'GetDefenderMachine': {
        const machineKey = Object.keys(mockDefenderMachines).find(k => 
          k.toLowerCase() === String(args.machineNameOrId).toLowerCase() ||
          mockDefenderMachines[k].id === args.machineNameOrId
        );

        if (!machineKey) {
          return {
            isError: true,
            content: [{ type: 'text', text: `Defender machine '${args.machineNameOrId}' not found.` }]
          };
        }

        return {
          content: [{
            type: 'text',
            text: JSON.stringify(mockDefenderMachines[machineKey], null, 2)
          }]
        };
      }

      case 'GetDefenderFileInfo': {
        const hash = String(args.fileHash || '').toLowerCase();
        const fileInfo = mockDefenderFiles[hash] || {
          sha256: hash,
          determination: 'Unknown / Not in Threat Feed',
          globalPrevalence: 1
        };

        return {
          content: [{
            type: 'text',
            text: JSON.stringify(fileInfo, null, 2)
          }]
        };
      }

      case 'GetDefenderIpAlerts': {
        const ip = args.ipAddress;
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              ipAddress: ip,
              threatVerdict: ip.startsWith('185.') || ip.startsWith('103.') || ip.startsWith('194.') ? 'Known C2 / Malicious Proxy' : 'Benign IP',
              associatedAlerts: [
                { alertName: 'C2 Beaconing Traffic', severity: 'High', timestamp: '2026-10-24T18:12:30Z' }
              ]
            }, null, 2)
          }]
        };
      }

      case 'ListDefenderIndicators': {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              totalIndicators: mockDefenderIndicators.length,
              indicators: mockDefenderIndicators
            }, null, 2)
          }]
        };
      }

      case 'analyze_incident': {
        const incident = this.findIncident(args.incidentId);
        if (!incident) {
          return {
            isError: true,
            content: [{ type: 'text', text: `Incident '${args.incidentId}' not found.` }]
          };
        }

        const analysis = {
          incidentId: incident.id,
          title: incident.title,
          severity: incident.severity,
          status: incident.status,
          riskScore: incident.metrics.riskScore,
          confidenceScore: incident.metrics.confidenceScore,
          blastRadius: incident.metrics.blastRadius,
          threatVector: incident.tactics.join(' -> '),
          executiveSummary: incident.summary,
          deepTechnicalAnalysis: incident.description,
          mitreMapping: {
            tactics: incident.tactics,
            techniques: incident.techniques
          },
          affectedEntities: incident.entities.map(e => ({
            type: e.type,
            name: e.name,
            riskScore: e.properties.threatScore || e.properties.riskLevel || 'Medium'
          })),
          attackProgression: incident.timeline,
          recommendedContainmentActions: incident.remediationPlaybooks.map(pb => ({
            id: pb.playbookId,
            action: pb.name,
            target: pb.target,
            currentStatus: pb.status,
            guidance: pb.description
          }))
        };

        return {
          content: [{
            type: 'text',
            text: JSON.stringify(analysis, null, 2)
          }]
        };
      }

      case 'get_incident_entities': {
        const incident = this.findIncident(args.incidentId);
        if (!incident) {
          return {
            isError: true,
            content: [{ type: 'text', text: `Incident '${args.incidentId}' not found.` }]
          };
        }
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              incidentId: incident.id,
              totalEntities: incident.entities.length,
              entities: incident.entities
            }, null, 2)
          }]
        };
      }

      case 'trigger_playbook': {
        const { playbookId, targetEntity, incidentId } = args;
        const incident = this.findIncident(incidentId);

        if (incident && incident.remediationPlaybooks) {
          const pb = incident.remediationPlaybooks.find(p => p.playbookId === playbookId || p.target === targetEntity);
          if (pb) pb.status = 'Executed';
        }

        // If isolating machine, update machine state
        if (playbookId === 'PB-ISOLATE-HOST' && mockDefenderMachines[targetEntity]) {
          mockDefenderMachines[targetEntity].isIsolated = true;
        }

        const executionRecord = {
          executionId: `EXEC-${Math.floor(100000 + Math.random() * 900000)}`,
          playbookId,
          targetEntity,
          incidentId: incidentId || 'Global',
          status: 'Success',
          timestamp: new Date().toISOString(),
          responseDetails: `Playbook ${playbookId} executed against ${targetEntity}. Automation rule completed successfully.`
        };

        return {
          content: [{
            type: 'text',
            text: JSON.stringify(executionRecord, null, 2)
          }]
        };
      }

      case 'get_mitre_mapping': {
        if (args.incidentId && args.incidentId !== 'all') {
          const inc = this.findIncident(args.incidentId);
          if (inc) {
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  incidentId: inc.id,
                  tactics: inc.tactics,
                  techniques: inc.techniques
                }, null, 2)
              }]
            };
          }
        }

        const matrix = {};
        this.incidents.forEach(inc => {
          inc.tactics.forEach((tactic, idx) => {
            if (!matrix[tactic]) matrix[tactic] = [];
            matrix[tactic].push({
              incidentId: inc.id,
              technique: inc.techniques[idx] || 'General'
            });
          });
        });

        return {
          content: [{
            type: 'text',
            text: JSON.stringify(matrix, null, 2)
          }]
        };
      }

      default:
        return {
          isError: true,
          content: [{ type: 'text', text: `Unknown tool: ${toolName}` }]
        };
    }
  }

  handleJsonRpc(message) {
    const { id, method, params } = message;

    switch (method) {
      case 'initialize':
        return {
          jsonrpc: '2.0',
          id,
          result: {
            protocolVersion: '2024-11-05',
            capabilities: {
              tools: {},
              resources: {},
              prompts: {}
            },
            serverInfo: {
              name: this.name,
              version: this.version
            },
            collections: this.getCollections()
          }
        };

      case 'initialized':
        return null;

      case 'ping':
        return { jsonrpc: '2.0', id, result: {} };

      case 'tools/list': {
        const collection = params?.collection;
        return {
          jsonrpc: '2.0',
          id,
          result: {
            tools: this.getToolDefinitions(collection)
          }
        };
      }

      case 'tools/call':
        return this.executeTool(params.name, params.arguments || {})
          .then(toolResult => ({
            jsonrpc: '2.0',
            id,
            result: toolResult
          }))
          .catch(err => ({
            jsonrpc: '2.0',
            id,
            error: {
              code: -32000,
              message: err.message
            }
          }));

      default:
        return {
          jsonrpc: '2.0',
          id,
          error: {
            code: -32601,
            message: `Method not found: ${method}`
          }
        };
    }
  }

  startStdio() {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false
    });

    rl.on('line', async (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      try {
        const request = JSON.parse(trimmed);
        const response = await this.handleJsonRpc(request);
        if (response) {
          process.stdout.write(JSON.stringify(response) + '\n');
        }
      } catch (err) {
        process.stdout.write(JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: `Parse error: ${err.message}` }
        }) + '\n');
      }
    });

    process.on('SIGTERM', () => process.exit(0));
    process.on('SIGINT', () => process.exit(0));
  }
}

if (require.main === module) {
  const server = new SentinelMCPServer();
  server.startStdio();
}

module.exports = SentinelMCPServer;
