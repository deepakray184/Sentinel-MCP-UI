#!/usr/bin/env node
// Microsoft Sentinel Model Context Protocol (MCP) Server
// Implements MCP 2024-11-05 JSON-RPC protocol over Stdio

const readline = require('readline');
const { mockIncidents, mockKqlDatabase } = require('./mock_sentinel_data');
const AzureSentinelClient = require('./azure_sentinel_client');

class SentinelMCPServer {
  constructor() {
    this.name = 'microsoft-sentinel-mcp-server';
    this.version = '1.2.0';
    this.incidents = JSON.parse(JSON.stringify(mockIncidents));
    this.azureClient = new AzureSentinelClient();
    this.isLiveMode = false;
  }

  setAzureConfig(config) {
    this.azureClient = new AzureSentinelClient(config);
    this.isLiveMode = this.azureClient.isConfigured();
    return { isLiveMode: this.isLiveMode };
  }

  getToolDefinitions() {
    return [
      {
        name: 'list_incidents',
        description: 'List Microsoft Sentinel security incidents with optional filters for severity (High, Medium, Low, Informational) and status (New, Active, Closed).',
        inputSchema: {
          type: 'object',
          properties: {
            severity: {
              type: 'string',
              description: 'Filter by severity: High, Medium, Low, Informational',
              enum: ['High', 'Medium', 'Low', 'Informational', 'All']
            },
            status: {
              type: 'string',
              description: 'Filter by status: New, Active, Closed, All',
              enum: ['New', 'Active', 'Closed', 'All']
            },
            limit: {
              type: 'number',
              description: 'Maximum number of incidents to return (default 10)'
            }
          }
        }
      },
      {
        name: 'get_incident_details',
        description: 'Get deep details of a specific Microsoft Sentinel incident including description, status, severity, tactics, and metrics.',
        inputSchema: {
          type: 'object',
          properties: {
            incidentId: {
              type: 'string',
              description: 'The incident ID (e.g. INC-8042) or incident number (8042)'
            }
          },
          required: ['incidentId']
        }
      },
      {
        name: 'get_incident_entities',
        description: 'Extract all correlated security entities for an incident (Compromised Accounts, Hosts, Malicious IPs, File Hashes, Azure Cloud Resources).',
        inputSchema: {
          type: 'object',
          properties: {
            incidentId: {
              type: 'string',
              description: 'The incident identifier (e.g. INC-8042)'
            }
          },
          required: ['incidentId']
        }
      },
      {
        name: 'get_incident_alerts',
        description: 'Retrieve all alerts aggregated under a Microsoft Sentinel incident with detection sources and evidence.',
        inputSchema: {
          type: 'object',
          properties: {
            incidentId: {
              type: 'string',
              description: 'The incident identifier (e.g. INC-8042)'
            }
          },
          required: ['incidentId']
        }
      },
      {
        name: 'run_kql_query',
        description: 'Execute a Kusto Query Language (KQL) query against Microsoft Sentinel Log Analytics workspace tables (e.g. SecurityAlert, DeviceProcessEvents, SigninLogs, DeviceNetworkEvents).',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'The KQL query to execute (e.g. "SecurityAlert | where Severity == \'High\' | take 10")'
            },
            timespan: {
              type: 'string',
              description: 'Timeframe filter (e.g. P1D for 24 hours, P7D for 7 days)'
            }
          },
          required: ['query']
        }
      },
      {
        name: 'analyze_incident',
        description: 'Perform an automated SOC triage and threat analysis on an incident, synthesizing kill-chain progression, blast radius, MITRE ATT&CK mapping, and recommended response steps.',
        inputSchema: {
          type: 'object',
          properties: {
            incidentId: {
              type: 'string',
              description: 'The incident ID to analyze'
            },
            focusArea: {
              type: 'string',
              description: 'Optional focus: "root_cause", "containment", "lateral_movement", "entities", or "all"'
            }
          },
          required: ['incidentId']
        }
      },
      {
        name: 'update_incident_status',
        description: 'Update the status, severity, classification, or assigned owner of a Microsoft Sentinel incident.',
        inputSchema: {
          type: 'object',
          properties: {
            incidentId: {
              type: 'string',
              description: 'The incident ID to update'
            },
            status: {
              type: 'string',
              description: 'New status: New, Active, Closed',
              enum: ['New', 'Active', 'Closed']
            },
            classification: {
              type: 'string',
              description: 'Classification: TruePositive, FalsePositive, BenignPositive',
              enum: ['TruePositive', 'FalsePositive', 'BenignPositive']
            },
            comment: {
              type: 'string',
              description: 'Investigation note or comment to attach'
            }
          },
          required: ['incidentId']
        }
      },
      {
        name: 'trigger_playbook',
        description: 'Trigger an automated SOAR containment or remediation playbook in Sentinel (e.g. Isolate Endpoint, Revoke Entra Session, Block IP at Azure Firewall).',
        inputSchema: {
          type: 'object',
          properties: {
            playbookId: {
              type: 'string',
              description: 'The playbook ID to execute (e.g. PB-ISOLATE-HOST, PB-REVOKE-SESSION, PB-BLOCK-C2-IP)'
            },
            targetEntity: {
              type: 'string',
              description: 'Target IP, Hostname, or User Principal Name'
            },
            incidentId: {
              type: 'string',
              description: 'Associated Incident ID'
            }
          },
          required: ['playbookId', 'targetEntity']
        }
      },
      {
        name: 'get_mitre_mapping',
        description: 'Generate MITRE ATT&CK tactics and techniques matrix mapping for an incident or all current threats.',
        inputSchema: {
          type: 'object',
          properties: {
            incidentId: {
              type: 'string',
              description: 'Specific incident ID or "all"'
            }
          }
        }
      }
    ];
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
    switch (name) {
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
          content: [
            {
              type: 'text',
              text: JSON.stringify({ count: result.length, incidents: result }, null, 2)
            }
          ]
        };
      }

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

      case 'get_incident_entities': {
        const incident = this.findIncident(args.incidentId);
        if (!incident) {
          return {
            isError: true,
            content: [{ type: 'text', text: `Incident '${args.incidentId}' not found.` }]
          };
        }
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                incidentId: incident.id,
                totalEntities: incident.entities.length,
                entities: incident.entities
              }, null, 2)
            }
          ]
        };
      }

      case 'get_incident_alerts': {
        const incident = this.findIncident(args.incidentId);
        if (!incident) {
          return {
            isError: true,
            content: [{ type: 'text', text: `Incident '${args.incidentId}' not found.` }]
          };
        }
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                incidentId: incident.id,
                totalAlerts: incident.alerts.length,
                alerts: incident.alerts
              }, null, 2)
            }
          ]
        };
      }

      case 'run_kql_query': {
        const query = (args.query || '').trim();
        if (this.isLiveMode) {
          try {
            const data = await this.azureClient.executeKql(query, args.timespan || 'P1D');
            return {
              content: [{ type: 'text', text: JSON.stringify(data, null, 2) }]
            };
          } catch (err) {
            return {
              isError: true,
              content: [{ type: 'text', text: `KQL execution error on Azure: ${err.message}` }]
            };
          }
        }

        // Mock KQL Execution
        let matchedTable = 'SecurityAlert';
        if (/DeviceProcessEvents/i.test(query)) matchedTable = 'DeviceProcessEvents';
        else if (/SigninLogs/i.test(query)) matchedTable = 'SigninLogs';
        else if (/DeviceNetworkEvents/i.test(query)) matchedTable = 'DeviceNetworkEvents';

        let rows = mockKqlDatabase[matchedTable] || [];

        // Simple mock filter
        if (/where.*Critical/i.test(query)) {
          rows = rows.filter(r => r.Severity === 'Critical');
        } else if (/where.*High/i.test(query)) {
          rows = rows.filter(r => r.Severity === 'High' || r.RiskLevelDuringSignIn === 'High');
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                executedQuery: query,
                table: matchedTable,
                rowCount: rows.length,
                results: rows
              }, null, 2)
            }
          ]
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
          content: [
            {
              type: 'text',
              text: JSON.stringify(analysis, null, 2)
            }
          ]
        };
      }

      case 'update_incident_status': {
        const incident = this.findIncident(args.incidentId);
        if (!incident) {
          return {
            isError: true,
            content: [{ type: 'text', text: `Incident '${args.incidentId}' not found.` }]
          };
        }

        if (args.status) incident.status = args.status;
        if (args.classification) incident.classification = args.classification;
        if (args.comment) {
          incident.comments = incident.comments || [];
          incident.comments.push({
            author: 'Sentinel MCP Agent',
            time: new Date().toISOString(),
            text: args.comment
          });
        }
        incident.lastModifiedTimeUtc = new Date().toISOString();

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                message: `Incident ${incident.id} updated successfully.`,
                status: incident.status,
                classification: incident.classification,
                lastModified: incident.lastModifiedTimeUtc
              }, null, 2)
            }
          ]
        };
      }

      case 'trigger_playbook': {
        const { playbookId, targetEntity, incidentId } = args;
        const incident = this.findIncident(incidentId);

        let playbook = null;
        if (incident && incident.remediationPlaybooks) {
          playbook = incident.remediationPlaybooks.find(pb => pb.playbookId === playbookId || pb.target === targetEntity);
          if (playbook) {
            playbook.status = 'Executed';
          }
        }

        const executionRecord = {
          executionId: `EXEC-${Math.floor(100000 + Math.random() * 900000)}`,
          playbookId,
          targetEntity,
          incidentId: incidentId || 'Global',
          status: 'Success',
          timestamp: new Date().toISOString(),
          responseDetails: `Playbook ${playbookId} executed against ${targetEntity}. Automation rule completed with exit code 0.`
        };

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(executionRecord, null, 2)
            }
          ]
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

        // Global Matrix
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
          content: [{ type: 'text', text: `Unknown tool: ${name}` }]
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
            }
          }
        };

      case 'initialized':
        return null; // Notification, no response needed

      case 'ping':
        return { jsonrpc: '2.0', id, result: {} };

      case 'tools/list':
        return {
          jsonrpc: '2.0',
          id,
          result: {
            tools: this.getToolDefinitions()
          }
        };

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

      case 'resources/list':
        return {
          jsonrpc: '2.0',
          id,
          result: {
            resources: [
              {
                uri: 'sentinel://incidents/active',
                name: 'Active Sentinel Incidents',
                description: 'Current real-time incidents from Microsoft Sentinel workspace',
                mimeType: 'application/json'
              },
              {
                uri: 'sentinel://tables/catalog',
                name: 'Log Analytics Tables',
                description: 'Catalog of tables available for KQL hunting',
                mimeType: 'application/json'
              }
            ]
          }
        };

      case 'resources/read': {
        const uri = params?.uri || '';
        let data = {};
        if (uri.includes('incidents')) {
          data = this.incidents.filter(i => i.status === 'Active');
        } else {
          data = ['SecurityAlert', 'DeviceProcessEvents', 'SigninLogs', 'DeviceNetworkEvents'];
        }
        return {
          jsonrpc: '2.0',
          id,
          result: {
            contents: [
              {
                uri,
                mimeType: 'application/json',
                text: JSON.stringify(data, null, 2)
              }
            ]
          }
        };
      }

      case 'prompts/list':
        return {
          jsonrpc: '2.0',
          id,
          result: {
            prompts: [
              {
                name: 'triage_incident',
                description: 'Standard SOC Level 2/3 incident triage workflow',
                arguments: [
                  { name: 'incidentId', description: 'ID of the incident to triage', required: true }
                ]
              },
              {
                name: 'hunt_threat',
                description: 'Automated threat hunting query synthesis across security logs',
                arguments: [
                  { name: 'ioc', description: 'Indicator of compromise (IP, hash, account)', required: true }
                ]
              }
            ]
          }
        };

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

    // Handle signals
    process.on('SIGTERM', () => process.exit(0));
    process.on('SIGINT', () => process.exit(0));
  }
}

// If executed directly
if (require.main === module) {
  const server = new SentinelMCPServer();
  server.startStdio();
}

module.exports = SentinelMCPServer;
