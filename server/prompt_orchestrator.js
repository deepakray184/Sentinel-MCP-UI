// AI & SOC Prompt Orchestrator for Microsoft Sentinel MCP Server
// Supports:
// 1. Data exploration (https://sentinel.microsoft.com/mcp/data-exploration)
// 2. Security Copilot agent creation (https://sentinel.microsoft.com/mcp/security-copilot-agent-creation)
// 3. Triage (https://sentinel.microsoft.com/mcp/triage)

class PromptOrchestrator {
  constructor(mcpClient) {
    this.mcpClient = mcpClient;
  }

  async processPrompt(userPrompt, activeIncidentId = null, preferredCollection = 'all') {
    const prompt = (userPrompt || '').trim();
    const executedToolCalls = [];

    // 1. Detect Intent Category
    const isAgentCreation = /(create|build|generate|make|deploy)\s+(a\s+)?(security\s+copilot\s+)?agent/i.test(prompt) ||
                            /(agent\s+creation|copilot\s+agent|generate\s+agent|agent\s+yaml)/i.test(prompt);

    const isDataExploration = /(search\s+table|table\s+catalog|query\s+lake|explore\s+data|analyze\s+user|analyze\s+url|workspace\s+list|data\s+graph)/i.test(prompt) ||
                              /(tables\s+for|columns\s+in|lake\s+tables|user\s+entity|url\s+entity)/i.test(prompt);

    const isDefenderLookup = /(defender\s+machine|machine\s+status|file\s+hash|file\s+intel|threat\s+indicator|indicators|ioc\s+list|machine\s+telemetry)/i.test(prompt);

    // =========================================================================
    // BRANCH A: Security Copilot Agent Creation Collection
    // Endpoint: https://sentinel.microsoft.com/mcp/security-copilot-agent-creation
    // =========================================================================
    if (isAgentCreation || preferredCollection === 'security-copilot-agent-creation') {
      let agentName = 'Custom-Security-Agent';
      const nameMatch = prompt.match(/named?\s+["']?([A-Za-z0-9_-]+)["']?/i) || prompt.match(/agent\s+([A-Za-z0-9_-]+)/i);
      if (nameMatch && !['that', 'for', 'to', 'a', 'the'].includes(nameMatch[1].toLowerCase())) {
        agentName = nameMatch[1];
      } else if (/ransomware/i.test(prompt)) {
        agentName = 'Ransomware-Rapid-Responder';
      } else if (/report|post-incident/i.test(prompt)) {
        agentName = 'Post-Incident-Reporter';
      } else if (/phish|email/i.test(prompt)) {
        agentName = 'Phishing-Triager';
      }

      // Step 1: Search for tools matching the workflow
      executedToolCalls.push({ name: 'search_for_tools', args: { capabilityNeed: prompt } });
      let toolsRes = null;
      try {
        toolsRes = await this.mcpClient.callTool('search_for_tools', { capabilityNeed: prompt });
      } catch (e) {
        console.error('search_for_tools error:', e);
      }

      // Step 2: Create the agent
      const skillsToEquip = (toolsRes && toolsRes.availableTools) ? toolsRes.availableTools.slice(0, 3).map(t => t.toolId) : [
        'sentinel_incident_triage',
        'defender_isolate_machine',
        'entra_revoke_user_sessions'
      ];

      executedToolCalls.push({
        name: 'create_security_copilot_agent',
        args: { agentName, workflowPrompt: prompt, skills: skillsToEquip }
      });

      const agentRes = await this.mcpClient.callTool('create_security_copilot_agent', {
        agentName,
        workflowPrompt: prompt,
        skills: skillsToEquip
      });

      return {
        prompt,
        intent: 'agent_creation',
        collection: 'Security Copilot agent creation',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/security-copilot-agent-creation',
        type: 'agent_created',
        executedToolCalls,
        agent: agentRes.agent,
        toolsUsed: toolsRes?.availableTools || [],
        summary: `Created Microsoft Security Copilot agent '${agentName}' with ${skillsToEquip.length} integrated capabilities.`,
        narrativeMarkdown: `### 🤖 Microsoft Security Copilot Agent Created: \`${agentName}\`\n\n` +
          `**Collection:** [Security Copilot agent creation](https://sentinel.microsoft.com/mcp/security-copilot-agent-creation)\n` +
          `**Status:** \`Draft\` | **Runtime:** \`Microsoft Security Copilot\`\n\n` +
          `#### 1. Workflow Specification\n${prompt}\n\n` +
          `#### 2. Equipped Capabilities & Tools\n` +
          `${skillsToEquip.map(s => `- \`${s}\``).join('\n')}\n\n` +
          `#### 3. Generated Agent YAML Manifest\n` +
          `\`\`\`yaml\n${agentRes.agent.yamlSpec}\n\`\`\`\n`
      };
    }

    // =========================================================================
    // BRANCH B: Data Exploration Collection
    // Endpoint: https://sentinel.microsoft.com/mcp/data-exploration
    // =========================================================================
    if (isDataExploration || preferredCollection === 'data-exploration') {
      // 1. Check if user is asking to analyze a specific user entity
      const userMatch = prompt.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/);
      if (userMatch || /analyze user/i.test(prompt)) {
        const upn = userMatch ? userMatch[1] : 'sarah.jenkins@contoso.com';
        executedToolCalls.push({ name: 'analyze_user_entity', args: { userPrincipalName: upn } });
        const userRes = await this.mcpClient.callTool('analyze_user_entity', { userPrincipalName: upn });

        return {
          prompt,
          intent: 'data_exploration_user',
          collection: 'Data exploration',
          collectionUrl: 'https://sentinel.microsoft.com/mcp/data-exploration',
          type: 'entity_analysis',
          executedToolCalls,
          userEntity: userRes,
          summary: `Analyzed user entity ${upn} in Sentinel data lake. Risk Verdict: ${userRes.riskVerdict}.`,
          narrativeMarkdown: `### 👤 Sentinel Data Lake Entity Analysis: \`${upn}\`\n\n` +
            `**Department:** ${userRes.department} &bull; **Job Title:** ${userRes.jobTitle}\n` +
            `**Risk Score:** ${userRes.riskScore}/100 &bull; **Verdict:** **${userRes.riskVerdict}**\n\n` +
            `#### Summary\n${userRes.summary}\n\n` +
            `#### Behavioral Anomalies Detected\n` +
            `${(userRes.anomalies || []).map(a => `- ${a}`).join('\n')}\n\n` +
            `#### Recommended Actions\n` +
            `${(userRes.recommendedActions || []).map(r => `- ${r}`).join('\n')}`
        };
      }

      // 2. Check if user is asking to search tables
      const tableKeyword = prompt.replace(/(search\s+table|table\s+catalog|tables|show|find)/gi, '').trim() || 'security';
      executedToolCalls.push({ name: 'search_tables', args: { keyword: tableKeyword } });
      const tablesRes = await this.mcpClient.callTool('search_tables', { keyword: tableKeyword });

      return {
        prompt,
        intent: 'data_exploration_tables',
        collection: 'Data exploration',
        collectionUrl: 'https://sentinel.microsoft.com/mcp/data-exploration',
        type: 'table_catalog',
        executedToolCalls,
        tablesData: tablesRes,
        summary: `Found ${tablesRes.matchedCount} Sentinel data lake tables matching keyword '${tableKeyword}'.`,
        narrativeMarkdown: `### 🗄️ Sentinel Data Lake Table Catalog Search: \`${tableKeyword}\`\n\n` +
          `Found **${tablesRes.matchedCount} matching tables** in Microsoft Sentinel data lake.\n\n` +
          `${(tablesRes.tables || []).map(t => `#### \`${t.name}\` (${t.category})\n${t.description}\n- **Sample KQL:** \`${t.sampleQuery}\`\n`).join('\n')}`
      };
    }

    // =========================================================================
    // BRANCH C: Triage Collection
    // Endpoint: https://sentinel.microsoft.com/mcp/triage
    // =========================================================================
    if (isDefenderLookup) {
      // Defender Machine or File lookup
      if (/machine|host|srv|wks/i.test(prompt)) {
        const machineTarget = prompt.includes('882') ? 'WKS-FIN-882' : 'SRV-FIN-SQL01';
        executedToolCalls.push({ name: 'GetDefenderMachine', args: { machineNameOrId: machineTarget } });
        const machineData = await this.mcpClient.callTool('GetDefenderMachine', { machineNameOrId: machineTarget });

        return {
          prompt,
          intent: 'triage_defender_machine',
          collection: 'Triage',
          collectionUrl: 'https://sentinel.microsoft.com/mcp/triage',
          type: 'defender_machine',
          executedToolCalls,
          machineData,
          summary: `Retrieved Defender telemetry for machine ${machineTarget}. Isolation status: ${machineData.isIsolated ? 'ISOLATED' : 'NOT ISOLATED'}.`,
          narrativeMarkdown: `### 💻 Microsoft Defender Machine Telemetry: \`${machineTarget}\`\n\n` +
            `- **OS:** ${machineData.osPlatform} (${machineData.version})\n` +
            `- **IP Addresses:** ${machineData.ipAddresses.join(', ')}\n` +
            `- **Health Status:** ${machineData.healthStatus} &bull; **Risk Score:** ${machineData.riskScore}\n` +
            `- **Network Isolation Status:** **${machineData.isIsolated ? '🛡️ ISOLATED' : '⚠️ NOT ISOLATED'}**\n` +
            `- **Logged On Users:** ${machineData.loggedOnUsers.join(', ')}\n`
        };
      }
    }

    // Default Triage Incident Analysis Flow
    let matchedIncidentId = this.detectIncidentId(prompt) || activeIncidentId || 'INC-8042';

    // 1. Call MCP analyze_incident
    executedToolCalls.push({ name: 'analyze_incident', args: { incidentId: matchedIncidentId } });
    const analysisData = await this.mcpClient.callTool('analyze_incident', { incidentId: matchedIncidentId });

    // 2. Call MCP get_incident_entities
    executedToolCalls.push({ name: 'get_incident_entities', args: { incidentId: matchedIncidentId } });
    const entitiesData = await this.mcpClient.callTool('get_incident_entities', { incidentId: matchedIncidentId });

    // 3. Call MCP ListAlerts
    executedToolCalls.push({ name: 'ListAlerts', args: { incidentId: matchedIncidentId } });
    const alertsData = await this.mcpClient.callTool('ListAlerts', { incidentId: matchedIncidentId });

    // 4. Call MCP get_mitre_mapping
    executedToolCalls.push({ name: 'get_mitre_mapping', args: { incidentId: matchedIncidentId } });
    const mitreData = await this.mcpClient.callTool('get_mitre_mapping', { incidentId: matchedIncidentId });

    return this.synthesizeAnalysisReport({
      prompt,
      incidentId: matchedIncidentId,
      analysis: analysisData,
      entities: entitiesData?.entities || [],
      alerts: alertsData?.alerts || [],
      mitre: mitreData,
      executedToolCalls
    });
  }

  detectIncidentId(prompt) {
    if (!prompt) return null;
    const match = prompt.match(/\b(INC[-_]?[0-9]{4})\b/i);
    if (match) return match[1].replace('_', '-').toUpperCase();

    const numMatch = prompt.match(/\b(8042|7391|6218|5109|4470)\b/);
    if (numMatch) return `INC-${numMatch[1]}`;

    const lower = prompt.toLowerCase();
    if (lower.includes('ransomware') || lower.includes('shadow copy') || lower.includes('sql')) return 'INC-8042';
    if (lower.includes('impossible travel') || lower.includes('sarah') || lower.includes('jenkins')) return 'INC-7391';
    if (lower.includes('supply chain') || lower.includes('devops')) return 'INC-6218';
    return null;
  }

  synthesizeAnalysisReport({ prompt, incidentId, analysis, entities, alerts, mitre, executedToolCalls }) {
    if (!analysis) {
      return {
        prompt,
        incidentId,
        type: 'error',
        message: `Incident ${incidentId} could not be resolved.`,
        executedToolCalls
      };
    }

    let analysisNarrative = `### Executive Summary & Incident Triage for ${analysis.incidentId}\n\n` +
      `**Title:** ${analysis.title}\n` +
      `**Assigned Severity:** ${analysis.severity.toUpperCase()} | **Risk Score:** ${analysis.riskScore}/100 | **Detection Confidence:** ${analysis.confidenceScore}%\n` +
      `**Blast Radius:** ${analysis.blastRadius}\n\n` +
      `#### 1. Attack Progression & Threat Vector\n` +
      `${analysis.deepTechnicalAnalysis}\n\n` +
      `Adversary Kill Chain Trajectory: \`${analysis.threatVector}\`.\n\n` +
      `#### 2. Correlated Forensic Findings\n` +
      `- **Correlated Alerts:** ${alerts.length} distinct alerts aggregated under Sentinel Triage.\n` +
      `- **Compromised Identity:** ${entities.filter(e => e.type === 'Account').map(e => e.name).join(', ') || 'N/A'}.\n` +
      `- **Impacted Infrastructure:** ${entities.filter(e => e.type === 'Host').map(e => e.name).join(', ') || 'N/A'}.\n` +
      `- **C2 & Malicious Infrastructure:** ${entities.filter(e => e.type === 'IP').map(e => e.name).join(', ') || 'Internal'}.\n\n` +
      `#### 3. Immediate Containment & SOAR Playbooks\n` +
      `Execute playbooks below to isolate endpoints, block malicious IPs, and revoke Entra ID tokens.`;

    return {
      prompt,
      incidentId: analysis.incidentId,
      title: analysis.title,
      severity: analysis.severity,
      status: analysis.status,
      riskScore: analysis.riskScore,
      confidenceScore: analysis.confidenceScore,
      blastRadius: analysis.blastRadius,
      threatVerdict: analysis.riskScore > 90 ? 'CRITICAL SEVERITY INCIDENT - ACTIVE IMPACT DETECTED' : 'HIGH PRIORITY INCIDENT - POTENTIAL BREACH',
      narrativeMarkdown: analysisNarrative,
      attackProgression: analysis.attackProgression || [],
      recommendedActions: analysis.recommendedContainmentActions || [],
      entities,
      alerts,
      mitre: mitre || analysis.mitreMapping,
      executedToolCalls,
      collection: 'Triage',
      collectionUrl: 'https://sentinel.microsoft.com/mcp/triage'
    };
  }
}

module.exports = PromptOrchestrator;
