// AI & SOC Prompt Orchestrator
// Translates natural language user prompts into Sentinel MCP tool calls and synthesizes analysis

class PromptOrchestrator {
  constructor(mcpClient) {
    this.mcpClient = mcpClient;
  }

  async processPrompt(userPrompt, activeIncidentId = null) {
    const prompt = (userPrompt || '').trim();
    const executedToolCalls = [];

    // 1. Detect Incident ID in prompt or fallback to activeIncidentId or default to INC-8042
    let matchedIncidentId = this.detectIncidentId(prompt) || activeIncidentId;

    // If still none detected, check if user is asking to list or summarize all
    const isListRequest = /(list|show|all|active|recent|overview)\s+(incidents|alerts|threats)/i.test(prompt);
    const isKqlRequest = /(kql|query|search log|log analytics|powershell log|signin log|events)/i.test(prompt);
    const isMitreRequest = /(mitre|att&ck|tactics|techniques|matrix)/i.test(prompt);

    if (!matchedIncidentId && !isListRequest && !isKqlRequest && !isMitreRequest) {
      matchedIncidentId = 'INC-8042'; // Default sample incident if nothing specified
    }

    let incidentData = null;
    let entitiesData = null;
    let alertsData = null;
    let mitreData = null;
    let kqlData = null;
    let analysisData = null;

    // 2. Invoke appropriate MCP tools based on intent
    if (isListRequest) {
      executedToolCalls.push({ name: 'list_incidents', args: { severity: 'All', status: 'Active' } });
      const listRes = await this.mcpClient.callTool('list_incidents', { severity: 'All', status: 'Active' });

      return {
        prompt,
        intent: 'list_incidents',
        type: 'incident_list',
        executedToolCalls,
        data: listRes,
        summary: `Retrieved ${listRes.count} active incidents from Microsoft Sentinel workspace.`,
        insights: [
          'High priority: INC-8042 (Multi-stage Ransomware) requires immediate containment.',
          'INC-7391 (Impossible Travel) involves an Entra ID Global Administrator account with active inbox forwarding rules.',
          'INC-6218 (Supply Chain) has outbound C2 beaconing from Azure DevOps runner.'
        ]
      };
    }

    if (isKqlRequest && !matchedIncidentId) {
      const sampleQuery = prompt.includes('|') ? prompt : "DeviceProcessEvents | where ProcessCommandLine contains 'vssadmin' or ProcessCommandLine contains 'powershell' | take 5";
      executedToolCalls.push({ name: 'run_kql_query', args: { query: sampleQuery } });
      kqlData = await this.mcpClient.callTool('run_kql_query', { query: sampleQuery });

      return {
        prompt,
        intent: 'kql_hunt',
        type: 'kql_result',
        executedToolCalls,
        kqlData,
        summary: `Executed KQL query across Sentinel Log Analytics. Found ${kqlData.rowCount || 0} matching security telemetry records.`
      };
    }

    // Default or Specific Incident Investigation Flow
    if (matchedIncidentId) {
      // 1. Call MCP analyze_incident
      executedToolCalls.push({ name: 'analyze_incident', args: { incidentId: matchedIncidentId } });
      try {
        analysisData = await this.mcpClient.callTool('analyze_incident', { incidentId: matchedIncidentId });
      } catch (e) {
        console.error('Error calling analyze_incident:', e);
      }

      // 2. Call MCP get_incident_entities
      executedToolCalls.push({ name: 'get_incident_entities', args: { incidentId: matchedIncidentId } });
      try {
        entitiesData = await this.mcpClient.callTool('get_incident_entities', { incidentId: matchedIncidentId });
      } catch (e) {
        console.error('Error calling get_incident_entities:', e);
      }

      // 3. Call MCP get_incident_alerts
      executedToolCalls.push({ name: 'get_incident_alerts', args: { incidentId: matchedIncidentId } });
      try {
        alertsData = await this.mcpClient.callTool('get_incident_alerts', { incidentId: matchedIncidentId });
      } catch (e) {
        console.error('Error calling get_incident_alerts:', e);
      }

      // 4. Call MCP get_mitre_mapping
      executedToolCalls.push({ name: 'get_mitre_mapping', args: { incidentId: matchedIncidentId } });
      try {
        mitreData = await this.mcpClient.callTool('get_mitre_mapping', { incidentId: matchedIncidentId });
      } catch (e) {
        console.error('Error calling get_mitre_mapping:', e);
      }

      // 5. If user specifically asked for KQL or process events, execute KQL query
      if (/(process|command|execution|powershell|hash|network|traffic)/i.test(prompt)) {
        const query = "DeviceProcessEvents | where DeviceName contains 'FIN' or DeviceName contains 'AZ' | take 5";
        executedToolCalls.push({ name: 'run_kql_query', args: { query } });
        try {
          kqlData = await this.mcpClient.callTool('run_kql_query', { query });
        } catch (e) {
          console.error('Error calling run_kql_query:', e);
        }
      }
    }

    // Build synthesized narrative
    const responsePayload = this.synthesizeAnalysisReport({
      prompt,
      incidentId: matchedIncidentId,
      analysis: analysisData,
      entities: entitiesData?.entities || [],
      alerts: alertsData?.alerts || [],
      mitre: mitreData,
      kql: kqlData,
      executedToolCalls
    });

    return responsePayload;
  }

  detectIncidentId(prompt) {
    if (!prompt) return null;
    const lower = prompt.toLowerCase();

    // Direct ID match
    const match = prompt.match(/\b(INC[-_]?[0-9]{4})\b/i);
    if (match) {
      return match[1].replace('_', '-').toUpperCase();
    }
    const numMatch = prompt.match(/\b(8042|7391|6218|5109|4470)\b/);
    if (numMatch) {
      return `INC-${numMatch[1]}`;
    }

    // Keyword heuristics
    if (lower.includes('ransomware') || lower.includes('shadow copy') || lower.includes('sql') || lower.includes('blackcat') || lower.includes('vssadmin')) {
      return 'INC-8042';
    }
    if (lower.includes('impossible travel') || lower.includes('sarah') || lower.includes('jenkins') || lower.includes('aitm') || lower.includes('evilginx')) {
      return 'INC-7391';
    }
    if (lower.includes('supply chain') || lower.includes('sideload') || lower.includes('devops') || lower.includes('runner') || lower.includes('c2 beacon')) {
      return 'INC-6218';
    }
    if (lower.includes('exfiltration') || lower.includes('storage') || lower.includes('sas token') || lower.includes('blob') || lower.includes('egress')) {
      return 'INC-5109';
    }
    if (lower.includes('kerberoast') || lower.includes('ticket') || lower.includes('domain controller') || lower.includes('spn')) {
      return 'INC-4470';
    }

    return null;
  }

  synthesizeAnalysisReport({ prompt, incidentId, analysis, entities, alerts, mitre, kql, executedToolCalls }) {
    if (!analysis) {
      return {
        prompt,
        incidentId,
        type: 'error',
        message: `Incident ${incidentId} could not be resolved or retrieved from Sentinel MCP server.`,
        executedToolCalls
      };
    }

    // Determine threat verdict
    let threatVerdict = 'Malicious Active Cyber Attack';
    if (analysis.severity === 'Critical' || analysis.riskScore >= 90) {
      threatVerdict = 'CRITICAL SEVERITY INCIDENT - ACTIVE IMPACT DETECTED';
    } else if (analysis.severity === 'High') {
      threatVerdict = 'HIGH PRIORITY INCIDENT - POTENTIAL BREACH IN PROGRESS';
    }

    // Extract IoCs
    const iocs = {
      accounts: entities.filter(e => e.type === 'Account').map(e => e.name),
      hosts: entities.filter(e => e.type === 'Host').map(e => e.name),
      ips: entities.filter(e => e.type === 'IP').map(e => e.name),
      hashes: entities.filter(e => e.type === 'FileHash').map(e => e.name),
      cloudResources: entities.filter(e => e.type === 'AzureResource').map(e => e.name)
    };

    // Assessment narrative tailored to prompt
    let analysisNarrative = `### Executive Summary & Incident Triage for ${analysis.incidentId}\n\n` +
      `**Title:** ${analysis.title}\n` +
      `**Assigned Severity:** ${analysis.severity.toUpperCase()} | **Risk Score:** ${analysis.riskScore}/100 | **Detection Confidence:** ${analysis.confidenceScore}%\n` +
      `**Blast Radius:** ${analysis.blastRadius}\n\n` +
      `#### 1. Attack Progression & Threat Vector\n` +
      `${analysis.deepTechnicalAnalysis}\n\n` +
      `Adversary Kill Chain Trajectory: \`${analysis.threatVector}\`.\n\n` +
      `#### 2. Correlated Forensic Findings\n` +
      `- **Correlated Alerts:** ${alerts.length} distinct security alerts aggregated across Defender for Endpoint, Defender for Identity, and Sentinel Analytics.\n` +
      `- **Compromised Identity:** ${iocs.accounts.length ? iocs.accounts.join(', ') : 'None directly identified'}.\n` +
      `- **Impacted Infrastructure:** ${iocs.hosts.length ? iocs.hosts.join(', ') : 'N/A'}.\n` +
      `- **C2 & Malicious Infrastructure:** ${iocs.ips.length ? iocs.ips.join(', ') : 'Internal pivot only'}.\n\n` +
      `#### 3. Immediate Containment & SOAR Remediation Plan\n` +
      `The following incident response playbooks have been prepared via Sentinel SOAR orchestration:`;

    return {
      prompt,
      incidentId: analysis.incidentId,
      title: analysis.title,
      severity: analysis.severity,
      status: analysis.status,
      riskScore: analysis.riskScore,
      confidenceScore: analysis.confidenceScore,
      blastRadius: analysis.blastRadius,
      threatVerdict,
      narrativeMarkdown: analysisNarrative,
      attackProgression: analysis.attackProgression || [],
      recommendedActions: analysis.recommendedContainmentActions || [],
      entities,
      alerts,
      mitre: mitre || analysis.mitreMapping,
      kqlData: kql,
      iocs,
      executedToolCalls
    };
  }
}

module.exports = PromptOrchestrator;
