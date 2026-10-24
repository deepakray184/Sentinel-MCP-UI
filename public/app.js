// Microsoft Sentinel MCP SOC Dashboard Frontend Controller

let currentIncidentId = 'INC-8042';
let allIncidents = [];
let currentAnalysis = null;
let wireLogsCache = [];

document.addEventListener('DOMContentLoaded', () => {
  initApp();
  setupEventListeners();
  startWirePolling();
});

async function initApp() {
  await fetchStatus();
  await loadIncidents();
  await loadMCPTools();
  // Automatically trigger initial analysis on the default incident
  await runPrompt(`Analyze incident ${currentIncidentId} and summarize root cause, blast radius, and containment actions.`);
}

function setupEventListeners() {
  // Prompt Form Submission
  const promptForm = document.getElementById('prompt-form');
  promptForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const promptInput = document.getElementById('prompt-input');
    const promptText = promptInput.value.trim();
    if (promptText) {
      await runPrompt(promptText);
    }
  });

  // Quick Starter Chips
  document.querySelectorAll('.starter-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const prompt = chip.getAttribute('data-prompt');
      document.getElementById('prompt-input').value = prompt;
      runPrompt(prompt);
    });
  });

  // Tab Navigation for Analysis Pane
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      
      btn.classList.add('active');
      const targetTabId = btn.getAttribute('data-tab');
      const targetPane = document.getElementById(targetTabId);
      if (targetPane) {
        targetPane.classList.add('active');
      }
    });
  });

  // Subtab Navigation for Inspector Pane
  document.querySelectorAll('.subtab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.subtab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.subtab-pane').forEach(p => p.classList.remove('active'));
      
      btn.classList.add('active');
      const targetSubtab = btn.getAttribute('data-subtab');
      const targetPane = document.getElementById(targetSubtab);
      if (targetPane) {
        targetPane.classList.add('active');
      }
    });
  });

  // Search & Severity Filter for Incident List
  const searchInput = document.getElementById('incident-search');
  searchInput.addEventListener('input', filterIncidents);

  document.querySelectorAll('.severity-pill-group .pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('.severity-pill-group .pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      filterIncidents();
    });
  });

  // KQL Preset Selector
  const kqlPreset = document.getElementById('kql-preset-selector');
  kqlPreset.addEventListener('change', () => {
    document.getElementById('kql-editor-input').value = kqlPreset.value;
  });

  // Execute KQL Button
  const btnKql = document.getElementById('btn-execute-kql');
  btnKql.addEventListener('click', executeKqlQuery);

  // Clear Wire Logs Button
  const btnClearLogs = document.getElementById('btn-clear-logs');
  btnClearLogs.addEventListener('click', () => {
    document.getElementById('wire-terminal').innerHTML = '<div class="subtext">Logs cleared. Waiting for next MCP message...</div>';
  });

  // Jump to Wire View from Banner
  const btnViewWire = document.getElementById('btn-view-wire');
  btnViewWire.addEventListener('click', () => {
    const wireTab = document.querySelector('.subtab-btn[data-subtab="subtab-wire"]');
    if (wireTab) wireTab.click();
  });

  // Export Report Button
  const btnExport = document.getElementById('btn-export-report');
  btnExport.addEventListener('click', exportIncidentReport);

  // Settings Modal Handlers
  const btnOpenSettings = document.getElementById('btn-open-settings');
  const btnCloseModal = document.getElementById('btn-close-modal');
  const btnCancelSettings = document.getElementById('btn-cancel-settings');
  const btnSaveSettings = document.getElementById('btn-save-settings');
  const modal = document.getElementById('settings-modal');

  btnOpenSettings.addEventListener('click', () => modal.classList.add('active'));
  btnCloseModal.addEventListener('click', () => modal.classList.remove('active'));
  btnCancelSettings.addEventListener('click', () => modal.classList.remove('active'));

  btnSaveSettings.addEventListener('click', async () => {
    const mode = document.getElementById('config-mode').value;
    const workspace = document.getElementById('config-workspace').value;
    const rg = document.getElementById('config-rg').value;
    const sub = document.getElementById('config-sub').value;
    const tenant = document.getElementById('config-tenant').value;
    const client = document.getElementById('config-client').value;

    try {
      const res = await fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode,
          azureWorkspaceName: workspace,
          azureResourceGroup: rg,
          azureSubscriptionId: sub,
          azureTenantId: tenant,
          azureClientId: client
        })
      });
      const data = await res.json();
      modal.classList.remove('active');
      showToast('Settings saved successfully', 'success');
      await fetchStatus();
    } catch (e) {
      showToast('Failed to save settings: ' + e.message, 'error');
    }
  });
}

// Fetch System Status & Header Info
async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    const statusText = document.getElementById('mcp-status-text');
    if (data.status === 'connected') {
      statusText.textContent = `MCP CONNECTED (${data.version})`;
      document.getElementById('mcp-status-pill').className = 'mcp-status-pill connected';
    } else {
      statusText.textContent = 'MCP CONNECTING...';
      document.getElementById('mcp-status-pill').className = 'mcp-status-pill';
    }
  } catch (err) {
    console.error('Error fetching status:', err);
  }
}

// Load Incidents from Sentinel MCP Server
async function loadIncidents() {
  try {
    const res = await fetch('/api/incidents');
    const data = await res.json();
    allIncidents = data.incidents || [];

    // Update telemetry counts
    document.getElementById('stat-incidents').textContent = allIncidents.length;
    const critCount = allIncidents.filter(i => i.severity === 'High' || i.severity === 'Critical').length;
    document.getElementById('stat-critical').textContent = critCount;
    document.getElementById('incident-count-badge').textContent = `${allIncidents.length} Active`;

    renderIncidentList(allIncidents);
  } catch (e) {
    console.error('Error loading incidents:', e);
    document.getElementById('incident-list-container').innerHTML = 
      `<div class="loading-state text-critical">Failed to load incidents: ${e.message}</div>`;
  }
}

function renderIncidentList(incidents) {
  const container = document.getElementById('incident-list-container');
  if (!incidents.length) {
    container.innerHTML = '<div class="loading-state">No incidents matched filter criteria.</div>';
    return;
  }

  container.innerHTML = incidents.map(inc => {
    const sevClass = `sev-${inc.severity.toLowerCase()}`;
    const isActive = inc.id === currentIncidentId ? 'active' : '';
    const tacticsBadges = (inc.tactics || []).slice(0, 2).map(t => 
      `<span class="inc-tactic-tag">${t}</span>`
    ).join('');

    return `
      <div class="incident-card ${isActive}" data-id="${inc.id}">
        <div class="incident-card-header">
          <span class="inc-id">${inc.id}</span>
          <span class="severity-badge ${sevClass}">${inc.severity}</span>
        </div>
        <div class="inc-title">${escapeHtml(inc.title)}</div>
        <div class="inc-footer">
          <div class="inc-tactics-mini">${tacticsBadges}</div>
          <span>${inc.alertsCount || 1} Alerts</span>
        </div>
      </div>
    `;
  }).join('');

  // Add click handlers
  container.querySelectorAll('.incident-card').forEach(card => {
    card.addEventListener('click', () => {
      const id = card.getAttribute('data-id');
      selectIncident(id);
    });
  });
}

function filterIncidents() {
  const query = document.getElementById('incident-search').value.toLowerCase();
  const activeSevPill = document.querySelector('.severity-pill-group .pill.active');
  const selectedSev = activeSevPill ? activeSevPill.getAttribute('data-sev') : 'All';

  const filtered = allIncidents.filter(inc => {
    const matchesSearch = inc.id.toLowerCase().includes(query) ||
                          inc.title.toLowerCase().includes(query) ||
                          (inc.tactics && inc.tactics.some(t => t.toLowerCase().includes(query)));

    let matchesSev = true;
    if (selectedSev === 'High') {
      matchesSev = inc.severity === 'High' || inc.severity === 'Critical';
    } else if (selectedSev === 'Medium') {
      matchesSev = inc.severity === 'Medium';
    }

    return matchesSearch && matchesSev;
  });

  renderIncidentList(filtered);
}

function selectIncident(id) {
  currentIncidentId = id;
  document.getElementById('current-incident-tag').textContent = id;
  
  // Highlight card
  document.querySelectorAll('.incident-card').forEach(c => {
    c.classList.toggle('active', c.getAttribute('data-id') === id);
  });

  // Run analysis for this incident
  runPrompt(`Deep analyze incident ${id} and retrieve all correlated entities, alerts, and remediation playbooks.`);
}

// Execute Natural Language Prompt Analysis via Sentinel MCP Server
async function runPrompt(promptText) {
  const btnRun = document.getElementById('btn-run-prompt');
  const originalBtnHtml = btnRun.innerHTML;
  btnRun.innerHTML = `<div class="cyber-spinner" style="width:14px;height:14px;border-width:2px;"></div><span>Analyzing MCP...</span>`;
  btnRun.disabled = true;

  try {
    const res = await fetch('/api/prompt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        prompt: promptText,
        incidentId: currentIncidentId
      })
    });

    const data = await res.json();
    currentAnalysis = data;
    renderAnalysisView(data);
    showToast(`Analysis completed via ${data.executedToolCalls ? data.executedToolCalls.length : 1} MCP tool calls`, 'info');
  } catch (err) {
    console.error('Prompt analysis error:', err);
    showToast('Analysis request failed: ' + err.message, 'error');
  } finally {
    btnRun.innerHTML = originalBtnHtml;
    btnRun.disabled = false;
  }
}

// Render the Rich Analysis View
function renderAnalysisView(data) {
  if (data.incidentId) {
    currentIncidentId = data.incidentId;
    document.getElementById('current-incident-tag').textContent = data.incidentId;
    document.getElementById('banner-id').textContent = data.incidentId;
  }

  // Update Headline Banner
  if (data.title) {
    document.getElementById('banner-title').textContent = data.title;
  }
  if (data.severity) {
    const sevBadge = document.getElementById('banner-severity');
    sevBadge.textContent = data.severity.toUpperCase();
    sevBadge.className = `severity-badge sev-${data.severity.toLowerCase()}`;
  }
  if (data.status) {
    document.getElementById('banner-status').textContent = data.status.toUpperCase();
  }
  if (data.riskScore !== undefined) {
    document.getElementById('metric-risk-score').textContent = data.riskScore;
  }
  if (data.confidenceScore !== undefined) {
    document.getElementById('metric-confidence').textContent = data.confidenceScore + '%';
  }

  // Tactics Badges
  const tacticsRow = document.getElementById('banner-tactics');
  const tacticsList = (data.mitre?.tactics) || (data.mitre) || [];
  if (Array.isArray(tacticsList)) {
    tacticsRow.innerHTML = tacticsList.map(t => `<span class="tactic-tag">${t}</span>`).join('');
  } else if (typeof tacticsList === 'object') {
    tacticsRow.innerHTML = Object.keys(tacticsList).map(t => `<span class="tactic-tag">${t}</span>`).join('');
  }

  // MCP Tool Execution Banner
  const toolBanner = document.getElementById('mcp-tool-banner');
  const toolBannerText = document.getElementById('mcp-tool-banner-text');
  if (data.executedToolCalls && data.executedToolCalls.length > 0) {
    toolBanner.style.display = 'flex';
    const toolNames = data.executedToolCalls.map(tc => `<code>${tc.name}</code>`).join(', ');
    toolBannerText.innerHTML = `Sentinel MCP Server invoked: ${toolNames}`;
  } else {
    toolBanner.style.display = 'none';
  }

  // Render Tab 1: Executive Narrative
  renderNarrativeTab(data);

  // Render Tab 2: Entities
  renderEntitiesTab(data.entities || []);

  // Render Tab 3: Timeline
  renderTimelineTab(data.attackProgression || []);

  // Render Tab 4: Alerts
  renderAlertsTab(data.alerts || []);

  // Render Tab 6: Playbooks
  renderPlaybooksTab(data.recommendedActions || [], data.incidentId);

  // Update tab counts
  document.getElementById('tab-entities-count').textContent = (data.entities || []).length;
  document.getElementById('tab-alerts-count').textContent = (data.alerts || []).length;
}

function renderNarrativeTab(data) {
  const verdictBox = document.getElementById('threat-verdict-box');
  const verdictTitle = document.getElementById('verdict-title');
  const verdictSummary = document.getElementById('verdict-summary');
  
  if (data.threatVerdict) {
    verdictTitle.textContent = data.threatVerdict;
  }
  if (data.blastRadius) {
    verdictSummary.textContent = `Blast Radius: ${data.blastRadius} | Risk Score: ${data.riskScore}/100`;
  }

  const container = document.getElementById('narrative-content');
  const md = data.narrativeMarkdown || data.summary || 'No narrative generated.';
  container.innerHTML = parseMarkdownToHtml(md);
}

function renderEntitiesTab(entities) {
  const tbody = document.getElementById('entities-table-body');
  if (!entities.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="subtext">No entities extracted for this incident.</td></tr>';
    return;
  }

  tbody.innerHTML = entities.map(entity => {
    let actionBtn = '';
    const name = escapeHtml(entity.name);

    if (entity.type === 'Host') {
      actionBtn = `<button class="btn btn-secondary btn-sm" onclick="triggerDirectPlaybook('PB-ISOLATE-HOST', '${name}')">Isolate Host</button>`;
    } else if (entity.type === 'Account') {
      actionBtn = `<button class="btn btn-secondary btn-sm" onclick="triggerDirectPlaybook('PB-REVOKE-SESSION', '${name}')">Revoke Session</button>`;
    } else if (entity.type === 'IP') {
      actionBtn = `<button class="btn btn-secondary btn-sm" onclick="triggerDirectPlaybook('PB-BLOCK-C2-IP', '${name}')">Block IP</button>`;
    } else {
      actionBtn = `<button class="btn btn-secondary btn-sm" onclick="showToast('Entity marked for review: ${name}', 'info')">Review</button>`;
    }

    let riskBadge = '<span class="severity-badge sev-medium">Medium</span>';
    const risk = entity.properties?.riskLevel || entity.properties?.threatScore || 'Medium';
    if (risk === 'High' || risk > 80) {
      riskBadge = `<span class="severity-badge sev-critical">Risk ${risk}</span>`;
    }

    const context = entity.properties?.threatReputation || entity.properties?.osVersion || entity.properties?.role || 'Verified identity / system asset';

    return `
      <tr>
        <td><span class="entity-type-badge type-${entity.type}">${entity.type}</span></td>
        <td><strong>${name}</strong></td>
        <td>${riskBadge}</td>
        <td class="subtext">${escapeHtml(context)}</td>
        <td>${actionBtn}</td>
      </tr>
    `;
  }).join('');
}

function renderTimelineTab(steps) {
  const container = document.getElementById('timeline-container');
  if (!steps.length) {
    container.innerHTML = '<div class="subtext">Timeline progression will appear once threat events are correlated.</div>';
    return;
  }

  container.innerHTML = steps.map(step => `
    <div class="timeline-step">
      <div class="timeline-dot"></div>
      <div class="timeline-content-card">
        <div class="timeline-top">
          <span class="timeline-phase">${escapeHtml(step.phase)}</span>
          <span class="timeline-time">${escapeHtml(step.time)}</span>
        </div>
        <div class="subtext" style="color:#7dd3fc;margin-bottom:4px;font-family:var(--font-mono);font-size:0.72rem;">
          Tactic: ${escapeHtml(step.tactic)}
        </div>
        <div class="timeline-details">${escapeHtml(step.details)}</div>
      </div>
    </div>
  `).join('');
}

function renderAlertsTab(alerts) {
  const container = document.getElementById('alerts-feed-container');
  if (!alerts.length) {
    container.innerHTML = '<div class="subtext">No individual alerts linked.</div>';
    return;
  }

  container.innerHTML = alerts.map(a => `
    <div class="alert-card">
      <div class="alert-top">
        <span class="alert-name">${escapeHtml(a.alertDisplayName)}</span>
        <span class="severity-badge sev-${(a.severity || 'high').toLowerCase()}">${a.severity}</span>
      </div>
      <div class="alert-provider">Provider: ${escapeHtml(a.provider || 'Microsoft Defender')} &bull; ID: ${escapeHtml(a.alertId || 'N/A')}</div>
      <div class="alert-desc">${escapeHtml(a.description || '')}</div>
    </div>
  `).join('');
}

function renderPlaybooksTab(playbooks, incidentId) {
  const container = document.getElementById('playbook-grid');
  if (!playbooks.length) {
    container.innerHTML = '<div class="subtext">No automated playbooks configured for this incident profile.</div>';
    return;
  }

  container.innerHTML = playbooks.map(pb => `
    <div class="playbook-card">
      <div>
        <div class="playbook-name">${escapeHtml(pb.action || pb.name)}</div>
        <div class="subtext" style="color:var(--sentinel-cyan);font-family:var(--font-mono);margin:4px 0;">
          Target: ${escapeHtml(pb.target)}
        </div>
        <div class="playbook-desc">${escapeHtml(pb.guidance || pb.description)}</div>
      </div>
      <div class="playbook-footer">
        <span class="badge badge-subtle">Status: ${pb.currentStatus || 'Ready'}</span>
        <button class="btn btn-cyber btn-sm" onclick="triggerDirectPlaybook('${pb.id || pb.playbookId}', '${escapeHtml(pb.target)}')">
          Execute Playbook
        </button>
      </div>
    </div>
  `).join('');
}

// Direct Playbook Invocation via MCP trigger_playbook Tool
async function triggerDirectPlaybook(playbookId, target) {
  try {
    showToast(`Triggering SOAR playbook ${playbookId} on ${target}...`, 'info');
    const res = await fetch('/api/playbook/trigger', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        playbookId,
        targetEntity: target,
        incidentId: currentIncidentId
      })
    });
    const data = await res.json();
    showToast(`Playbook executed successfully! Execution ID: ${data.result?.executionId || 'OK'}`, 'success');
  } catch (e) {
    showToast('Failed to trigger playbook: ' + e.message, 'error');
  }
}

// Execute KQL Query via MCP run_kql_query Tool
async function executeKqlQuery() {
  const query = document.getElementById('kql-editor-input').value.trim();
  const resultsContainer = document.getElementById('kql-results-container');
  resultsContainer.innerHTML = '<div class="loading-state"><div class="cyber-spinner"></div><p>Executing KQL via Sentinel MCP...</p></div>';

  try {
    const res = await fetch('/api/kql', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query })
    });
    const data = await res.json();
    
    if (data.results && data.results.length > 0) {
      const keys = Object.keys(data.results[0]);
      let tableHtml = `
        <div style="margin-bottom:8px;color:#34d399;">Table: ${data.table} &bull; Returned ${data.rowCount} rows</div>
        <table class="cyber-table" style="font-size:0.75rem;">
          <thead>
            <tr>${keys.map(k => `<th>${escapeHtml(k)}</th>`).join('')}</tr>
          </thead>
          <tbody>
            ${data.results.map(row => `
              <tr>${keys.map(k => `<td>${escapeHtml(String(row[k] || ''))}</td>`).join('')}</tr>
            `).join('')}
          </tbody>
        </table>
      `;
      resultsContainer.innerHTML = tableHtml;
    } else {
      resultsContainer.innerHTML = `<div class="subtext">Query executed successfully. 0 records returned.</div><pre style="color:#94a3b8;margin-top:8px;">${JSON.stringify(data, null, 2)}</pre>`;
    }
  } catch (err) {
    resultsContainer.innerHTML = `<div class="text-critical">KQL execution error: ${err.message}</div>`;
  }
}

// Load Exposed MCP Tools into Right Panel
async function loadMCPTools() {
  try {
    const res = await fetch('/api/mcp/tools');
    const data = await res.json();
    const container = document.getElementById('tools-list-container');
    const tools = data.tools || [];
    
    container.innerHTML = tools.map(tool => `
      <div class="tool-card">
        <div class="tool-name">${tool.name}</div>
        <div class="tool-desc">${escapeHtml(tool.description)}</div>
      </div>
    `).join('');
  } catch (e) {
    console.error('Failed to load MCP tools list:', e);
  }
}

// Poll & Stream Live JSON-RPC 2.0 Wire Logs
function startWirePolling() {
  setInterval(async () => {
    try {
      const res = await fetch('/api/mcp/logs');
      const data = await res.json();
      const logs = data.logs || [];
      
      if (logs.length !== wireLogsCache.length) {
        wireLogsCache = logs;
        renderWireLogs(logs);
      }
    } catch (e) {
      // Ignore polling errors
    }
  }, 1200);
}

function renderWireLogs(logs) {
  const container = document.getElementById('wire-terminal');
  if (!logs.length) {
    container.innerHTML = '<div class="subtext">Waiting for MCP JSON-RPC protocol traffic...</div>';
    return;
  }

  // Render recent logs (newest at bottom)
  container.innerHTML = logs.slice(-25).map(log => {
    const isOut = log.direction === 'outgoing';
    const arrow = isOut ? '&rarr; Client Request' : '&larr; Server Response';
    const jsonStr = escapeHtml(JSON.stringify(log.data, null, 2));

    return `
      <div class="wire-entry ${log.direction}">
        <div class="wire-entry-header">
          <span class="wire-direction">${arrow}</span>
          <span class="wire-time">${formatTime(log.timestamp)}</span>
        </div>
        <pre class="wire-json">${jsonStr}</pre>
      </div>
    `;
  }).join('');

  // Auto-scroll to bottom
  container.scrollTop = container.scrollHeight;
}

// Export Incident Report as Markdown
function exportIncidentReport() {
  if (!currentAnalysis) {
    showToast('No active incident analysis to export.', 'error');
    return;
  }

  const filename = `Sentinel-Analysis-${currentIncidentId}.md`;
  const reportContent = `# Microsoft Sentinel Incident Analysis Report
**Incident ID:** ${currentIncidentId}
**Title:** ${currentAnalysis.title || 'Security Incident'}
**Severity:** ${currentAnalysis.severity || 'High'}
**Status:** ${currentAnalysis.status || 'Active'}
**Generated:** ${new Date().toISOString()}
**Protocol Source:** Microsoft Sentinel Model Context Protocol (MCP) Server

---

## 1. Executive Summary & Verdict
${currentAnalysis.threatVerdict || 'Malicious Activity Detected'}
${currentAnalysis.narrativeMarkdown || ''}

---

## 2. Indicators of Compromise (IoCs) & Entities
${(currentAnalysis.entities || []).map(e => `- **[${e.type}]** ${e.name} (Risk: ${e.properties?.riskLevel || e.properties?.threatScore || 'Identified'})`).join('\n')}

---

## 3. Correlated Sentinel Security Alerts
${(currentAnalysis.alerts || []).map(a => `- **${a.alertDisplayName}** [${a.severity}] (Provider: ${a.provider})`).join('\n')}

---

## 4. Remediation & Containment Actions Executed
${(currentAnalysis.recommendedActions || []).map(pb => `- **${pb.action}** -> Target: \`${pb.target}\` (${pb.currentStatus || 'Actionable'})`).join('\n')}

---
*Report generated automatically via Microsoft Sentinel MCP Agent GUI.*
`;

  const blob = new Blob([reportContent], { type: 'text/markdown;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast(`Exported ${filename}`, 'success');
}

// Toast Notifications
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 4000);
}

// Simple Markdown to HTML Helper
function parseMarkdownToHtml(md) {
  if (!md) return '';
  let html = escapeHtml(md);

  // Headers
  html = html.replace(/^### (.*$)/gim, '<h4>$1</h4>');
  html = html.replace(/^## (.*$)/gim, '<h3>$1</h3>');
  html = html.replace(/^# (.*$)/gim, '<h2>$1</h2>');

  // Bold & Italic
  html = html.replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>');
  html = html.replace(/\*(.*?)\*/gim, '<em>$1</em>');

  // Inline Code
  html = html.replace(/`([^`]+)`/gim, '<code>$1</code>');

  // Lists
  html = html.replace(/^\- (.*$)/gim, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>)/gim, '<ul>$1</ul>');

  // Line breaks
  html = html.replace(/\n\n/gim, '<br><br>');

  return html;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatTime(isoStr) {
  if (!isoStr) return '';
  const d = new Date(isoStr);
  return d.toTimeString().split(' ')[0] + '.' + String(d.getMilliseconds()).padStart(3, '0');
}
