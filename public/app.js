// Microsoft Sentinel Multi-Collection MCP Hub Frontend Controller
// Supporting:
// 1. Data exploration (https://sentinel.microsoft.com/mcp/data-exploration)
// 2. Security Copilot agent creation (https://sentinel.microsoft.com/mcp/security-copilot-agent-creation)
// 3. Triage (https://sentinel.microsoft.com/mcp/triage)

let currentIncidentId = 'INC-8042';
let activeCollection = 'all';
let allIncidents = [];
let allTools = [];
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
  await loadDataLakeTables('');
  await loadCopilotAgents();
  // Initial prompt triage
  await runPrompt(`Analyze incident ${currentIncidentId} and summarize root cause, blast radius, and containment actions.`);
}

function setupEventListeners() {
  // Collection Tabs in Header
  document.querySelectorAll('.collection-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.collection-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      activeCollection = tab.getAttribute('data-collection');
      onCollectionChanged(activeCollection);
    });
  });

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
      const col = chip.getAttribute('data-col');
      document.getElementById('prompt-input').value = prompt;
      if (col && col !== activeCollection) {
        const matchingTab = document.querySelector(`.collection-tab[data-collection="${col}"]`);
        if (matchingTab) matchingTab.click();
      }
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
      if (targetPane) targetPane.classList.add('active');
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
      if (targetPane) targetPane.classList.add('active');
    });
  });

  // Search & Severity Filter for Incident List
  document.getElementById('incident-search').addEventListener('input', filterIncidents);
  document.querySelectorAll('.severity-pill-group .pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('.severity-pill-group .pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      filterIncidents();
    });
  });

  // Tools collection filter in right panel
  const toolsFilter = document.getElementById('tools-collection-filter');
  toolsFilter.addEventListener('change', () => {
    renderToolsList(toolsFilter.value);
  });

  // Data Lake Table Search
  document.getElementById('btn-search-tables').addEventListener('click', async () => {
    const kw = document.getElementById('de-table-search-input').value.trim();
    await loadDataLakeTables(kw);
  });

  // Copilot Agent Creator Button
  document.getElementById('btn-create-copilot-agent').addEventListener('click', async () => {
    const name = document.getElementById('new-agent-name').value.trim();
    const prompt = document.getElementById('new-agent-prompt').value.trim();
    if (!name || !prompt) {
      showToast('Agent name and workflow prompt required', 'error');
      return;
    }
    await createCopilotAgent(name, prompt);
  });

  // KQL Preset Selector & Execute
  const kqlPreset = document.getElementById('kql-preset-selector');
  kqlPreset.addEventListener('change', () => {
    document.getElementById('kql-editor-input').value = kqlPreset.value;
  });
  document.getElementById('btn-execute-kql').addEventListener('click', executeKqlQuery);

  // Clear Wire Logs Button
  document.getElementById('btn-clear-logs').addEventListener('click', () => {
    document.getElementById('wire-terminal').innerHTML = '<div class="subtext">Logs cleared. Waiting for next MCP message...</div>';
  });

  // Jump to Wire View from Banner
  document.getElementById('btn-view-wire').addEventListener('click', () => {
    const wireTab = document.querySelector('.subtab-btn[data-subtab="subtab-wire"]');
    if (wireTab) wireTab.click();
  });

  // Export Report Button
  document.getElementById('btn-export-report').addEventListener('click', exportIncidentReport);

  // Settings Modal Handlers
  const modal = document.getElementById('settings-modal');
  document.getElementById('btn-open-settings').addEventListener('click', () => modal.classList.add('active'));
  document.getElementById('btn-close-modal').addEventListener('click', () => modal.classList.remove('active'));
  document.getElementById('btn-cancel-settings').addEventListener('click', () => modal.classList.remove('active'));
  document.getElementById('btn-save-settings').addEventListener('click', async () => {
    const mode = document.getElementById('config-mode').value;
    const workspace = document.getElementById('config-workspace').value;
    const rg = document.getElementById('config-rg').value;
    const sub = document.getElementById('config-sub').value;

    try {
      await fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode, azureWorkspaceName: workspace, azureResourceGroup: rg, azureSubscriptionId: sub })
      });
      modal.classList.remove('active');
      showToast('Settings saved successfully', 'success');
      await fetchStatus();
    } catch (e) {
      showToast('Failed to save settings: ' + e.message, 'error');
    }
  });
}

function onCollectionChanged(col) {
  const endpointTag = document.getElementById('active-collection-endpoint');
  const heading = document.getElementById('prompt-assistant-heading');
  const icon = document.getElementById('prompt-collection-icon');

  if (col === 'data-exploration') {
    endpointTag.textContent = 'https://sentinel.microsoft.com/mcp/data-exploration';
    heading.textContent = 'Data Exploration Assistant (Sentinel Lake)';
    icon.textContent = '🔍';
    // Switch to Data Lake tab
    const tab = document.querySelector('.tab-btn[data-tab="tab-data-exploration"]');
    if (tab) tab.click();
  } else if (col === 'security-copilot-agent-creation') {
    endpointTag.textContent = 'https://sentinel.microsoft.com/mcp/security-copilot-agent-creation';
    heading.textContent = 'Security Copilot Agent Creation (NL2Agent)';
    icon.textContent = '🤖';
    // Switch to Copilot Agent tab
    const tab = document.querySelector('.tab-btn[data-tab="tab-copilot-agent"]');
    if (tab) tab.click();
  } else if (col === 'triage') {
    endpointTag.textContent = 'https://sentinel.microsoft.com/mcp/triage';
    heading.textContent = 'Incident Triage & Hunting Assistant';
    icon.textContent = '🚨';
    const tab = document.querySelector('.tab-btn[data-tab="tab-narrative"]');
    if (tab) tab.click();
  } else {
    endpointTag.textContent = 'https://sentinel.microsoft.com/mcp/*';
    heading.textContent = 'Sentinel MCP Multi-Collection Hub';
    icon.textContent = '🌐';
  }

  // Also filter right panel tools
  const toolsFilter = document.getElementById('tools-collection-filter');
  toolsFilter.value = col;
  renderToolsList(col);
}

// Fetch System Status
async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    const statusText = document.getElementById('mcp-status-text');
    if (data.status === 'connected') {
      statusText.textContent = `MCP CONNECTED (${data.version})`;
      document.getElementById('mcp-status-pill').className = 'mcp-status-pill connected';
    }
  } catch (err) {
    console.error('Error fetching status:', err);
  }
}

// Load Incidents (Triage Collection)
async function loadIncidents() {
  try {
    const res = await fetch('/api/incidents');
    const data = await res.json();
    allIncidents = data.incidents || [];
    document.getElementById('incident-count-badge').textContent = `${allIncidents.length} Active`;
    renderIncidentList(allIncidents);
  } catch (e) {
    console.error('Error loading incidents:', e);
  }
}

function renderIncidentList(incidents) {
  const container = document.getElementById('incident-list-container');
  if (!incidents.length) {
    container.innerHTML = '<div class="loading-state">No incidents found.</div>';
    return;
  }

  container.innerHTML = incidents.map(inc => {
    const sevClass = `sev-${inc.severity.toLowerCase()}`;
    const isActive = inc.id === currentIncidentId ? 'active' : '';
    const tacticsBadges = (inc.tactics || []).slice(0, 2).map(t => `<span class="inc-tactic-tag">${t}</span>`).join('');

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
    const matchesSearch = inc.id.toLowerCase().includes(query) || inc.title.toLowerCase().includes(query);
    let matchesSev = true;
    if (selectedSev === 'High') matchesSev = inc.severity === 'High' || inc.severity === 'Critical';
    else if (selectedSev === 'Medium') matchesSev = inc.severity === 'Medium';
    return matchesSearch && matchesSev;
  });

  renderIncidentList(filtered);
}

function selectIncident(id) {
  currentIncidentId = id;
  document.getElementById('current-incident-tag').textContent = id;
  document.querySelectorAll('.incident-card').forEach(c => {
    c.classList.toggle('active', c.getAttribute('data-id') === id);
  });
  runPrompt(`Deep analyze incident ${id} and retrieve correlated entities and alerts.`);
}

// Execute Prompt
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
        incidentId: currentIncidentId,
        collection: activeCollection
      })
    });

    const data = await res.json();
    currentAnalysis = data;
    renderAnalysisView(data);
    showToast(`Executed via collection: ${data.collection || 'Sentinel MCP'}`, 'info');
  } catch (err) {
    console.error('Prompt error:', err);
    showToast('Analysis request failed: ' + err.message, 'error');
  } finally {
    btnRun.innerHTML = originalBtnHtml;
    btnRun.disabled = false;
  }
}

function renderAnalysisView(data) {
  if (data.incidentId) {
    currentIncidentId = data.incidentId;
    document.getElementById('current-incident-tag').textContent = data.incidentId;
    document.getElementById('banner-id').textContent = data.incidentId;
  }

  if (data.collection) {
    document.getElementById('banner-collection').textContent = `COLLECTION: ${data.collection.toUpperCase()}`;
  }

  if (data.title) document.getElementById('banner-title').textContent = data.title;
  if (data.severity) {
    const sevBadge = document.getElementById('banner-severity');
    sevBadge.textContent = data.severity.toUpperCase();
    sevBadge.className = `severity-badge sev-${data.severity.toLowerCase()}`;
  }
  if (data.riskScore !== undefined) document.getElementById('metric-risk-score').textContent = data.riskScore;
  if (data.confidenceScore !== undefined) document.getElementById('metric-confidence').textContent = data.confidenceScore + '%';

  const tacticsRow = document.getElementById('banner-tactics');
  const tacticsList = data.mitre?.tactics || [];
  if (Array.isArray(tacticsList)) {
    tacticsRow.innerHTML = tacticsList.map(t => `<span class="tactic-tag">${t}</span>`).join('');
  }

  // Tool calls banner
  const toolBanner = document.getElementById('mcp-tool-banner');
  const toolBannerText = document.getElementById('mcp-tool-banner-text');
  if (data.executedToolCalls && data.executedToolCalls.length > 0) {
    toolBanner.style.display = 'flex';
    const toolNames = data.executedToolCalls.map(tc => `<code>${tc.name}</code>`).join(', ');
    toolBannerText.innerHTML = `Sentinel MCP invoked: ${toolNames}`;
  } else {
    toolBanner.style.display = 'none';
  }

  // Render Subtabs
  renderNarrativeTab(data);
  renderEntitiesTab(data.entities || []);
  renderTimelineTab(data.attackProgression || []);
  renderAlertsTab(data.alerts || []);
  renderPlaybooksTab(data.recommendedActions || [], data.incidentId);

  document.getElementById('tab-entities-count').textContent = (data.entities || []).length;
  document.getElementById('tab-alerts-count').textContent = (data.alerts || []).length;
}

function renderNarrativeTab(data) {
  const verdictTitle = document.getElementById('verdict-title');
  const verdictSummary = document.getElementById('verdict-summary');
  
  if (data.threatVerdict) verdictTitle.textContent = data.threatVerdict;
  if (data.blastRadius) verdictSummary.textContent = `Blast Radius: ${data.blastRadius} | Risk Score: ${data.riskScore}/100`;

  const container = document.getElementById('narrative-content');
  const md = data.narrativeMarkdown || data.summary || 'No narrative generated.';
  container.innerHTML = parseMarkdownToHtml(md);
}

function renderEntitiesTab(entities) {
  const tbody = document.getElementById('entities-table-body');
  if (!entities.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="subtext">No entities extracted.</td></tr>';
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

    const risk = entity.properties?.riskLevel || entity.properties?.threatScore || 'Medium';
    const riskBadge = (risk === 'High' || risk > 80) ? 
      `<span class="severity-badge sev-critical">Risk ${risk}</span>` : 
      `<span class="severity-badge sev-medium">Medium</span>`;

    const context = entity.properties?.threatReputation || entity.properties?.osVersion || 'Verified security asset';

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

// Data Lake Tables (Data exploration collection)
async function loadDataLakeTables(keyword = '') {
  try {
    const res = await fetch('/api/tables/search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ keyword })
    });
    const data = await res.json();
    const container = document.getElementById('data-lake-tables-container');
    const tables = data.tables || [];

    if (!tables.length) {
      container.innerHTML = '<div class="subtext">No tables matched keyword.</div>';
      return;
    }

    container.innerHTML = tables.map(t => `
      <div class="table-card">
        <div>
          <div class="table-name">${t.name}</div>
          <div class="table-category">${t.category}</div>
          <div class="table-desc">${t.description}</div>
          <div class="columns-preview">
            ${(t.columns || []).map(c => `<span class="column-tag">${c.name}</span>`).join('')}
          </div>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="loadKqlQuery('${escapeHtml(t.sampleQuery)}')">
          Load Sample KQL
        </button>
      </div>
    `).join('');
  } catch (e) {
    console.error('Failed to load tables:', e);
  }
}

function loadKqlQuery(query) {
  document.getElementById('kql-editor-input').value = query;
  const kqlTab = document.querySelector('.tab-btn[data-tab="tab-kql"]');
  if (kqlTab) kqlTab.click();
}

// Copilot Agent Builder (Security Copilot agent creation collection)
async function loadCopilotAgents() {
  try {
    const res = await fetch('/api/agent/list');
    const data = await res.json();
    const container = document.getElementById('copilot-agents-container');
    const agents = data.agents || [];

    container.innerHTML = agents.map(a => `
      <div class="copilot-agent-card">
        <div class="agent-title-row">
          <span class="agent-name-text">${escapeHtml(a.name)}</span>
          <span class="agent-status-badge">${a.status}</span>
        </div>
        <div class="agent-desc-text">${escapeHtml(a.description)}</div>
        <div class="subtext" style="color:#c084fc;font-family:var(--font-mono);font-size:0.72rem;">
          Skills: ${(a.capabilities || []).join(', ')}
        </div>
        <pre class="agent-yaml-code">${escapeHtml(a.yamlSpec || '')}</pre>
      </div>
    `).join('');
  } catch (e) {
    console.error('Failed to load copilot agents:', e);
  }
}

async function createCopilotAgent(agentName, workflowPrompt) {
  try {
    showToast(`Creating Security Copilot agent '${agentName}' via MCP...`, 'info');
    const res = await fetch('/api/agent/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agentName, workflowPrompt })
    });
    const data = await res.json();
    showToast(`Agent created successfully!`, 'success');
    await loadCopilotAgents();
  } catch (e) {
    showToast('Failed to create agent: ' + e.message, 'error');
  }
}

// Playbook trigger
async function triggerDirectPlaybook(playbookId, target) {
  try {
    showToast(`Triggering SOAR playbook ${playbookId} on ${target}...`, 'info');
    const res = await fetch('/api/playbook/trigger', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ playbookId, targetEntity: target, incidentId: currentIncidentId })
    });
    const data = await res.json();
    showToast(`Playbook executed! ID: ${data.result?.executionId || 'OK'}`, 'success');
  } catch (e) {
    showToast('Failed to trigger playbook: ' + e.message, 'error');
  }
}

// Execute KQL
async function executeKqlQuery() {
  const query = document.getElementById('kql-editor-input').value.trim();
  const resultsContainer = document.getElementById('kql-results-container');
  resultsContainer.innerHTML = '<div class="loading-state"><div class="cyber-spinner"></div><p>Executing KQL via query_lake...</p></div>';

  try {
    const res = await fetch('/api/kql', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query })
    });
    const data = await res.json();
    
    if (data.results && data.results.length > 0) {
      const keys = Object.keys(data.results[0]);
      resultsContainer.innerHTML = `
        <div style="margin-bottom:8px;color:#34d399;">Table: ${data.resolvedTable} &bull; Returned ${data.rowCount} rows</div>
        <table class="cyber-table" style="font-size:0.75rem;">
          <thead>
            <tr>${keys.map(k => `<th>${escapeHtml(k)}</th>`).join('')}</tr>
          </thead>
          <tbody>
            ${data.results.map(row => `<tr>${keys.map(k => `<td>${escapeHtml(String(row[k] || ''))}</td>`).join('')}</tr>`).join('')}
          </tbody>
        </table>
      `;
    } else {
      resultsContainer.innerHTML = `<div class="subtext">0 records returned.</div><pre style="color:#94a3b8;margin-top:8px;">${JSON.stringify(data, null, 2)}</pre>`;
    }
  } catch (err) {
    resultsContainer.innerHTML = `<div class="text-critical">KQL error: ${err.message}</div>`;
  }
}

// MCP Tools Catalog
async function loadMCPTools() {
  try {
    const res = await fetch('/api/mcp/tools');
    const data = await res.json();
    allTools = data.tools || [];
    document.getElementById('tools-badge-count').textContent = allTools.length;
    renderToolsList('all');
  } catch (e) {
    console.error('Failed to load MCP tools:', e);
  }
}

function renderToolsList(colFilter = 'all') {
  const container = document.getElementById('tools-list-container');
  let tools = allTools;
  if (colFilter !== 'all') {
    tools = allTools.filter(t => t.collection === colFilter);
  }

  container.innerHTML = tools.map(tool => `
    <div class="tool-card">
      <div class="tool-name">${tool.name}</div>
      <div class="tool-collection-tag">${tool.collectionUrl || tool.collection}</div>
      <div class="tool-desc">${escapeHtml(tool.description)}</div>
    </div>
  `).join('');
}

// Wire logs stream
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
    } catch (e) {}
  }, 1200);
}

function renderWireLogs(logs) {
  const container = document.getElementById('wire-terminal');
  if (!logs.length) return;

  container.innerHTML = logs.slice(-25).map(log => {
    const isOut = log.direction === 'outgoing';
    const arrow = isOut ? '&rarr; Client Request' : '&larr; Server Response';
    return `
      <div class="wire-entry ${log.direction}">
        <div class="wire-entry-header">
          <span class="wire-direction">${arrow}</span>
          <span class="wire-time">${formatTime(log.timestamp)}</span>
        </div>
        <pre class="wire-json">${escapeHtml(JSON.stringify(log.data, null, 2))}</pre>
      </div>
    `;
  }).join('');
  container.scrollTop = container.scrollHeight;
}

// Export Report
function exportIncidentReport() {
  if (!currentAnalysis) {
    showToast('No active incident analysis to export.', 'error');
    return;
  }
  const filename = `Sentinel-Analysis-${currentIncidentId}.md`;
  const reportContent = `# Microsoft Sentinel Incident Analysis Report
**Incident ID:** ${currentIncidentId}
**Collection:** ${currentAnalysis.collection || 'Triage'} (${currentAnalysis.collectionUrl || 'https://sentinel.microsoft.com/mcp'})
**Title:** ${currentAnalysis.title || 'Security Incident'}
**Severity:** ${currentAnalysis.severity || 'High'}
**Generated:** ${new Date().toISOString()}

---

## 1. Executive Summary & Verdict
${currentAnalysis.threatVerdict || 'Malicious Activity Detected'}
${currentAnalysis.narrativeMarkdown || ''}

---

## 2. Indicators of Compromise (IoCs) & Entities
${(currentAnalysis.entities || []).map(e => `- **[${e.type}]** ${e.name}`).join('\n')}

---

## 3. Correlated Sentinel Security Alerts
${(currentAnalysis.alerts || []).map(a => `- **${a.alertDisplayName}** [${a.severity}]`).join('\n')}
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

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

function parseMarkdownToHtml(md) {
  if (!md) return '';
  let html = escapeHtml(md);
  html = html.replace(/^### (.*$)/gim, '<h4>$1</h4>');
  html = html.replace(/^## (.*$)/gim, '<h3>$1</h3>');
  html = html.replace(/^# (.*$)/gim, '<h2>$1</h2>');
  html = html.replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>');
  html = html.replace(/\*(.*?)\*/gim, '<em>$1</em>');
  html = html.replace(/`([^`]+)`/gim, '<code>$1</code>');
  html = html.replace(/^\- (.*$)/gim, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>)/gim, '<ul>$1</ul>');
  html = html.replace(/\n\n/gim, '<br><br>');
  return html;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function formatTime(isoStr) {
  if (!isoStr) return '';
  const d = new Date(isoStr);
  return d.toTimeString().split(' ')[0] + '.' + String(d.getMilliseconds()).padStart(3, '0');
}
