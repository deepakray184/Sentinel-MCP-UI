// Sentinel SOC Dashboard & Multi-Collection MCP Web Server
// Supports the 3 official Microsoft Sentinel MCP Collections:
// 1. Data exploration (https://sentinel.microsoft.com/mcp/data-exploration)
// 2. Security Copilot agent creation (https://sentinel.microsoft.com/mcp/security-copilot-agent-creation)
// 3. Triage (https://sentinel.microsoft.com/mcp/triage)

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const MCPClient = require('./mcp_client');
const PromptOrchestrator = require('./prompt_orchestrator');

const PORT = process.env.PORT || 3333;
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const mcpClient = new MCPClient();
const orchestrator = new PromptOrchestrator(mcpClient);

const serverConfig = {
  mode: 'Sentinel Emulated (High Fidelity)',
  azureTenantId: '',
  azureClientId: '',
  azureSubscriptionId: '',
  azureResourceGroup: 'rg-sentinel-prod',
  azureWorkspaceName: 'law-sentinel-cyber-ops',
  mcpServerVersion: '2.0.0',
  collections: [
    {
      id: 'data-exploration',
      name: 'Data exploration',
      description: 'Explore security data in Microsoft Sentinel data lake by searching for relevant tables, querying the lake, and analyzing entities',
      serverUrl: 'https://sentinel.microsoft.com/mcp/data-exploration'
    },
    {
      id: 'security-copilot-agent-creation',
      name: 'Security Copilot agent creation',
      description: 'Create Microsoft Security Copilot agents for complex workflows',
      serverUrl: 'https://sentinel.microsoft.com/mcp/security-copilot-agent-creation'
    },
    {
      id: 'triage',
      name: 'Triage',
      description: 'Triage incidents rapidly and hunt over your own data easily',
      serverUrl: 'https://sentinel.microsoft.com/mcp/triage'
    }
  ],
  connectedSince: new Date().toISOString()
};

const MIME_TYPES = {
  '.html': 'text/html; charset=UTF-8',
  '.css': 'text/css; charset=UTF-8',
  '.js': 'application/javascript; charset=UTF-8',
  '.json': 'application/json; charset=UTF-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(JSON.stringify(data));
}

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 5 * 1024 * 1024) reject(new Error('Body payload too large'));
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        reject(new Error('Invalid JSON payload'));
      }
    });
    req.on('error', reject);
  });
}

function serveStatic(res, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('404 Not Found');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('500 Server Error: ' + err.code);
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    }
  });
}

const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    res.end();
    return;
  }

  try {
    // API: System Status & Collections Overview
    if (pathname === '/api/status' && req.method === 'GET') {
      return sendJson(res, 200, {
        status: mcpClient.isReady ? 'connected' : 'connecting',
        serverName: 'Microsoft Sentinel MCP Server (Multi-Collection)',
        version: serverConfig.mcpServerVersion,
        mode: serverConfig.mode,
        workspace: serverConfig.azureWorkspaceName,
        availableToolsCount: mcpClient.availableTools.length,
        collections: serverConfig.collections,
        connectedSince: serverConfig.connectedSince,
        protocol: 'MCP 2024-11-05 (JSON-RPC 2.0)'
      });
    }

    if (pathname === '/api/mcp/collections' && req.method === 'GET') {
      const collectionsRes = await mcpClient.callTool('get_available_collections', {});
      return sendJson(res, 200, collectionsRes);
    }

    // API: Incidents List (Triage Collection)
    if (pathname === '/api/incidents' && req.method === 'GET') {
      const severity = parsedUrl.query.severity || 'All';
      const status = parsedUrl.query.status || 'All';
      const result = await mcpClient.callTool('ListIncidents', { severity, status });
      return sendJson(res, 200, result);
    }

    if (pathname.startsWith('/api/incidents/') && req.method === 'GET') {
      const incidentId = pathname.replace('/api/incidents/', '');
      const details = await mcpClient.callTool('GetIncidentById', { incidentId });
      const entities = await mcpClient.callTool('get_incident_entities', { incidentId });
      const alerts = await mcpClient.callTool('ListAlerts', { incidentId });
      const mitre = await mcpClient.callTool('get_mitre_mapping', { incidentId });

      return sendJson(res, 200, {
        details,
        entities: entities.entities || [],
        alerts: alerts.alerts || [],
        mitre
      });
    }

    // API: Tools List (optionally filtered by collection)
    if (pathname === '/api/mcp/tools' && req.method === 'GET') {
      const collection = parsedUrl.query.collection || null;
      let tools = await mcpClient.listTools();
      if (collection && collection !== 'all') {
        tools = tools.filter(t => t.collection === collection);
      }
      return sendJson(res, 200, { tools, total: tools.length });
    }

    // API: Execute Raw MCP Tool
    if (pathname === '/api/mcp/call' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      const { name, arguments: args } = body;
      if (!name) return sendJson(res, 400, { error: 'Tool name is required.' });
      const result = await mcpClient.callTool(name, args || {});
      return sendJson(res, 200, { result });
    }

    // API: Wire Logs Stream
    if (pathname === '/api/mcp/logs' && req.method === 'GET') {
      return sendJson(res, 200, { logs: mcpClient.getLogs() });
    }

    // API: Natural Language Prompt Orchestrator
    if (pathname === '/api/prompt' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      const { prompt, incidentId, collection } = body;
      if (!prompt) return sendJson(res, 400, { error: 'Prompt is required.' });

      const analysisReport = await orchestrator.processPrompt(prompt, incidentId, collection);
      return sendJson(res, 200, analysisReport);
    }

    // API: Data Exploration - Table Search
    if (pathname === '/api/tables/search' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      const result = await mcpClient.callTool('search_tables', { keyword: body.keyword || '' });
      return sendJson(res, 200, result);
    }

    // API: Data Exploration - Entity Analysis
    if (pathname === '/api/entity/analyze' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      if (body.type === 'url') {
        const result = await mcpClient.callTool('analyze_url_entity', { url: body.target });
        return sendJson(res, 200, result);
      } else {
        const result = await mcpClient.callTool('analyze_user_entity', { userPrincipalName: body.target });
        return sendJson(res, 200, result);
      }
    }

    // API: Security Copilot Agent Creation
    if (pathname === '/api/agent/create' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      const result = await mcpClient.callTool('create_security_copilot_agent', {
        agentName: body.agentName || 'Custom-Agent',
        workflowPrompt: body.workflowPrompt || '',
        skills: body.skills || []
      });
      return sendJson(res, 200, result);
    }

    if (pathname === '/api/agent/list' && req.method === 'GET') {
      const result = await mcpClient.callTool('list_copilot_agents', {});
      return sendJson(res, 200, result);
    }

    // API: Playbook Trigger
    if (pathname === '/api/playbook/trigger' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      const { playbookId, targetEntity, incidentId } = body;
      const result = await mcpClient.callTool('trigger_playbook', {
        playbookId,
        targetEntity,
        incidentId
      });
      return sendJson(res, 200, { result });
    }

    // API: Query Lake / KQL
    if (pathname === '/api/kql' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      const { query } = body;
      const result = await mcpClient.callTool('query_lake', { query: query || 'SecurityAlert | take 10' });
      return sendJson(res, 200, result);
    }

    // API: Config
    if (pathname === '/api/config' && req.method === 'GET') {
      return sendJson(res, 200, serverConfig);
    }

    if (pathname === '/api/config' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      Object.assign(serverConfig, body);
      return sendJson(res, 200, { message: 'Configuration updated', config: serverConfig });
    }

    // Static Web Serving
    let safePath = path.normalize(pathname).replace(/^(\.\.[\/\\])+/, '');
    if (safePath === '/' || safePath === '') safePath = '/index.html';
    const targetFile = path.join(PUBLIC_DIR, safePath);
    return serveStatic(res, targetFile);

  } catch (err) {
    console.error('Server request error:', err);
    return sendJson(res, 500, { error: err.message });
  }
});

async function startServer() {
  console.log('Connecting to Multi-Collection Sentinel MCP Server...');
  try {
    const connInfo = await mcpClient.connect();
    console.log(`Connected to MCP Server: ${connInfo.serverInfo.name} v${connInfo.serverInfo.version} (${connInfo.toolsCount} tools across 3 collections ready)`);
  } catch (e) {
    console.error('Failed to establish MCP connection at startup:', e);
  }

  server.listen(PORT, '127.0.0.1', () => {
    console.log(`=======================================================`);
    console.log(` Microsoft Sentinel Multi-Collection MCP Hub`);
    console.log(` Collections: Data exploration, Agent creation, Triage`);
    console.log(` Running at: http://localhost:${PORT}`);
    console.log(`=======================================================`);
  });
}

if (require.main === module) {
  startServer();
}

module.exports = { server, startServer, mcpClient };
