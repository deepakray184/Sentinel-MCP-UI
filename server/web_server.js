// Sentinel SOC Dashboard & Incident Analysis Web Server
// Integrates with Microsoft Sentinel MCP Server

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const MCPClient = require('./mcp_client');
const PromptOrchestrator = require('./prompt_orchestrator');

const PORT = process.env.PORT || 3333;
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

// Initialize MCP Client & Orchestrator
const mcpClient = new MCPClient();
const orchestrator = new PromptOrchestrator(mcpClient);

// Configuration state
const serverConfig = {
  mode: 'Sentinel Emulated (High Fidelity)',
  azureTenantId: '',
  azureClientId: '',
  azureSubscriptionId: '',
  azureResourceGroup: 'rg-sentinel-prod',
  azureWorkspaceName: 'law-sentinel-cyber-ops',
  mcpServerVersion: '1.2.0',
  connectedSince: new Date().toISOString()
};

// MIME types dictionary
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
      if (body.length > 5 * 1024 * 1024) {
        reject(new Error('Body payload too large'));
      }
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

  // Handle CORS Preflight
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
    // API Routes
    if (pathname === '/api/status' && req.method === 'GET') {
      return sendJson(res, 200, {
        status: mcpClient.isReady ? 'connected' : 'connecting',
        serverName: 'Microsoft Sentinel MCP Server',
        version: serverConfig.mcpServerVersion,
        mode: serverConfig.mode,
        workspace: serverConfig.azureWorkspaceName,
        availableToolsCount: mcpClient.availableTools.length,
        connectedSince: serverConfig.connectedSince,
        protocol: 'MCP 2024-11-05 (JSON-RPC 2.0)'
      });
    }

    if (pathname === '/api/incidents' && req.method === 'GET') {
      const severity = parsedUrl.query.severity || 'All';
      const status = parsedUrl.query.status || 'All';
      const result = await mcpClient.callTool('list_incidents', { severity, status });
      return sendJson(res, 200, result);
    }

    if (pathname.startsWith('/api/incidents/') && req.method === 'GET') {
      const incidentId = pathname.replace('/api/incidents/', '');
      const details = await mcpClient.callTool('get_incident_details', { incidentId });
      const entities = await mcpClient.callTool('get_incident_entities', { incidentId });
      const alerts = await mcpClient.callTool('get_incident_alerts', { incidentId });
      const mitre = await mcpClient.callTool('get_mitre_mapping', { incidentId });

      return sendJson(res, 200, {
        details,
        entities: entities.entities || [],
        alerts: alerts.alerts || [],
        mitre
      });
    }

    if (pathname === '/api/mcp/tools' && req.method === 'GET') {
      const tools = await mcpClient.listTools();
      return sendJson(res, 200, { tools });
    }

    if (pathname === '/api/mcp/call' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      const { name, arguments: args } = body;
      if (!name) {
        return sendJson(res, 400, { error: 'Tool name is required.' });
      }
      const result = await mcpClient.callTool(name, args || {});
      return sendJson(res, 200, { result });
    }

    if (pathname === '/api/mcp/logs' && req.method === 'GET') {
      return sendJson(res, 200, { logs: mcpClient.getLogs() });
    }

    if (pathname === '/api/prompt' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      const { prompt, incidentId } = body;
      if (!prompt) {
        return sendJson(res, 400, { error: 'Prompt is required.' });
      }

      const analysisReport = await orchestrator.processPrompt(prompt, incidentId);
      return sendJson(res, 200, analysisReport);
    }

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

    if (pathname === '/api/kql' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      const { query } = body;
      const result = await mcpClient.callTool('run_kql_query', { query: query || 'SecurityAlert | take 10' });
      return sendJson(res, 200, result);
    }

    if (pathname === '/api/incident/update' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      const { incidentId, status, classification, comment } = body;
      const result = await mcpClient.callTool('update_incident_status', {
        incidentId,
        status,
        classification,
        comment
      });
      return sendJson(res, 200, result);
    }

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
    if (safePath === '/' || safePath === '') {
      safePath = '/index.html';
    }
    const targetFile = path.join(PUBLIC_DIR, safePath);
    return serveStatic(res, targetFile);

  } catch (err) {
    console.error('Server request error:', err);
    return sendJson(res, 500, { error: err.message });
  }
});

async function startServer() {
  console.log('Connecting to Sentinel MCP Server child process...');
  try {
    const connInfo = await mcpClient.connect();
    console.log(`Connected to MCP Server: ${connInfo.serverInfo.name} v${connInfo.serverInfo.version} (${connInfo.toolsCount} tools ready)`);
  } catch (e) {
    console.error('Failed to establish MCP connection at startup:', e);
  }

  server.listen(PORT, '127.0.0.1', () => {
    console.log(`=======================================================`);
    console.log(` Microsoft Sentinel MCP Incident Analysis GUI Website`);
    console.log(` Running at: http://localhost:${PORT}`);
    console.log(` MCP Endpoint: stdio JSON-RPC 2.0 (mcp/sentinel_mcp_server.js)`);
    console.log(`=======================================================`);
  });
}

if (require.main === module) {
  startServer();
}

module.exports = { server, startServer, mcpClient };
