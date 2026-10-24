// Model Context Protocol (MCP) Client
// Communicates with the Sentinel MCP Server over JSON-RPC 2.0 stdio

const { spawn } = require('child_process');
const path = require('path');
const readline = require('readline');
const EventEmitter = require('events');

class MCPClient extends EventEmitter {
  constructor() {
    super();
    this.process = null;
    this.requestId = 1;
    this.pendingRequests = new Map();
    this.wireLogs = [];
    this.maxLogs = 80;
    this.isReady = false;
    this.serverCapabilities = null;
    this.availableTools = [];
  }

  logWire(direction, data) {
    const logEntry = {
      id: Date.now() + '-' + Math.random().toString(36).substring(2, 7),
      timestamp: new Date().toISOString(),
      direction, // 'outgoing' or 'incoming'
      data
    };
    this.wireLogs.push(logEntry);
    if (this.wireLogs.length > this.maxLogs) {
      this.wireLogs.shift();
    }
    this.emit('wire', logEntry);
  }

  getLogs() {
    return this.wireLogs;
  }

  async connect() {
    return new Promise((resolve, reject) => {
      const serverPath = path.join(__dirname, '..', 'mcp', 'sentinel_mcp_server.js');
      this.process = spawn('node', [serverPath], {
        stdio: ['pipe', 'pipe', 'pipe']
      });

      const rl = readline.createInterface({
        input: this.process.stdout,
        terminal: false
      });

      rl.on('line', (line) => {
        const trimmed = line.trim();
        if (!trimmed) return;
        try {
          const message = JSON.parse(trimmed);
          this.logWire('incoming', message);
          if (message.id !== undefined && this.pendingRequests.has(message.id)) {
            const { resolve: reqResolve, reject: reqReject } = this.pendingRequests.get(message.id);
            this.pendingRequests.delete(message.id);
            if (message.error) {
              reqReject(new Error(message.error.message || 'JSON-RPC Error'));
            } else {
              reqResolve(message.result);
            }
          }
        } catch (e) {
          console.error('[MCP Client] Error parsing incoming line:', e, trimmed);
        }
      });

      this.process.stderr.on('data', (data) => {
        console.error('[MCP Server stderr]:', data.toString());
      });

      this.process.on('error', (err) => {
        console.error('[MCP Server Process Error]:', err);
        reject(err);
      });

      this.process.on('close', (code) => {
        console.log('[MCP Server Process Closed] code:', code);
        this.isReady = false;
      });

      // Initialize handshake
      this.sendRequest('initialize', {
        protocolVersion: '2024-11-05',
        clientInfo: {
          name: 'sentinel-soc-web-client',
          version: '1.0.0'
        },
        capabilities: {}
      }).then(async (initResult) => {
        this.serverCapabilities = initResult.capabilities;
        // Fetch tools list
        const toolsResult = await this.sendRequest('tools/list', {});
        this.availableTools = toolsResult.tools || [];
        this.isReady = true;
        resolve({
          serverInfo: initResult.serverInfo,
          toolsCount: this.availableTools.length
        });
      }).catch(reject);
    });
  }

  sendRequest(method, params = {}) {
    return new Promise((resolve, reject) => {
      if (!this.process || !this.process.stdin.writable) {
        return reject(new Error('MCP Server process is not connected or writable.'));
      }
      const id = ++this.requestId;
      const payload = {
        jsonrpc: '2.0',
        id,
        method,
        params
      };

      this.pendingRequests.set(id, { resolve, reject });
      this.logWire('outgoing', payload);
      this.process.stdin.write(JSON.stringify(payload) + '\n');
    });
  }

  async listTools() {
    const res = await this.sendRequest('tools/list', {});
    this.availableTools = res.tools || [];
    return this.availableTools;
  }

  async callTool(name, args = {}) {
    const res = await this.sendRequest('tools/call', {
      name,
      arguments: args
    });

    if (res.isError) {
      const errText = res.content && res.content[0] ? res.content[0].text : 'Tool error';
      throw new Error(errText);
    }

    if (res.content && res.content[0] && res.content[0].type === 'text') {
      try {
        return JSON.parse(res.content[0].text);
      } catch (e) {
        return res.content[0].text;
      }
    }
    return res;
  }
}

module.exports = MCPClient;
