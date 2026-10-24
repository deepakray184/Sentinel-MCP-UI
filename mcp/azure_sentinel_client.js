// Azure Sentinel Live API Client
// Connects to Azure Resource Manager REST API for Microsoft Sentinel & Log Analytics

const https = require('https');

class AzureSentinelClient {
  constructor(config = {}) {
    this.tenantId = config.tenantId || process.env.AZURE_TENANT_ID || '';
    this.clientId = config.clientId || process.env.AZURE_CLIENT_ID || '';
    this.clientSecret = config.clientSecret || process.env.AZURE_CLIENT_SECRET || '';
    this.subscriptionId = config.subscriptionId || process.env.AZURE_SUBSCRIPTION_ID || '';
    this.resourceGroup = config.resourceGroup || process.env.AZURE_RESOURCE_GROUP || '';
    this.workspaceName = config.workspaceName || process.env.AZURE_WORKSPACE_NAME || '';
    this.accessToken = null;
    this.tokenExpiresAt = 0;
  }

  isConfigured() {
    return Boolean(
      this.tenantId &&
      this.clientId &&
      this.clientSecret &&
      this.subscriptionId &&
      this.resourceGroup &&
      this.workspaceName
    );
  }

  async getAccessToken() {
    if (this.accessToken && Date.now() < this.tokenExpiresAt - 60000) {
      return this.accessToken;
    }

    if (!this.tenantId || !this.clientId || !this.clientSecret) {
      throw new Error('Azure credentials not fully configured (Tenant ID, Client ID, Client Secret required).');
    }

    const postData = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: this.clientId,
      client_secret: this.clientSecret,
      scope: 'https://management.azure.com/.default'
    }).toString();

    const options = {
      hostname: 'login.microsoftonline.com',
      port: 443,
      path: `/${this.tenantId}/oauth2/v2.0/token`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postData)
      }
    };

    return new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try {
            const data = JSON.parse(body);
            if (data.access_token) {
              this.accessToken = data.access_token;
              this.tokenExpiresAt = Date.now() + (data.expires_in * 1000);
              resolve(this.accessToken);
            } else {
              reject(new Error(`Azure OAuth failed: ${data.error_description || body}`));
            }
          } catch (e) {
            reject(new Error(`Failed to parse OAuth response: ${e.message}`));
          }
        });
      });

      req.on('error', (err) => reject(err));
      req.write(postData);
      req.end();
    });
  }

  async queryArm(endpoint, method = 'GET', bodyData = null) {
    const token = await this.getAccessToken();
    const options = {
      hostname: 'management.azure.com',
      port: 443,
      path: endpoint,
      method: method,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    };

    return new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try {
            const json = JSON.parse(body);
            if (res.statusCode >= 200 && res.statusCode < 300) {
              resolve(json);
            } else {
              reject(new Error(json.error ? json.error.message : `ARM Request failed with code ${res.statusCode}: ${body}`));
            }
          } catch (e) {
            reject(new Error(`ARM JSON parse error: ${e.message}`));
          }
        });
      });

      req.on('error', (err) => reject(err));
      if (bodyData) {
        req.write(JSON.stringify(bodyData));
      }
      req.end();
    });
  }

  async listIncidents(filter = '') {
    const apiVersion = '2023-11-01-preview';
    let path = `/subscriptions/${this.subscriptionId}/resourceGroups/${this.resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${this.workspaceName}/providers/Microsoft.SecurityInsights/incidents?api-version=${apiVersion}`;
    if (filter) {
      path += `&$filter=${encodeURIComponent(filter)}`;
    }
    return this.queryArm(path);
  }

  async getIncident(incidentId) {
    const apiVersion = '2023-11-01-preview';
    const path = `/subscriptions/${this.subscriptionId}/resourceGroups/${this.resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${this.workspaceName}/providers/Microsoft.SecurityInsights/incidents/${incidentId}?api-version=${apiVersion}`;
    return this.queryArm(path);
  }

  async getIncidentEntities(incidentId) {
    const apiVersion = '2023-11-01-preview';
    const path = `/subscriptions/${this.subscriptionId}/resourceGroups/${this.resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${this.workspaceName}/providers/Microsoft.SecurityInsights/incidents/${incidentId}/entities?api-version=${apiVersion}`;
    return this.queryArm(path, 'POST');
  }

  async getIncidentAlerts(incidentId) {
    const apiVersion = '2023-11-01-preview';
    const path = `/subscriptions/${this.subscriptionId}/resourceGroups/${this.resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${this.workspaceName}/providers/Microsoft.SecurityInsights/incidents/${incidentId}/alerts?api-version=${apiVersion}`;
    return this.queryArm(path, 'POST');
  }

  async executeKql(query, timespan = 'P1D') {
    // Log Analytics Query API
    const token = await this.getAccessToken();
    const bodyData = JSON.stringify({ query, timespan });
    const options = {
      hostname: 'api.loganalytics.io',
      port: 443,
      path: `/v1/workspaces/${this.workspaceName}/query`,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(bodyData)
      }
    };

    return new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try {
            resolve(JSON.parse(body));
          } catch (e) {
            reject(new Error(`KQL response parse error: ${e.message}`));
          }
        });
      });
      req.on('error', (err) => reject(err));
      req.write(bodyData);
      req.end();
    });
  }
}

module.exports = AzureSentinelClient;
