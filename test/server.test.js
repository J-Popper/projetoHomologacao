const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const net = require('node:net');
const path = require('node:path');
const { after, before, test } = require('node:test');
const { isAllowedMicrosoftEmail } = require('../src/microsoft-auth');

const rootDirectory = path.resolve(__dirname, '..');
let serverProcess;
let baseUrl;
let serverOutput = '';

before(async () => {
    const port = await getAvailablePort();
    baseUrl = `http://127.0.0.1:${port}`;
    serverProcess = spawn(process.execPath, ['src/server.js'], {
        cwd: rootDirectory,
        env: {
            ...process.env,
            NODE_ENV: 'test',
            HOST: '127.0.0.1',
            PORT: String(port),
            TRUST_PROXY_HOPS: '0',
            OPENAI_API_KEY: '',
            MICROSOFT_CLIENT_ID: '11111111-1111-4111-8111-111111111111',
            MICROSOFT_CLIENT_SECRET: 'test-secret',
            MICROSOFT_TENANT_ID: '22222222-2222-4222-8222-222222222222',
            MICROSOFT_REDIRECT_URI: 'http://localhost:3000/auth/callback',
            MICROSOFT_ALLOWED_EMAIL_DOMAINS: ''
        },
        stdio: ['ignore', 'pipe', 'pipe']
    });
    serverProcess.stdout.setEncoding('utf8').on('data', (chunk) => { serverOutput += chunk; });
    serverProcess.stderr.setEncoding('utf8').on('data', (chunk) => { serverOutput += chunk; });
    serverProcess.once('error', (error) => { serverOutput += error.message; });

    await waitForServer();
});

after(async () => {
    if (!serverProcess || serverProcess.exitCode !== null) return;
    const exited = new Promise((resolve) => serverProcess.once('exit', resolve));
    serverProcess.kill();
    await exited;
});

test('health endpoint reports server availability without exposing secrets', async () => {
    const response = await fetch(`${baseUrl}/api/health`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.ok, true);
    assert.equal(body.aiConfigured, false);
    assert.equal(body.authConfigured, true);
    assert.equal(JSON.stringify(body).includes('OPENAI_API_KEY'), false);
});

test('application page is served', async () => {
    const response = await fetch(`${baseUrl}/`);
    const html = await response.text();

    assert.equal(response.status, 200);
    assert.match(html, /Sentinela \| Análise de segurança/);
});

test('protected API rejects unauthenticated users', async () => {
    const response = await fetch(`${baseUrl}/api/report-prompt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanId: 'unknown' })
    });

    assert.equal(response.status, 401);
});

test('Microsoft sign-in uses the configured tenant and redirect URI', async () => {
    const response = await fetch(`${baseUrl}/auth/microsoft`, { redirect: 'manual' });
    const location = response.headers.get('location');
    const authorizationUrl = new URL(location);

    assert.equal(response.status, 302);
    assert.equal(authorizationUrl.hostname, 'login.microsoftonline.com');
    assert.equal(authorizationUrl.pathname, '/22222222-2222-4222-8222-222222222222/oauth2/v2.0/authorize');
    assert.equal(authorizationUrl.searchParams.get('redirect_uri'), 'http://localhost:3000/auth/callback');
});

test('Microsoft sign-in accepts any email at the Greylogix domain only', () => {
    const allowedDomains = ['greylogix.com.br'];

    assert.equal(isAllowedMicrosoftEmail('colaborador@greylogix.com.br', allowedDomains), true);
    assert.equal(isAllowedMicrosoftEmail('COLABORADOR@GREYLOGIX.COM.BR', allowedDomains), true);
    assert.equal(isAllowedMicrosoftEmail('colaborador@outrodominio.com.br', allowedDomains), false);
    assert.equal(isAllowedMicrosoftEmail('colaborador@greylogix.com.br.evil.test', allowedDomains), false);
    assert.equal(isAllowedMicrosoftEmail('colaborador@sub.greylogix.com.br', allowedDomains), false);
    assert.equal(isAllowedMicrosoftEmail('colaborador@@greylogix.com.br', allowedDomains), false);
});

test('API rejects unapproved cross-origin requests', async () => {
    const response = await fetch(`${baseUrl}/api/health`, {
        headers: { Origin: 'https://untrusted.example' }
    });

    assert.equal(response.status, 403);
});

async function getAvailablePort() {
    const listener = net.createServer();
    await new Promise((resolve, reject) => {
        listener.once('error', reject);
        listener.listen(0, '127.0.0.1', resolve);
    });
    const { port } = listener.address();
    await new Promise((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
    return port;
}

async function waitForServer() {
    const timeoutAt = Date.now() + 10000;
    while (Date.now() < timeoutAt) {
        if (serverProcess.exitCode !== null) {
            throw new Error(`Server exited during startup with code ${serverProcess.exitCode}.`);
        }
        try {
            const response = await fetch(`${baseUrl}/api/health`, { signal: AbortSignal.timeout(1000) });
            if (response.ok) return;
        } catch {
            await new Promise((resolve) => setTimeout(resolve, 100));
        }
    }
    serverProcess.kill();
    throw new Error(`Server did not become ready within 10 seconds.${serverOutput ? ` Output: ${serverOutput}` : ''}`);
}
