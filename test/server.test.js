const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const net = require('node:net');
const path = require('node:path');
const { after, before, test } = require('node:test');
const { getTokenExchangeAuthError, isAllowedMicrosoftEmail } = require('../src/microsoft-auth');

const rootDirectory = path.resolve(__dirname, '..');
let serverProcess;
let baseUrl;
let serverPort;
let serverOutput = '';

before(async () => {
    serverPort = await getAvailablePort();
    baseUrl = `http://localhost:${serverPort}`;
    serverProcess = spawn(process.execPath, ['src/server.js'], {
        cwd: rootDirectory,
        env: {
            ...process.env,
            NODE_ENV: 'test',
            HOST: '127.0.0.1',
            PORT: String(serverPort),
            TRUST_PROXY_HOPS: '0',
            OPENAI_API_KEY: '',
            MICROSOFT_CLIENT_ID: '11111111-1111-4111-8111-111111111111',
            MICROSOFT_CLIENT_SECRET: 'test-secret',
            MICROSOFT_TENANT_ID: '22222222-2222-4222-8222-222222222222',
            MICROSOFT_REDIRECT_URI: 'http://localhost:3000/auth/callback',
            MICROSOFT_ALLOWED_EMAIL_DOMAINS: '',
            PENTEST_ALLOWED_HOSTS: ''
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

test('local IP address is redirected to canonical localhost origin', async () => {
    const response = await fetch(`http://127.0.0.1:${serverPort}/`, { redirect: 'manual' });

    assert.equal(response.status, 308);
    assert.equal(response.headers.get('location'), `http://localhost:${serverPort}/`);
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

test('Microsoft callback directs expired state to a safe retry message', async () => {
    const response = await fetch(`${baseUrl}/auth/callback?state=expired-test`, { redirect: 'manual' });

    assert.equal(response.status, 302);
    assert.equal(response.headers.get('location'), '/?authError=expired');
});

test('Microsoft invalid client error maps to a safe actionable reason', () => {
    assert.equal(getTokenExchangeAuthError('invalid_client'), 'invalid_client');
    assert.equal(getTokenExchangeAuthError('invalid_grant'), 'token_exchange');
    assert.equal(getTokenExchangeAuthError('invalid_client\nsecret'), 'token_exchange');
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

const { isHostAllowed, parseZapReport, validatePentestTarget } = require('../src/scanners');

test('pentest allowlist matches exact hosts and subdomain wildcards only', () => {
    const allowed = ['app.homolog.local', '*.homologacao.greylogix.com.br'];

    assert.equal(isHostAllowed('app.homolog.local', allowed), true);
    assert.equal(isHostAllowed('APP.HOMOLOG.LOCAL', allowed), true);
    assert.equal(isHostAllowed('crm.homologacao.greylogix.com.br', allowed), true);
    assert.equal(isHostAllowed('homologacao.greylogix.com.br', allowed), false);
    assert.equal(isHostAllowed('evilhomologacao.greylogix.com.br', allowed), false);
    assert.equal(isHostAllowed('crm.homologacao.greylogix.com.br.evil.test', allowed), false);
    assert.equal(isHostAllowed('greylogix.com.br', allowed), false);
});

test('pentest target validation refuses when no allowlist is configured or host is not listed', () => {
    const previous = process.env.PENTEST_ALLOWED_HOSTS;
    try {
        delete process.env.PENTEST_ALLOWED_HOSTS;
        assert.equal(validatePentestTarget('https://app.homolog.local').status, 503);

        process.env.PENTEST_ALLOWED_HOSTS = 'app.homolog.local';
        assert.equal(validatePentestTarget('https://app.homolog.local/login#x').url, 'https://app.homolog.local/login');
        assert.equal(validatePentestTarget('https://www.google.com').status, 403);
        assert.ok(validatePentestTarget('https://user:pass@app.homolog.local').error);
        assert.ok(validatePentestTarget('ftp://app.homolog.local').error);
        assert.ok(validatePentestTarget('not a url').error);
    } finally {
        if (previous === undefined) delete process.env.PENTEST_ALLOWED_HOSTS;
        else process.env.PENTEST_ALLOWED_HOSTS = previous;
    }
});

test('ZAP report alerts are mapped to severities and false positives are dropped', () => {
    const { findings, urlsTested } = parseZapReport({
        '@version': '2.16.0',
        site: [{
            '@name': 'https://app.homolog.local',
            alerts: [
                { pluginid: '10038', name: 'CSP Header Not Set', riskcode: '2', confidence: '3', desc: '<p>No <b>CSP</b></p>', solution: '<p>Set CSP</p>', cweid: '693', instances: [{ uri: 'https://app.homolog.local/', method: 'GET' }] },
                { pluginid: '40012', name: 'Cross Site Scripting (Reflected)', riskcode: '3', confidence: '2', desc: 'XSS', instances: [{ uri: 'https://app.homolog.local/search?q=x', method: 'GET', param: 'q', evidence: '<script>' }] },
                { pluginid: '1', name: 'False positive', riskcode: '3', confidence: '0', instances: [] }
            ]
        }]
    });

    assert.equal(findings.length, 2);
    assert.equal(findings[0].severity, 'high');
    assert.equal(findings[0].source, 'zap');
    assert.match(findings[0].evidence, /parâmetro: q/);
    assert.equal(findings[1].severity, 'medium');
    assert.equal(findings[1].description.includes('<p>'), false);
    assert.equal(urlsTested, 2);
});

test('health reports pentest as disabled without an allowlist', async () => {
    const body = await (await fetch(`${baseUrl}/api/health`)).json();
    assert.equal(body.pentestConfigured, false);
});
