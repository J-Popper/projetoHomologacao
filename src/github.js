// Integração OAuth com o GitHub (conta corporativa) para analisar repositórios privados.
// O token de acesso fica somente na sessão do servidor (memória) e nunca é enviado ao navegador.
const apiBase = 'https://api.github.com';
const userAgent = 'Sentinela-AppSec-Triage';

function getGithubConfigurationError() {
    const { GITHUB_CLIENT_ID: clientId, GITHUB_CLIENT_SECRET: clientSecret, GITHUB_REDIRECT_URI: redirectUri } = process.env;
    if (!clientId?.trim() && !clientSecret?.trim() && !redirectUri?.trim()) return 'not_configured';
    const missing = [['GITHUB_CLIENT_ID', clientId], ['GITHUB_CLIENT_SECRET', clientSecret], ['GITHUB_REDIRECT_URI', redirectUri]]
        .filter(([, value]) => !value?.trim()).map(([key]) => key);
    if (missing.length) return `Preencha no servidor: ${missing.join(', ')}.`;
    let callback;
    try {
        callback = new URL(redirectUri);
    } catch {
        return 'GITHUB_REDIRECT_URI precisa ser uma URL válida terminada em /auth/github/callback.';
    }
    const localHttp = ['localhost', '127.0.0.1', '[::1]'].includes(callback.hostname);
    if ((callback.protocol !== 'https:' && !(callback.protocol === 'http:' && localHttp)) || callback.pathname !== '/auth/github/callback' || callback.search || callback.hash) {
        return 'GITHUB_REDIRECT_URI deve ser HTTPS e terminar em /auth/github/callback; HTTP só é permitido em localhost.';
    }
    return null;
}

function getGithubConfig() {
    if (getGithubConfigurationError()) return null;
    return {
        clientId: process.env.GITHUB_CLIENT_ID.trim(),
        clientSecret: process.env.GITHUB_CLIENT_SECRET.trim(),
        redirectUri: process.env.GITHUB_REDIRECT_URI.trim(),
        allowedOrgs: getAllowedOrgs(),
        required: process.env.GITHUB_LOGIN_REQUIRED === 'true'
    };
}

function getAllowedOrgs() {
    return (process.env.GITHUB_ALLOWED_ORGS || '').split(',').map((org) => org.trim().toLowerCase()).filter(Boolean);
}

function buildAuthorizeUrl(config, state, challenge) {
    const url = new URL('https://github.com/login/oauth/authorize');
    url.search = new URLSearchParams({
        client_id: config.clientId,
        redirect_uri: config.redirectUri,
        // "repo" é o único escopo do GitHub OAuth que permite ler repositórios privados.
        // O Sentinela só executa leituras (listar repositórios e baixar o zip).
        scope: 'repo read:org read:user user:email',
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        allow_signup: 'false'
    }).toString();
    return url.toString();
}

async function exchangeCode(config, code, verifier) {
    const response = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': userAgent },
        body: new URLSearchParams({
            client_id: config.clientId,
            client_secret: config.clientSecret,
            code,
            redirect_uri: config.redirectUri,
            code_verifier: verifier
        }),
        signal: AbortSignal.timeout(15000)
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || typeof data.access_token !== 'string') {
        const error = new Error(`GitHub recusou a troca do código (${typeof data.error === 'string' ? data.error.slice(0, 60) : response.status}).`);
        error.status = 502;
        throw error;
    }
    return { token: data.access_token, scopes: String(data.scope || '').split(',').filter(Boolean) };
}

async function githubApi(token, pathname, { allow404 = false } = {}) {
    const response = await fetch(new URL(pathname, apiBase), {
        headers: {
            Accept: 'application/vnd.github+json',
            Authorization: `Bearer ${token}`,
            'User-Agent': userAgent,
            'X-GitHub-Api-Version': '2022-11-28'
        },
        signal: AbortSignal.timeout(15000)
    });
    if (allow404 && response.status === 404) return null;
    if (response.status === 401) {
        const error = new Error('A conexão com o GitHub expirou ou foi revogada. Conecte o GitHub novamente.');
        error.status = 401;
        error.githubUnauthorized = true;
        throw error;
    }
    if (!response.ok) {
        const error = new Error(`O GitHub respondeu com status ${response.status}.`);
        error.status = 502;
        throw error;
    }
    return response.json();
}

async function getAuthenticatedUser(token) {
    const user = await githubApi(token, '/user');
    const orgs = await githubApi(token, '/user/orgs?per_page=100').catch(() => []);
    return {
        login: user.login,
        name: user.name || '',
        avatarUrl: user.avatar_url || '',
        orgs: orgs.map((org) => String(org.login).toLowerCase())
    };
}

// E-mails verificados da conta GitHub (escopo user:email).
async function getVerifiedEmails(token) {
    const emails = await githubApi(token, '/user/emails?per_page=100');
    return (Array.isArray(emails) ? emails : [])
        .filter((item) => item.verified === true && typeof item.email === 'string')
        .map((item) => item.email.trim().toLowerCase());
}

// A conta GitHub só é aceita se tiver, verificado, o mesmo e-mail do login Microsoft
// (ex.: pessoa@greylogix.com.br). Sem e-mail Microsoft (conta admin local), exige um
// e-mail verificado de um domínio autorizado.
function findMatchingEmail(verifiedEmails, sessionEmail, allowedDomains = []) {
    const normalized = verifiedEmails.map((email) => String(email).trim().toLowerCase());
    const target = String(sessionEmail || '').trim().toLowerCase();
    if (target.includes('@')) return normalized.includes(target) ? target : null;
    return normalized.find((email) => {
        const at = email.lastIndexOf('@');
        return at > 0 && at === email.indexOf('@') && allowedDomains.includes(email.slice(at + 1));
    }) || null;
}

function isAllowedGithubUser(githubUser, allowedOrgs) {
    if (!allowedOrgs.length) return true;
    return githubUser.orgs.some((org) => allowedOrgs.includes(org));
}

async function listRepositories(token, allowedOrgs = []) {
    const repositories = [];
    for (let page = 1; page <= 5; page += 1) {
        const batch = await githubApi(token, `/user/repos?per_page=100&page=${page}&sort=pushed&affiliation=owner,collaborator,organization_member`);
        repositories.push(...batch);
        if (batch.length < 100) break;
    }
    return repositories
        .filter((repo) => !allowedOrgs.length || allowedOrgs.includes(String(repo.owner?.login).toLowerCase()))
        .map((repo) => ({
            fullName: repo.full_name,
            private: Boolean(repo.private),
            description: repo.description || '',
            defaultBranch: repo.default_branch,
            pushedAt: repo.pushed_at,
            url: repo.html_url
        }));
}

// Metadados usados para sugerir o responsável pelo projeto.
async function getRepositoryMetadata(token, owner, name) {
    const base = `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`;
    const repo = await githubApi(token, base, { allow404: true });
    if (!repo) return null;
    const [contributors, commits] = await Promise.all([
        githubApi(token, `${base}/contributors?per_page=5`).catch(() => []),
        githubApi(token, `${base}/commits?per_page=10`).catch(() => [])
    ]);
    return {
        fullName: repo.full_name,
        private: Boolean(repo.private),
        description: repo.description || '',
        ownerLogin: repo.owner?.login || owner,
        ownerType: repo.owner?.type || '',
        defaultBranch: repo.default_branch,
        topContributors: (Array.isArray(contributors) ? contributors : []).map((item) => `${item.login} (${item.contributions} commits)`),
        recentCommitAuthors: [...new Set((Array.isArray(commits) ? commits : [])
            .map((commit) => commit.commit?.author?.name && `${commit.commit.author.name}${commit.author?.login ? ` (@${commit.author.login})` : ''}`)
            .filter(Boolean))].slice(0, 5)
    };
}

async function revokeToken(token) {
    const config = getGithubConfig();
    if (!config || !token) return;
    try {
        await fetch(`${apiBase}/applications/${encodeURIComponent(config.clientId)}/token`, {
            method: 'DELETE',
            headers: {
                Accept: 'application/vnd.github+json',
                Authorization: `Basic ${Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64')}`,
                'Content-Type': 'application/json',
                'User-Agent': userAgent
            },
            body: JSON.stringify({ access_token: token }),
            signal: AbortSignal.timeout(10000)
        });
    } catch {
        // A revogação é melhor esforço; a sessão local é descartada de qualquer forma.
    }
}

module.exports = {
    getGithubConfig,
    getGithubConfigurationError,
    buildAuthorizeUrl,
    exchangeCode,
    getAuthenticatedUser,
    isAllowedGithubUser,
    getVerifiedEmails,
    findMatchingEmail,
    listRepositories,
    getRepositoryMetadata,
    revokeToken
};
