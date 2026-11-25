const form = document.querySelector('#scan-form');
const tabs = [...document.querySelectorAll('.source-tab')];
const fileInput = document.querySelector('#zip-file');
const dropzone = document.querySelector('#dropzone');
const fileLabel = document.querySelector('#file-label');
const scanButton = document.querySelector('#scan-button');
const aiStatusHint = document.querySelector('#ai-status-hint');
const resultsSection = document.querySelector('#results');
const toast = document.querySelector('#toast');
const promptPanel = document.querySelector('#prompt-panel');
const claudePrompt = document.querySelector('#claude-prompt');
const authGate = document.querySelector('#auth-gate');
const applicationContent = document.querySelector('#application-content');
const loginLink = document.querySelector('#login-link');
const apiBaseUrl = resolveApiBaseUrl();
let selectedSource = 'zip';
let currentReport = null;
let isAuthenticated = false;
let toastTimer;
const severityLabels = {
    critical: 'Crítica',
    high: 'Alta',
    medium: 'Média',
    low: 'Baixa',
    info: 'Informativa'
};

for (const tab of tabs) {
    tab.addEventListener('click', () => selectSource(tab.id.replace('tab-', '')));
}

const codePrivacyNote = 'Para concluir a análise, o código será enviado à API OpenAI configurada no servidor e verificado com Semgrep, Gitleaks e a base OSV. Envie apenas projetos autorizados. A triagem não substitui revisão especializada.';
const pentestPrivacyNote = 'O OWASP ZAP acessa a URL a partir do servidor do Sentinela. Teste apenas ambientes de homologação autorizados; o modo ativo pode alterar dados da aplicação.';

function selectSource(source) {
    selectedSource = source;
    for (const tab of tabs) {
        const active = tab.id === `tab-${source}`;
        tab.classList.toggle('active', active);
        tab.setAttribute('aria-selected', String(active));
    }
    document.querySelector('#panel-zip').hidden = source !== 'zip';
    document.querySelector('#panel-github').hidden = source !== 'github';
    document.querySelector('#panel-pentest').hidden = source !== 'pentest';
    document.querySelector('#ai-required').hidden = source === 'pentest';
    document.querySelector('#privacy-note').textContent = source === 'pentest' ? pentestPrivacyNote : codePrivacyNote;
    document.querySelector('#mode-note').textContent = source === 'pentest' ? 'Teste dinâmico · aplicação em execução' : 'Análise estática · código não é executado';
    setBusy(false);
}

function isSourceReady() {
    if (!isAuthenticated) return false;
    return selectedSource === 'pentest' ? Boolean(serviceStatus.pentestConfigured) : Boolean(serviceStatus.aiConfigured);
}

fileInput.addEventListener('change', () => {
    const file = fileInput.files[0];
    fileLabel.textContent = file ? `${file.name} · ${formatBytes(file.size)}` : 'Solte o ZIP aqui ou selecione um arquivo';
});

for (const eventName of ['dragenter', 'dragover']) {
    dropzone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropzone.classList.add('dragover');
    });
}
for (const eventName of ['dragleave', 'drop']) {
    dropzone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropzone.classList.remove('dragover');
    });
}
dropzone.addEventListener('drop', (event) => {
    const file = event.dataTransfer.files[0];
    if (!file) return;
    const transfer = new DataTransfer();
    transfer.items.add(file);
    fileInput.files = transfer.files;
    fileInput.dispatchEvent(new Event('change'));
});

form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const options = { method: 'POST', headers: {} };
    let endpoint;
    if (selectedSource === 'pentest') {
        if (!serviceStatus.pentestConfigured) return showToast('O teste dinâmico está desativado. Configure PENTEST_ALLOWED_HOSTS no servidor.');
        const url = document.querySelector('#pentest-url').value.trim();
        if (!url) return showToast('Informe a URL da aplicação em homologação.');
        const authorized = document.querySelector('#pentest-authorized').checked;
        if (!authorized) return showToast('Confirme que você tem autorização para testar este alvo.');
        const mode = document.querySelector('input[name="pentestMode"]:checked')?.value || 'baseline';
        if (mode === 'full' && !window.confirm('O modo ativo envia ataques reais e pode alterar dados da aplicação. Confirma que o alvo é um ambiente de homologação?')) return;
        options.headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify({ url, mode, authorized });
        endpoint = '/api/pentest';
    } else if (!serviceStatus.aiConfigured) {
        return showToast('A análise por IA é obrigatória. Configure OPENAI_API_KEY no servidor e tente novamente.');
    } else if (selectedSource === 'zip') {
        const file = fileInput.files[0];
        if (!file) return showToast('Selecione um arquivo ZIP para continuar.');
        if (!file.name.toLowerCase().endsWith('.zip')) return showToast('O arquivo selecionado precisa ter extensão .zip.');
        if (file.size > 20 * 1024 * 1024) return showToast('O ZIP não pode exceder 20 MB.');
        const data = new FormData();
        data.append('file', file);
        options.body = data;
        endpoint = '/api/scan/zip';
    } else {
        const url = document.querySelector('#github-url').value.trim();
        if (!url) return showToast('Informe a URL do repositório GitHub.');
        options.headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify({ url });
        endpoint = '/api/scan/github';
    }

    setBusy(true, 'Enviando...');
    document.querySelector('#email-status').textContent = '';
    try {
        const { jobId } = await fetchJson(endpoint, options);
        const body = await waitForJob(jobId);
        currentReport = body;
        renderReport(body);
        resultsSection.hidden = false;
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (error) {
        showToast(error.message || 'Falha de conexão com o serviço.');
    } finally {
        setBusy(false);
    }
});

for (const logoutButton of document.querySelectorAll('[data-logout]')) {
    logoutButton.addEventListener('click', async (event) => {
        const button = event.currentTarget;
        button.disabled = true;
        try {
            await fetchJson('/api/auth/logout', { method: 'POST' });
            window.location.assign(`${apiBaseUrl}/`);
        } catch (error) {
            button.disabled = false;
            showToast(error.message || 'Não foi possível encerrar a sessão.');
        }
    });
}

document.querySelector('#local-login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const errorElement = document.querySelector('#local-login-error');
    const submit = event.currentTarget.querySelector('button[type="submit"]');
    errorElement.hidden = true;
    submit.disabled = true;
    try {
        await fetchJson('/api/auth/local', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: document.querySelector('#local-username').value,
                password: document.querySelector('#local-password').value
            })
        }, 15000);
        document.querySelector('#local-password').value = '';
        await loadAuthStatus();
    } catch (error) {
        errorElement.textContent = error.message;
        errorElement.hidden = false;
    } finally {
        submit.disabled = false;
    }
});

document.querySelector('#password-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const errorElement = document.querySelector('#password-error');
    const newPassword = document.querySelector('#new-password').value;
    errorElement.hidden = true;
    if (newPassword !== document.querySelector('#confirm-password').value) {
        errorElement.textContent = 'A confirmação não corresponde à nova senha.';
        errorElement.hidden = false;
        return;
    }
    try {
        await fetchJson('/api/account/password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ currentPassword: document.querySelector('#current-password').value, newPassword })
        }, 15000);
        event.currentTarget.reset();
        showToast('Senha alterada com sucesso.');
        await loadAuthStatus();
    } catch (error) {
        errorElement.textContent = error.message;
        errorElement.hidden = false;
    }
});

let authStatus = null;
let githubRepositories = [];

function showOnly(section) {
    authGate.hidden = section !== 'auth';
    document.querySelector('#password-gate').hidden = section !== 'password';
    document.querySelector('#github-gate').hidden = section !== 'github';
    applicationContent.hidden = section !== 'app';
}

function applyPermissions(status) {
    const role = status.user?.role;
    const badge = document.querySelector('#role-badge');
    badge.textContent = status.user?.roleLabel || '';
    badge.className = `role-badge ${role || ''}`;
    document.querySelector('#admin-link').hidden = !status.permissions?.adminPanel;
    document.querySelector('#admin-link').href = `${apiBaseUrl}/admin`;

    const canActive = Boolean(status.permissions?.activePentest);
    const fullRadio = document.querySelector('#pentest-mode-full');
    fullRadio.disabled = !canActive;
    if (!canActive && fullRadio.checked) document.querySelector('input[name="pentestMode"][value="baseline"]').checked = true;
    document.querySelector('#mode-option-full').classList.toggle('locked', !canActive);
    document.querySelector('#active-lock').hidden = canActive;

    const gh = status.github || {};
    const githubStatus = document.querySelector('#github-status');
    githubStatus.hidden = !gh.configured;
    githubStatus.replaceChildren();
    if (gh.configured) {
        if (gh.connected) {
            const label = document.createElement('span');
            label.textContent = `GitHub: @${gh.login}`;
            const disconnect = document.createElement('button');
            disconnect.type = 'button';
            disconnect.className = 'mini-button';
            disconnect.textContent = 'Desconectar';
            disconnect.addEventListener('click', disconnectGithub);
            githubStatus.append(label, disconnect);
        } else {
            const link = document.createElement('a');
            link.className = 'mini-button';
            link.href = `${apiBaseUrl}/auth/github`;
            link.textContent = 'Conectar GitHub';
            githubStatus.append(link);
        }
    }
    document.querySelector('#github-connect').hidden = !gh.configured || gh.connected;
    document.querySelector('#github-connect-button').href = `${apiBaseUrl}/auth/github`;
    document.querySelector('#github-repo-picker').hidden = !gh.connected;
    document.querySelector('#github-url-hint').textContent = gh.connected
        ? `Usando a conta GitHub @${gh.login}: repositórios privados aos quais você tem acesso podem ser analisados.`
        : 'Sem conta GitHub conectada, apenas repositórios públicos podem ser analisados.';
    if (gh.connected && !githubRepositories.length) loadGithubRepositories();
}

async function disconnectGithub() {
    try {
        await fetchJson('/api/github/disconnect', { method: 'POST' });
        githubRepositories = [];
        showToast('Conta GitHub desconectada e token revogado.');
        await loadAuthStatus();
    } catch (error) {
        showToast(error.message);
    }
}

async function loadGithubRepositories() {
    const hint = document.querySelector('#github-repo-hint');
    hint.textContent = 'Carregando repositórios...';
    try {
        const data = await fetchJson('/api/github/repos', {}, 30000);
        githubRepositories = data.repositories;
        renderRepositoryOptions();
        hint.textContent = githubRepositories.length
            ? `${githubRepositories.length} repositório(s) disponíveis. Selecione um para preencher o endereço.`
            : 'Nenhum repositório disponível para esta conta (ou fora das organizações autorizadas).';
    } catch (error) {
        hint.textContent = error.message;
        if (/conecte|expirou/i.test(error.message)) loadAuthStatus();
    }
}

function renderRepositoryOptions() {
    const filter = document.querySelector('#github-repo-filter').value.trim().toLowerCase();
    const select = document.querySelector('#github-repo-select');
    select.replaceChildren(...githubRepositories
        .filter((repo) => !filter || repo.fullName.toLowerCase().includes(filter) || repo.description.toLowerCase().includes(filter))
        .slice(0, 300)
        .map((repo) => {
            const option = document.createElement('option');
            option.value = repo.url;
            option.textContent = `${repo.private ? '🔒 ' : ''}${repo.fullName}${repo.description ? ` — ${repo.description.slice(0, 80)}` : ''}`;
            return option;
        }));
}

document.querySelector('#github-repo-filter').addEventListener('input', renderRepositoryOptions);
document.querySelector('#github-repo-select').addEventListener('change', (event) => {
    document.querySelector('#github-url').value = event.currentTarget.value;
});

function showGithubCallbackMessage() {
    const params = new URLSearchParams(window.location.search);
    const githubError = params.get('githubError');
    const connected = params.get('github') === 'connected';
    if (!githubError && !connected) return;
    const messages = {
        not_configured: 'O login GitHub não está configurado no servidor (GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_REDIRECT_URI).',
        expired: 'A tentativa de login GitHub expirou. Tente novamente.',
        denied: 'O GitHub não autorizou o acesso. Tente novamente e aprove a solicitação.',
        org_not_allowed: 'Esta conta GitHub não pertence a uma organização autorizada. Use sua conta GitHub corporativa.',
        email_mismatch: 'A conta GitHub precisa ter, verificado, o mesmo e-mail @greylogix.com.br usado no login Microsoft. No GitHub, acesse Settings > Emails, adicione e verifique esse e-mail e tente novamente.',
        login_failed: 'Não foi possível concluir o login GitHub. Confira a configuração do OAuth App no servidor.'
    };
    if (connected) showToast('Conta GitHub conectada.');
    else {
        const message = messages[githubError] || messages.login_failed;
        const gateError = document.querySelector('#github-gate-error');
        gateError.textContent = message;
        gateError.hidden = false;
        showToast(message);
    }
    window.history.replaceState({}, '', window.location.pathname);
}

async function loadAuthStatus() {
    const message = document.querySelector('#auth-message');
    const error = document.querySelector('#auth-error');
    loginLink.href = `${apiBaseUrl}/auth/microsoft`;
    for (const link of document.querySelectorAll('#github-gate a')) link.href = `${apiBaseUrl}/auth/github`;
    const authError = new URLSearchParams(window.location.search).get('authError');
    if (authError) {
        const messages = {
            browser_binding: 'O login começou em um endereço local diferente do callback. Reinicie o login usando http://localhost:3000.',
            configuration: 'A configuração Microsoft do servidor está inválida. Confira o Tenant ID, Client ID e a URI de retorno.',
            expired: 'A tentativa de login expirou ou foi iniciada em outra sessão do navegador. Tente novamente.',
            invalid_client: 'A Microsoft não reconheceu as credenciais do aplicativo. No Entra ID, crie um novo Client Secret e copie o campo Value (não o Secret ID) para MICROSOFT_CLIENT_SECRET no config/.env. Confira também se ele pertence ao aplicativo do MICROSOFT_CLIENT_ID. Reinicie o servidor após atualizar; não compartilhe o segredo.',
            microsoft_denied: 'A Microsoft não concluiu o login. Confira se a conta pertence ao tenant configurado.',
            token_exchange: 'A Microsoft recusou a troca do código de login. Confira as credenciais do aplicativo e a URI de retorno cadastrada.',
            token_response: 'A resposta da Microsoft não continha uma identidade válida. Confira as permissões OpenID do aplicativo.',
            unauthorized_domain: 'O login foi concluído, mas esta conta não pertence a um domínio autorizado.',
            user_disabled: 'Seu acesso ao Sentinela foi bloqueado por um administrador.',
            session_required: 'Entre com sua conta Microsoft antes de conectar o GitHub.',
            forbidden: 'Seu perfil de acesso não permite abrir o painel administrativo.',
            login_failed: 'Não foi possível validar a identidade Microsoft. Reinicie o login e, se persistir, confira o log do backend.'
        };
        error.textContent = messages[authError] || messages.login_failed;
        error.hidden = false;
        if (authError === 'forbidden') showToast(messages.forbidden);
        window.history.replaceState({}, '', window.location.pathname);
    }
    showGithubCallbackMessage();
    try {
        const status = await fetchJson('/api/auth/status', {}, 8000);
        authStatus = status;
        const githubPending = status.authenticated && status.github?.required && !status.github.connected && status.user?.authType !== 'local';
        isAuthenticated = status.authenticated && !status.user?.mustChangePassword && !githubPending;
        showOnly(!status.authenticated ? 'auth' : status.user?.mustChangePassword ? 'password' : githubPending ? 'github' : 'app');
        if (status.authenticated) {
            document.querySelector('#signed-in-user').textContent = status.user?.email || status.user?.name || 'Conta Microsoft';
            applyPermissions(status);
        } else if (!status.authConfigured) {
            message.textContent = 'O acesso está bloqueado até que o login Microsoft seja configurado corretamente no servidor.';
            error.textContent = status.configurationError || 'Confira as variáveis de configuração Microsoft no servidor.';
            error.hidden = false;
            loginLink.setAttribute('aria-disabled', 'true');
            loginLink.classList.add('disabled');
            loginLink.removeAttribute('href');
        }
        setBusy(isBusy);
    } catch {
        isAuthenticated = false;
        showOnly('auth');
        message.textContent = 'Não foi possível verificar a autenticação. O acesso permanece bloqueado.';
        error.textContent = 'Verifique se o backend está ativo e tente recarregar a página.';
        error.hidden = false;
    }
}

let isBusy = false;
function setBusy(busy, label) {
    isBusy = busy;
    scanButton.disabled = busy || !isSourceReady();
    scanButton.querySelector('span').textContent = label || (selectedSource === 'pentest' ? 'Iniciar teste' : 'Iniciar análise');
}

// Acompanha uma tarefa em segundo plano até concluir (análises podem levar vários minutos).
async function waitForJob(jobId) {
    const deadline = Date.now() + 60 * 60 * 1000;
    let failures = 0;
    while (Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 3000));
        let job;
        try {
            job = await fetchJson(`/api/jobs/${encodeURIComponent(jobId)}`, {}, 15000);
            failures = 0;
        } catch (error) {
            if (/não encontrada/i.test(error.message) || ++failures >= 5) throw error;
            continue;
        }
        if (job.status === 'done') return job.report;
        if (job.status === 'error') throw new Error(job.error || 'A análise falhou.');
        const minutes = Math.floor(job.elapsedSeconds / 60);
        const seconds = String(job.elapsedSeconds % 60).padStart(2, '0');
        setBusy(true, `${job.stage} ${minutes}:${seconds}`);
    }
    throw new Error('A análise excedeu 60 minutos. Confira o log do servidor.');
}

function renderReport(report) {
    const verdict = document.querySelector('#verdict');
    const mark = document.querySelector('#verdict-mark');
    const hasHigh = report.counts.critical || report.counts.high;
    const requiresReview = report.recommendation === 'REVISÃO MANUAL';
    verdict.className = `verdict${hasHigh ? ' danger' : requiresReview ? ' review' : ''}`;
    mark.textContent = hasHigh ? '!' : requiresReview ? '!' : '✓';
    document.querySelector('#verdict-title').textContent = report.recommendation;
    document.querySelector('#verdict-description').textContent = report.recommendationDetail;
    document.querySelector('#finding-total').textContent = String(report.findings.length);
    document.querySelector('#scan-meta').textContent = `${report.project} · ${new Date(report.scannedAt).toLocaleString('pt-BR')}`;
    const isPentest = report.kind === 'pentest';
    const profile = report.projectProfile;
    document.querySelector('#project-profile').hidden = !profile || isPentest;
    if (profile) {
        document.querySelector('#profile-description').textContent = profile.description || 'Descrição não disponível.';
        document.querySelector('#profile-responsible').textContent = profile.responsible || 'Não identificado';
        document.querySelector('#profile-responsible').title = profile.responsibleBasis || '';
        document.querySelector('#profile-category').textContent = profile.category || '—';
        document.querySelector('#profile-technologies').textContent = (profile.technologies || []).join(', ') || '—';
    }
    document.querySelector('#findings-summary').textContent = isPentest
        ? `Teste ${report.modeLabel.toLowerCase()} · ${report.urlsTested} URL(s) com alertas`
        : `${report.filesAnalyzed} arquivos analisados`;
    document.querySelector('#report-caveat').textContent = isPentest
        ? 'O teste dinâmico automatizado cobre apenas as páginas que o OWASP ZAP conseguiu alcançar, sem autenticação. Áreas protegidas por login, regras de negócio e falhas de autorização exigem pentest manual. O resultado não substitui revisão especializada.'
        : 'Hospedagem e banco de dados são inferidos pelos arquivos enviados; esta análise não consulta a infraestrutura em produção, não testa conexões nem confirma configurações efetivamente implantadas. O resumo não substitui revisão humana, avaliação de impacto e controles de privacidade e segurança da organização.';

    const metricLabels = [
        ['critical', 'Crítica'], ['high', 'Alta'], ['medium', 'Média'], ['low', 'Baixa'], ['info', 'Informativa']
    ];
    const metrics = document.querySelector('#metrics');
    metrics.replaceChildren(...metricLabels.map(([severity, label]) => {
        const item = document.createElement('div');
        item.className = 'metric';
        const count = document.createElement('strong');
        count.textContent = String(report.counts[severity]);
        const caption = document.createElement('span');
        caption.textContent = label;
        item.append(count, caption);
        return item;
    }));

    const scanNotes = document.querySelector('#scan-notes');
    const coverage = report.aiCoverage;
    const completedChecks = isPentest ? [
        `Teste dinâmico (OWASP ZAP): concluído · modo ${report.modeLabel}`,
        `Alvo: ${report.target}`
    ] : [
        `Regras estáticas: concluídas`,
        `Semgrep (SAST): ${report.checks.semgrep ? 'concluído' : 'não executado'}`,
        `Gitleaks (segredos): ${report.checks.gitleaks ? 'concluído' : 'não executado'}`,
        `Auditoria OSV: ${report.checks.dependencyAudit ? 'concluída' : 'não executada'}`,
        `Hospedagem: ${report.checks.hostingReview ? 'verificada nos arquivos enviados' : 'não verificada'}`,
        `Banco de dados: ${report.checks.databaseReview ? 'verificado nos arquivos enviados' : 'não verificado'}`,
        `Análise por IA: ${report.checks.aiAnalysis ? `concluída${coverage ? ` · ${coverage.reviewedFiles} de ${coverage.totalFiles} arquivos em ${coverage.batches} lote(s)` : ''}` : 'não executada'}`
    ];
    const legalNotes = Array.isArray(report.legalContext) ? report.legalContext : [];
    const architecture = report.architecture;
    const architectureNotes = architecture ? [
        `Hospedagem identificada: ${architecture.hosting.assessment}${architecture.hosting.configFiles.length ? ` Arquivos: ${architecture.hosting.configFiles.join(', ')}.` : ''}`,
        ...architecture.hosting.securityObservations,
        `Banco de dados identificado: ${architecture.database.assessment}${architecture.database.configFiles.length ? ` Arquivos: ${architecture.database.configFiles.join(', ')}.` : ''}`,
        ...architecture.database.connectionSettings.map((setting) => `Configuração de conexão (somente nome da variável): ${setting}.`),
        ...architecture.database.securityObservations
    ] : [];
    scanNotes.replaceChildren(...[...completedChecks, ...architectureNotes, ...legalNotes, ...(report.warnings || [])].map((message) => {
        const note = document.createElement('p');
        note.textContent = message;
        return note;
    }));

    const list = document.querySelector('#findings-list');
    const groupDefinitions = [
        { severity: 'critical', label: 'Críticas', guidance: 'Trate imediatamente e avalie o impacto antes de prosseguir.', open: true },
        { severity: 'high', label: 'Altas', guidance: 'Priorize a correção antes da homologação.', open: true },
        { severity: 'medium', label: 'Médias', guidance: 'Revise o contexto e defina uma ação corretiva.' },
        { severity: 'low', label: 'Baixas', guidance: 'Avalie a aplicabilidade e registre a decisão.' },
        { severity: 'info', label: 'Informativas', guidance: 'Considere como contexto para a revisão técnica.' }
    ];
    list.replaceChildren(...groupDefinitions.flatMap((group) => {
        const findings = report.findings.filter((finding) => finding.severity === group.severity);
        return findings.length ? [createFindingGroup(group, findings)] : [];
    }));
    document.querySelector('#empty-findings').hidden = report.findings.length !== 0;
    document.querySelector('#email-button').disabled = !serviceStatus.emailConfigured;
    document.querySelector('#email-button').title = serviceStatus.emailConfigured ? '' : 'Configure SMTP e SECURITY_EMAIL no servidor.';
}

function createFindingGroup(group, findings) {
    const section = document.createElement('details');
    section.className = `finding-group ${group.severity}`;
    section.open = Boolean(group.open);

    const heading = document.createElement('summary');
    heading.className = 'finding-group-heading';
    const title = document.createElement('h4');
    title.id = `finding-group-${group.severity}`;
    title.textContent = group.label;
    const count = document.createElement('span');
    count.className = 'finding-group-count';
    count.textContent = `${findings.length} ${findings.length === 1 ? 'achado' : 'achados'}`;
    const guidance = document.createElement('p');
    guidance.className = 'finding-group-guidance';
    guidance.textContent = group.guidance;
    heading.append(title, count, guidance);

    const items = document.createElement('div');
    items.className = 'finding-group-items';
    items.append(...findings.map(createFinding));
    section.append(heading, items);
    return section;
}

function createFinding(finding) {
    const article = document.createElement('article');
    article.className = 'finding';
    const summary = document.createElement('div');
    summary.className = 'finding-summary';
    const severity = document.createElement('span');
    severity.className = `severity ${finding.severity}`;
    severity.textContent = severityLabels[finding.severity] || finding.severity;
    const title = document.createElement('span');
    title.className = 'finding-title';
    title.textContent = finding.title;
    const location = document.createElement('span');
    location.className = 'finding-location';
    location.textContent = `${finding.file}${finding.line ? `:${finding.line}` : ''}`;
    summary.append(severity, title, location);
    const evidenceLabelText = finding.source === 'zap' ? 'Requisições afetadas' : 'Trecho identificado';

    const detail = document.createElement('p');
    detail.className = 'finding-detail';
    detail.textContent = finding.description;
    article.append(summary, detail);
    if (finding.evidence) {
        const evidence = document.createElement('div');
        evidence.className = 'finding-evidence';
        const evidenceLabel = document.createElement('span');
        evidenceLabel.textContent = evidenceLabelText;
        const evidenceText = document.createElement('code');
        evidenceText.textContent = finding.evidence;
        evidence.append(evidenceLabel, evidenceText);
        article.append(evidence);
    }
    if (finding.source) {
        const sourceLabels = {
            static: 'Regra automática',
            openai: 'Análise contextual por IA',
            osv: 'Base de vulnerabilidades OSV',
            semgrep: 'Semgrep (SAST)',
            gitleaks: 'Gitleaks (detecção de segredos)',
            zap: 'OWASP ZAP (teste dinâmico)'
        };
        const source = document.createElement('p');
        source.className = 'finding-source';
        source.textContent = `Origem do achado: ${sourceLabels[finding.source] || finding.source}`;
        article.append(source);
    }
    return article;
}

document.querySelector('#docx-button').addEventListener('click', async () => {
    if (!currentReport) return;
    try {
        const response = await fetch(`${apiBaseUrl}/api/report-docx?scanId=${encodeURIComponent(currentReport.scanId)}`, { credentials: 'include' });
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Não foi possível gerar o documento Word.');
        }
        const blob = await response.blob();
        const downloadUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = `relatorio-${safeFileName(currentReport.project)}.docx`;
        link.click();
        URL.revokeObjectURL(downloadUrl);
        showToast('Relatório em DOCX baixado com o resumo em linguagem simples.');
    } catch (error) {
        showToast(error.message || 'Falha ao gerar o DOCX.');
    }
});

document.querySelector('#prompt-button').addEventListener('click', async () => {
    if (!currentReport) return;
    try {
        const data = await fetchJson('/api/report-prompt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scanId: currentReport.scanId })
        }, 30000);
        claudePrompt.value = data.prompt;
        promptPanel.hidden = false;
        showToast('Prompt de correção gerado para revisão.');
    } catch (error) {
        showToast(error.message || 'Não foi possível gerar o prompt.');
    }
});

document.querySelector('#copy-prompt-button').addEventListener('click', async () => {
    if (!claudePrompt.value) return;
    try {
        await navigator.clipboard.writeText(claudePrompt.value);
        showToast('Prompt copiado para a área de transferência.');
    } catch {
        claudePrompt.focus();
        claudePrompt.select();
        showToast('Selecione o texto e copie manualmente.');
    }
});

document.querySelector('#email-button').addEventListener('click', async (event) => {
    if (!currentReport) return;
    const button = event.currentTarget;
    button.disabled = true;
    document.querySelector('#email-status').textContent = 'Enviando...';
    try {
        await fetchJson('/api/report-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scanId: currentReport.scanId })
        }, 30000);
        document.querySelector('#email-status').textContent = 'Relatório enviado ao responsável configurado.';
    } catch (error) {
        document.querySelector('#email-status').textContent = error.message;
    } finally {
        button.disabled = !serviceStatus.emailConfigured;
    }
});

function safeFileName(value) {
    return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 70) || 'analise';
}

function formatBytes(bytes) {
    return bytes < 1024 * 1024 ? `${Math.ceil(bytes / 1024)} KB` : `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function showToast(message) {
    toast.textContent = message;
    toast.classList.add('visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('visible'), 4200);
}

async function fetchJson(url, options = {}, timeoutMs = 75000) {
    let response;
    try {
        response = await fetch(`${apiBaseUrl}${url}`, {
            ...options,
            credentials: 'include',
            signal: options.signal || AbortSignal.timeout(timeoutMs)
        });
    } catch (error) {
        if (error.name === 'TimeoutError' || error.name === 'AbortError') {
            const message = url.startsWith('/api/scan/')
                ? 'A análise excedeu o tempo limite de 75 segundos. Tente um projeto menor ou tente novamente.'
                : 'O serviço demorou para responder. Verifique se o backend está ativo e tente novamente.';
            throw new Error(message);
        }
        throw new Error('Não foi possível conectar ao serviço. Inicie o backend com npm start e abra http://localhost:3000.');
    }

    const contentType = response.headers.get('content-type') || '';
    const responseText = await response.text();
    if (!responseText) {
        throw new Error('O serviço respondeu sem dados. Verifique se o backend está ativo em http://localhost:3000.');
    }

    let data;
    try {
        data = JSON.parse(responseText);
    } catch {
        const message = contentType.includes('application/json')
            ? 'O serviço retornou JSON inválido. Confira o terminal do backend.'
            : 'A resposta não veio da API Sentinela. Abra http://localhost:3000 em vez de usar Live Server ou abrir o HTML diretamente.';
        throw new Error(message);
    }

    if (!response.ok) {
        throw new Error(data.error || `O serviço respondeu com erro HTTP ${response.status}.`);
    }

    return data;
}

function resolveApiBaseUrl() {
    const configuredBase = document.querySelector('meta[name="sentinela-api-base"]')?.content.trim();
    if (configuredBase) return configuredBase.replace(/\/+$/, '');

    const localHosts = new Set(['localhost', '127.0.0.1', '[::1]']);
    const { hostname, port, protocol } = window.location;
    if (hostname === 'localhost' && port === '3000') return '';
    if (localHosts.has(hostname)) return `${protocol}//localhost:3000`;
    return '';
}

let serviceStatus = { emailConfigured: false, aiConfigured: false, pentestConfigured: false, dockerAvailable: null };
async function loadServiceStatus() {
    const dot = document.querySelector('#service-dot');
    const label = document.querySelector('#service-label');
    const footer = document.querySelector('#footer-capabilities');
    try {
        serviceStatus = await fetchJson('/api/health', {}, 8000);
        aiStatusHint.textContent = serviceStatus.aiConfigured
            ? 'Disponível. O projeto será enviado à API OpenAI configurada; credenciais reconhecidas são mascaradas antes do envio.'
            : 'Análise bloqueada: a chave da OpenAI não está configurada. Preencha OPENAI_API_KEY em config/.env e reinicie o servidor.';
        document.querySelector('#ai-required').classList.toggle('unavailable', !serviceStatus.aiConfigured);
        if (!serviceStatus.pentestConfigured) {
            const pentestHint = document.querySelector('#pentest-hint');
            pentestHint.textContent = 'Teste dinâmico bloqueado: nenhum host autorizado. Preencha PENTEST_ALLOWED_HOSTS em config/.env e reinicie o servidor.';
            pentestHint.classList.add('hint-error');
        } else if (serviceStatus.dockerAvailable === false) {
            const pentestHint = document.querySelector('#pentest-hint');
            pentestHint.textContent = 'Docker indisponível no servidor: inicie o Docker Desktop para executar o teste dinâmico.';
            pentestHint.classList.add('hint-error');
        }
        setBusy(isBusy);
        dot?.classList.add('online');
        if (label) label.textContent = serviceStatus.aiConfigured ? 'Serviço ativo · IA obrigatória disponível' : 'Serviço ativo · IA obrigatória indisponível';
        const tools = serviceStatus.dockerAvailable === false ? '· ferramentas Docker indisponíveis' : '· Semgrep, Gitleaks e ZAP via Docker';
        if (footer) footer.textContent = `IA obrigatória ${tools} ${serviceStatus.emailConfigured ? '· e-mail configurado' : '· e-mail indisponível'}`;
    } catch {
        serviceStatus.aiConfigured = false;
        serviceStatus.pentestConfigured = false;
        scanButton.disabled = true;
        aiStatusHint.textContent = 'Indisponível: não foi possível verificar a configuração do serviço.';
        dot?.classList.add('offline');
        if (label) label.textContent = 'Serviço indisponível';
        if (footer) footer.textContent = 'Inicie o servidor para analisar projetos';
    }
}

loadAuthStatus();
loadServiceStatus();