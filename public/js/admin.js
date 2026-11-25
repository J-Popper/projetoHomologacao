// Painel administrativo do Sentinela. Todo conteúdo vindo da API é inserido com textContent.
const apiBaseUrl = resolveApiBaseUrl();
const toast = document.querySelector('#toast');
const dialog = document.querySelector('#project-dialog');
const sourceLabels = { github: 'GitHub', zip: 'ZIP', pentest: 'Teste dinâmico', code: 'Código' };
const recommendationClass = { 'NÃO RECOMENDADO': 'danger', 'REVISÃO MANUAL': 'review', 'APTO COM RESSALVAS': 'ok' };
const severityLabels = { critical: 'Crítica', high: 'Alta', medium: 'Média', low: 'Baixa', info: 'Informativa' };
const actionLabels = {
    login_microsoft: 'Login Microsoft', login_local: 'Login admin local', login_local_falhou: 'Falha no login local',
    login_bloqueado: 'Login de usuário bloqueado', logout: 'Saída', github_conectado: 'GitHub conectado',
    github_desconectado: 'GitHub desconectado', github_org_recusada: 'GitHub fora da organização',
    github_email_recusado: 'GitHub com e-mail diferente do Microsoft',
    analise_iniciada: 'Análise iniciada', analise_concluida: 'Análise concluída', analise_falhou: 'Análise com falha',
    pentest_iniciado: 'Teste dinâmico iniciado', pentest_alvo_bloqueado: 'Alvo de teste bloqueado (SSRF)', acesso_negado: 'Acesso negado pelo perfil',
    senha_admin_alterada: 'Senha admin alterada', troca_senha_falhou: 'Falha ao trocar senha',
    admin_editou_projeto: 'Admin editou projeto', admin_excluiu_projeto: 'Admin excluiu projeto',
    admin_cadastrou_usuario: 'Admin concedeu acesso', admin_alterou_usuario: 'Admin alterou usuário',
    admin_excluiu_usuario: 'Admin excluiu usuário', admin_encerrou_sessoes: 'Admin encerrou sessões',
    admin_encerrou_sessao: 'Admin encerrou sessão', admin_exportou_projetos: 'Exportação de projetos',
    admin_exportou_auditoria: 'Exportação da auditoria'
};

let me = null;
let projects = [];
let projectStatuses = [];
let users = [];
let roles = [];
let auditEntries = [];
let currentProject = null;
let toastTimer;

// ---------- Navegação ----------
for (const tab of document.querySelectorAll('.admin-tab')) {
    tab.addEventListener('click', () => selectTab(tab.dataset.tab));
}

function selectTab(name) {
    for (const tab of document.querySelectorAll('.admin-tab')) tab.classList.toggle('active', tab.dataset.tab === name);
    for (const panel of document.querySelectorAll('[data-panel]')) panel.hidden = panel.dataset.panel !== name;
    const loaders = { overview: loadOverview, projects: loadProjects, users: loadUsers, sessions: loadSessions, jobs: loadJobs, audit: loadAudit, settings: loadOverview };
    loaders[name]?.();
    history.replaceState({}, '', `#${name}`);
}

document.querySelector('#logout-button').addEventListener('click', async () => {
    await fetchJson('/api/auth/logout', { method: 'POST' }).catch(() => {});
    window.location.assign(`${apiBaseUrl}/`);
});

// ---------- Visão geral e configuração ----------
async function loadOverview() {
    try {
        const data = await fetchJson('/api/admin/overview');
        const p = data.projects;
        renderStats('#overview-stats', [
            [p.total, 'projetos analisados'],
            [p.last30Days, 'análises nos últimos 30 dias'],
            [p.byRecommendation['NÃO RECOMENDADO'] || 0, 'não recomendados', true],
            [p.byStatus['pendente'] || 0, 'aguardando decisão'],
            [p.privateRepositories, 'repositórios privados'],
            [data.users.total, 'usuários cadastrados'],
            [data.users.activeSessions, 'sessões ativas'],
            [data.jobs.running, 'análises em execução']
        ]);
        renderStats('#overview-severity', Object.entries(p.severityTotals).map(([level, total]) => [total, severityLabels[level], level === 'critical' && total > 0]));
        const max = Math.max(1, ...p.timeline.map((day) => day.scans));
        document.querySelector('#overview-timeline').replaceChildren(...p.timeline.map((day) => {
            const column = document.createElement('div');
            const value = document.createElement('span');
            value.textContent = day.scans || '';
            const bar = document.createElement('i');
            bar.style.height = `${Math.round((day.scans / max) * 100)}%`;
            const label = document.createElement('span');
            label.textContent = day.day.slice(8, 10) + '/' + day.day.slice(5, 7);
            column.title = `${day.scans} análise(s) em ${formatDate(day.day + 'T12:00:00')}`;
            column.append(value, bar, label);
            return column;
        }));
        const riskiest = document.querySelector('#overview-riskiest');
        riskiest.replaceChildren(...(p.riskiest.length ? p.riskiest.map((item) => {
            const row = tableRow([item.project, item.responsible, `${item.counts.critical} / ${item.counts.high}`, formatDate(item.scannedAt)]);
            row.classList.add('clickable');
            row.addEventListener('click', () => openProject(item.scanId));
            return row;
        }) : [emptyRow(4, 'Nenhum projeto com achados críticos ou altos.')]));
        renderSettings(data);
        document.querySelector('#admin-updated').textContent = `Atualizado em ${new Date().toLocaleTimeString('pt-BR')}`;
    } catch (error) {
        showToast(error.message);
    }
}

function renderStats(selector, items) {
    document.querySelector(selector).replaceChildren(...items.map(([value, label, alert]) => {
        const stat = document.createElement('div');
        stat.className = `stat${alert ? ' alert' : ''}`;
        const strong = document.createElement('strong');
        strong.textContent = String(value);
        const span = document.createElement('span');
        span.textContent = label;
        stat.append(strong, span);
        return stat;
    }));
}

function renderSettings(data) {
    const c = data.config;
    const yes = (value, detail = '') => value ? `Configurado${detail ? ` · ${detail}` : ''}` : 'Não configurado';
    const entries = [
        ['Login Microsoft (Entra ID)', yes(c.microsoft)],
        ['Login GitHub corporativo', c.github ? `Configurado · ${c.githubRequired ? 'obrigatório após o login Microsoft' : 'opcional'}` : 'Não configurado (GITHUB_CLIENT_ID / SECRET / REDIRECT_URI)'],
        ['Organizações GitHub permitidas', c.githubAllowedOrgs.join(', ') || 'Qualquer organização (GITHUB_ALLOWED_ORGS vazio)'],
        ['Análise por IA', yes(c.ai, c.aiModel)],
        ['E-mail de relatórios', yes(c.email)],
        ['Docker (Semgrep, Gitleaks, ZAP)', c.docker === null ? 'Verificando...' : c.docker ? 'Disponível' : 'Indisponível'],
        ['Hosts liberados para teste dinâmico', c.pentestHosts.join(', ') || 'Nenhum (teste dinâmico desativado)'],
        ['Administradores via ADMIN_EMAILS', c.bootstrapAdmins.join(', ') || 'Nenhum'],
        ['Último login do admin local', data.localAdmin.lastLoginAt ? formatDate(data.localAdmin.lastLoginAt) : 'Nunca'],
        ['Senha do admin local alterada em', data.localAdmin.passwordChangedAt ? formatDate(data.localAdmin.passwordChangedAt) : '—']
    ];
    document.querySelector('#settings-list').replaceChildren(...entries.map(([label, value]) => {
        const item = document.createElement('div');
        const dt = document.createElement('dt');
        dt.textContent = label;
        const dd = document.createElement('dd');
        dd.textContent = value;
        item.append(dt, dd);
        return item;
    }));
}

document.querySelector('#admin-password-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
        await fetchJson('/api/account/password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                currentPassword: document.querySelector('#admin-current-password').value,
                newPassword: document.querySelector('#admin-new-password').value
            })
        });
        event.currentTarget.reset();
        showToast('Senha alterada. As demais sessões da conta local foram encerradas.');
        loadOverview();
    } catch (error) {
        showToast(error.message);
    }
});

// ---------- Projetos ----------
async function loadProjects() {
    try {
        const data = await fetchJson('/api/admin/projects');
        projects = data.projects;
        if (!projectStatuses.length) {
            projectStatuses = data.statuses;
            const filter = document.querySelector('#project-status');
            filter.append(...projectStatuses.map((status) => new Option(capitalize(status), status)));
            document.querySelector('#dialog-status').replaceChildren(...projectStatuses.map((status) => new Option(capitalize(status), status)));
        }
        renderProjects();
    } catch (error) {
        showToast(error.message);
    }
}

for (const selector of ['#project-search', '#project-recommendation', '#project-source', '#project-status']) {
    document.querySelector(selector).addEventListener('input', renderProjects);
}

function renderProjects() {
    const query = document.querySelector('#project-search').value.trim().toLowerCase();
    const recommendation = document.querySelector('#project-recommendation').value;
    const source = document.querySelector('#project-source').value;
    const status = document.querySelector('#project-status').value;
    const filtered = projects.filter((project) => (!recommendation || project.recommendation === recommendation)
        && (!source || project.source === source)
        && (!status || (project.status || 'pendente') === status)
        && (!query || [project.project, project.description, project.responsible, project.scannedBy, project.category, ...(project.technologies || [])]
            .some((value) => String(value || '').toLowerCase().includes(query))));
    const body = document.querySelector('#projects-body');
    if (!filtered.length) return body.replaceChildren(emptyRow(7, projects.length ? 'Nenhum projeto corresponde aos filtros.' : 'Nenhum projeto analisado ainda.'));
    body.replaceChildren(...filtered.map((project) => {
        const row = document.createElement('tr');
        row.className = 'clickable';
        row.addEventListener('click', () => openProject(project.scanId));

        const name = cell(project.project);
        name.append(small(`${sourceLabels[project.source] || project.source}${project.private ? ' · privado' : ''}${project.category ? ` · ${project.category}` : ''}`));
        const about = cell(truncate(project.description || '—', 220));
        if (project.technologies?.length) about.append(small(project.technologies.join(', ')));
        const responsible = cell(project.responsible || 'Não identificado');
        if (project.responsibleBasis) responsible.append(small(project.responsibleBasis));
        const scannedBy = cell(project.scannedByName || project.scannedBy);
        if (project.scannedByName) scannedBy.append(small(project.scannedBy));
        const result = document.createElement('td');
        result.append(pill(project.recommendation, recommendationClass[project.recommendation]), severityCounts(project.counts));
        const statusCell = document.createElement('td');
        statusCell.append(pill(capitalize(project.status || 'pendente'), project.status === 'aprovado' ? 'ok' : project.status === 'reprovado' ? 'danger' : 'accent'));
        row.append(name, about, responsible, scannedBy, result, statusCell, cell(formatDate(project.scannedAt)));
        return row;
    }));
}

async function openProject(scanId) {
    try {
        if (!projectStatuses.length) await loadProjects();
        const { project, report } = await fetchJson(`/api/admin/projects/${encodeURIComponent(scanId)}`);
        currentProject = project;
        document.querySelector('#dialog-eyebrow').textContent = `${sourceLabels[project.source] || project.source}${project.private ? ' · REPOSITÓRIO PRIVADO' : ''}`.toUpperCase();
        document.querySelector('#dialog-title').textContent = project.project;
        document.querySelector('#dialog-meta').textContent = `Executado por ${project.scannedByName ? `${project.scannedByName} (${project.scannedBy})` : project.scannedBy} em ${formatDate(project.scannedAt)} · ${project.recommendation} · ${project.totalFindings} achado(s)${project.filesAnalyzed ? ` · ${project.filesAnalyzed} arquivos` : ''}${project.updatedBy ? ` · editado por ${project.updatedBy}` : ''}`;
        document.querySelector('#dialog-description').value = project.description || '';
        document.querySelector('#dialog-responsible').value = project.responsible || '';
        document.querySelector('#dialog-responsible-basis').textContent = project.responsibleBasis ? `Base: ${project.responsibleBasis}` : '';
        document.querySelector('#dialog-status').value = project.status || 'pendente';
        document.querySelector('#dialog-notes').value = project.notes || '';
        const findings = report?.findings || [];
        document.querySelector('#dialog-findings').replaceChildren(...(findings.length ? findings.slice(0, 40).map((finding) => {
            const item = document.createElement('div');
            const title = document.createElement('strong');
            title.textContent = `[${severityLabels[finding.severity] || finding.severity}] ${finding.title}`;
            item.append(title, small(`${finding.file}${finding.line ? `:${finding.line}` : ''}`));
            return item;
        }) : [Object.assign(document.createElement('div'), { textContent: report ? 'Nenhum achado.' : 'O relatório completo não está mais disponível.' })]));
        document.querySelector('#dialog-docx').disabled = !report;
        dialog.showModal();
    } catch (error) {
        showToast(error.message);
    }
}

document.querySelector('#dialog-close').addEventListener('click', () => dialog.close());

document.querySelector('#dialog-save').addEventListener('click', async () => {
    if (!currentProject) return;
    try {
        await fetchJson(`/api/admin/projects/${encodeURIComponent(currentProject.scanId)}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                description: document.querySelector('#dialog-description').value,
                responsible: document.querySelector('#dialog-responsible').value,
                status: document.querySelector('#dialog-status').value,
                notes: document.querySelector('#dialog-notes').value
            })
        });
        dialog.close();
        showToast('Projeto atualizado.');
        loadProjects();
    } catch (error) {
        showToast(error.message);
    }
});

document.querySelector('#dialog-delete').addEventListener('click', async () => {
    if (!currentProject || !window.confirm(`Excluir o registro e o relatório de "${currentProject.project}"? Esta ação não pode ser desfeita.`)) return;
    try {
        await fetchJson(`/api/admin/projects/${encodeURIComponent(currentProject.scanId)}`, { method: 'DELETE' });
        dialog.close();
        showToast('Registro excluído.');
        loadProjects();
    } catch (error) {
        showToast(error.message);
    }
});

document.querySelector('#dialog-docx').addEventListener('click', async () => {
    if (!currentProject) return;
    try {
        const response = await fetch(`${apiBaseUrl}/api/report-docx?scanId=${encodeURIComponent(currentProject.scanId)}`, { credentials: 'include' });
        if (!response.ok) throw new Error((await response.json().catch(() => ({}))).error || 'Não foi possível gerar o DOCX.');
        const url = URL.createObjectURL(await response.blob());
        const link = document.createElement('a');
        link.href = url;
        link.download = `relatorio-${currentProject.project.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 60)}.docx`;
        link.click();
        URL.revokeObjectURL(url);
    } catch (error) {
        showToast(error.message);
    }
});

// ---------- Usuários ----------
async function loadUsers() {
    try {
        const data = await fetchJson('/api/admin/users');
        users = data.users;
        if (!roles.length) {
            roles = data.roles;
            document.querySelector('#new-user-role').replaceChildren(...roles.map((role) => new Option(role.label, role.value, role.value === 'basic', role.value === 'basic')));
        }
        renderUsers();
    } catch (error) {
        showToast(error.message);
    }
}

document.querySelector('#user-search').addEventListener('input', renderUsers);

function renderUsers() {
    const query = document.querySelector('#user-search').value.trim().toLowerCase();
    const filtered = users.filter((user) => !query || `${user.email} ${user.name}`.toLowerCase().includes(query));
    const body = document.querySelector('#users-body');
    if (!filtered.length) return body.replaceChildren(emptyRow(6, 'Nenhum usuário. Usuários aparecem aqui após o primeiro login ou quando um admin concede acesso.'));
    body.replaceChildren(...filtered.map((user) => {
        const row = document.createElement('tr');
        const identity = cell(user.name || user.email);
        if (user.name) identity.append(small(user.email));
        if (user.email === me?.email) identity.append(small('(você)'));

        const roleCell = document.createElement('td');
        const select = document.createElement('select');
        select.className = 'text-input';
        select.setAttribute('aria-label', `Perfil de ${user.email}`);
        select.append(...roles.map((role) => new Option(role.label, role.value, false, role.value === user.role)));
        select.addEventListener('change', () => updateUser(user.email, { role: select.value }, () => { select.value = user.role; }));
        roleCell.append(select);

        const state = document.createElement('td');
        state.append(pill(user.disabled ? 'Bloqueado' : 'Ativo', user.disabled ? 'danger' : 'ok'));
        if (user.activeSessions) state.append(small(`${user.activeSessions} sessão(ões) ativa(s)`));

        const lastLogin = cell(user.lastLoginAt ? formatDate(user.lastLoginAt) : 'Nunca entrou');
        if (user.loginCount) lastLogin.append(small(`${user.loginCount} login(s)`));

        const actions = document.createElement('td');
        const group = document.createElement('div');
        group.className = 'row-actions';
        group.append(
            actionButton(user.disabled ? 'Desbloquear' : 'Bloquear', () => updateUser(user.email, { disabled: !user.disabled }), !user.disabled),
            actionButton('Encerrar sessões', async () => {
                const data = await fetchJson(`/api/admin/users/${encodeURIComponent(user.email)}/logout`, { method: 'POST' });
                showToast(`${data.revoked} sessão(ões) encerrada(s).`);
                loadUsers();
            }),
            actionButton('Excluir', async () => {
                if (!window.confirm(`Excluir ${user.email}? No próximo login a pessoa voltará com perfil Básico.`)) return;
                await fetchJson(`/api/admin/users/${encodeURIComponent(user.email)}`, { method: 'DELETE' });
                showToast('Usuário excluído.');
                loadUsers();
            }, true)
        );
        actions.append(group);
        row.append(identity, roleCell, state, lastLogin, cell(String(user.scans)), actions);
        return row;
    }));
}

async function updateUser(email, changes, onError) {
    try {
        await fetchJson(`/api/admin/users/${encodeURIComponent(email)}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(changes)
        });
        showToast('Usuário atualizado. A mudança vale imediatamente.');
        loadUsers();
    } catch (error) {
        onError?.();
        showToast(error.message);
    }
}

document.querySelector('#user-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
        await fetchJson('/api/admin/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: document.querySelector('#new-user-email').value,
                name: document.querySelector('#new-user-name').value,
                role: document.querySelector('#new-user-role').value
            })
        });
        event.currentTarget.reset();
        document.querySelector('#new-user-role').value = 'basic';
        showToast('Acesso concedido. O perfil será aplicado no login Microsoft da pessoa.');
        loadUsers();
    } catch (error) {
        showToast(error.message);
    }
});

// ---------- Sessões ----------
async function loadSessions() {
    try {
        if (!roles.length) await loadUsers();
        const { sessions } = await fetchJson('/api/admin/sessions');
        const body = document.querySelector('#sessions-body');
        if (!sessions.length) return body.replaceChildren(emptyRow(8, 'Nenhuma sessão ativa.'));
        body.replaceChildren(...sessions.map((session) => {
            const row = document.createElement('tr');
            const identity = cell(session.name || session.email);
            identity.append(small(session.email + (session.current ? ' (esta sessão)' : '')));
            const origin = cell(session.ip || '—');
            origin.append(small(session.userAgent));
            const actions = document.createElement('td');
            if (!session.current) {
                actions.append(actionButton('Encerrar', async () => {
                    await fetchJson(`/api/admin/sessions/${encodeURIComponent(session.ref)}`, { method: 'DELETE' });
                    showToast('Sessão encerrada.');
                    loadSessions();
                }, true));
            }
            row.append(identity, cell(roles.find((role) => role.value === session.role)?.label || session.role),
                cell(session.authType === 'local' ? 'Conta local' : 'Microsoft'), cell(session.github ? `@${session.github}` : '—'),
                origin, cell(formatDate(session.lastSeenAt)), cell(formatDate(session.expiresAt)), actions);
            return row;
        }));
    } catch (error) {
        showToast(error.message);
    }
}

// ---------- Tarefas ----------
document.querySelector('#jobs-refresh').addEventListener('click', loadJobs);

async function loadJobs() {
    try {
        const { jobs } = await fetchJson('/api/admin/jobs');
        const body = document.querySelector('#jobs-body');
        if (!jobs.length) return body.replaceChildren(emptyRow(6, 'Nenhuma análise desde que o servidor iniciou.'));
        const statusLabels = { running: ['Em execução', 'accent'], done: ['Concluída', 'ok'], error: ['Falhou', 'danger'] };
        body.replaceChildren(...jobs.map((job) => {
            const row = document.createElement('tr');
            const status = document.createElement('td');
            status.append(pill(...(statusLabels[job.status] || [job.status])));
            const stage = cell(job.status === 'error' ? job.error : job.status === 'running' ? job.stage : '—');
            const minutes = Math.floor(job.elapsedSeconds / 60);
            row.append(cell(job.type === 'pentest' ? 'Teste dinâmico' : 'Código'), cell(job.label || '—'), cell(job.ownerEmail), status, stage,
                cell(`${minutes}:${String(job.elapsedSeconds % 60).padStart(2, '0')}`));
            return row;
        }));
    } catch (error) {
        showToast(error.message);
    }
}

// ---------- Auditoria ----------
document.querySelector('#audit-search').addEventListener('input', renderAudit);

async function loadAudit() {
    try {
        auditEntries = (await fetchJson('/api/admin/audit?limit=2000')).entries;
        renderAudit();
    } catch (error) {
        showToast(error.message);
    }
}

function renderAudit() {
    const query = document.querySelector('#audit-search').value.trim().toLowerCase();
    const filtered = auditEntries.filter((entry) => !query || `${entry.actor} ${entry.action} ${actionLabels[entry.action] || ''} ${JSON.stringify(entry.details)}`.toLowerCase().includes(query)).slice(0, 500);
    const body = document.querySelector('#audit-body');
    if (!filtered.length) return body.replaceChildren(emptyRow(4, 'Nenhum registro.'));
    body.replaceChildren(...filtered.map((entry) => tableRow([
        formatDate(entry.at),
        entry.actor,
        actionLabels[entry.action] || entry.action,
        Object.entries(entry.details || {}).map(([key, value]) => `${key}: ${typeof value === 'object' ? JSON.stringify(value) : value}`).join(' · ') || '—'
    ])));
}

// ---------- Utilidades ----------
function cell(text) {
    const td = document.createElement('td');
    td.textContent = text ?? '';
    return td;
}

function small(text) {
    const element = document.createElement('small');
    element.textContent = text;
    return element;
}

function pill(text, variant = '') {
    const span = document.createElement('span');
    span.className = `pill ${variant || ''}`;
    span.textContent = text;
    return span;
}

function severityCounts(counts = {}) {
    const wrapper = document.createElement('small');
    wrapper.className = 'sev-counts';
    for (const [key, cls, label] of [['critical', 'c', 'C'], ['high', 'h', 'A'], ['medium', 'm', 'M'], ['low', '', 'B']]) {
        const span = document.createElement('span');
        span.className = cls;
        span.textContent = `${label}:${counts[key] || 0} `;
        wrapper.append(span);
    }
    return wrapper;
}

function tableRow(values) {
    const row = document.createElement('tr');
    row.append(...values.map(cell));
    return row;
}

function emptyRow(columns, message) {
    const row = document.createElement('tr');
    const td = cell(message);
    td.colSpan = columns;
    td.className = 'empty-state';
    row.append(td);
    return row;
}

function actionButton(label, handler, danger = false) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `mini-button${danger ? ' danger' : ''}`;
    button.textContent = label;
    button.addEventListener('click', async (event) => {
        event.stopPropagation();
        button.disabled = true;
        try {
            await handler();
        } catch (error) {
            showToast(error.message);
        } finally {
            button.disabled = false;
        }
    });
    return button;
}

function capitalize(value) {
    return value ? value[0].toUpperCase() + value.slice(1) : '';
}

function truncate(value, length) {
    return value.length > length ? `${value.slice(0, length - 1)}…` : value;
}

function formatDate(value) {
    if (!value) return '—';
    return new Date(value).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' });
}

function showToast(message) {
    toast.textContent = message;
    toast.classList.add('visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('visible'), 4200);
}

async function fetchJson(url, options = {}, timeoutMs = 30000) {
    let response;
    try {
        response = await fetch(`${apiBaseUrl}${url}`, { ...options, credentials: 'include', signal: AbortSignal.timeout(timeoutMs) });
    } catch {
        throw new Error('Não foi possível conectar ao serviço.');
    }
    const data = await response.json().catch(() => ({}));
    if (response.status === 401) {
        window.location.assign(`${apiBaseUrl}/`);
        throw new Error('Sessão expirada.');
    }
    if (!response.ok) throw new Error(data.error || `Erro HTTP ${response.status}.`);
    return data;
}

function resolveApiBaseUrl() {
    const configuredBase = document.querySelector('meta[name="sentinela-api-base"]')?.content.trim();
    if (configuredBase) return configuredBase.replace(/\/+$/, '');
    const { hostname, port, protocol } = window.location;
    if (hostname === 'localhost' && port === '3000') return '';
    if (['localhost', '127.0.0.1', '[::1]'].includes(hostname)) return `${protocol}//localhost:3000`;
    return '';
}

async function init() {
    try {
        const status = await fetchJson('/api/auth/status');
        if (!status.authenticated || !status.permissions?.adminPanel) {
            window.location.assign(`${apiBaseUrl}/?authError=forbidden`);
            return;
        }
        me = status.user;
        document.querySelector('#admin-user').textContent = `${me.email} · ${me.roleLabel}`;
        const isLocal = me.authType === 'local';
        document.querySelector('#admin-password-form').hidden = !isLocal;
        document.querySelector('#local-admin-hint').hidden = isLocal;
        document.querySelector('#projects-csv').href = `${apiBaseUrl}/api/admin/projects.csv`;
        document.querySelector('#audit-csv').href = `${apiBaseUrl}/api/admin/audit.csv`;
        const initialTab = window.location.hash.slice(1);
        selectTab(document.querySelector(`[data-tab="${initialTab}"]`) ? initialTab : 'overview');
    } catch (error) {
        showToast(error.message);
    }
}

init();
