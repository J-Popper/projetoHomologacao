// Integração com ferramentas de segurança executadas em containers Docker isolados:
// Semgrep (SAST), Gitleaks (segredos) e OWASP ZAP (teste dinâmico).
// Cada ferramenta degrada com aviso no relatório quando o Docker não está disponível.
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const severityRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
let dockerStatus = { available: null, checkedAt: 0 };

function getToolImages() {
    return {
        semgrep: process.env.SEMGREP_IMAGE || 'semgrep/semgrep:1.95.0',
        gitleaks: process.env.GITLEAKS_IMAGE || 'ghcr.io/gitleaks/gitleaks:v8.21.2',
        zap: process.env.ZAP_IMAGE || 'ghcr.io/zaproxy/zaproxy:2.16.0'
    };
}

function getCachedDockerStatus() {
    return dockerStatus.available;
}

async function isDockerAvailable() {
    if (dockerStatus.available !== null && Date.now() - dockerStatus.checkedAt < 60000) return dockerStatus.available;
    let available = false;
    try {
        const result = await runCommand('docker', ['info', '--format', '{{.ServerVersion}}'], { timeoutMs: 10000 });
        available = result.code === 0 && Boolean(result.stdout.trim());
    } catch {
        available = false;
    }
    dockerStatus = { available, checkedAt: Date.now() };
    return available;
}

function runCommand(command, args, { timeoutMs = 60000, maxBuffer = 64 * 1024 * 1024 } = {}) {
    return new Promise((resolve, reject) => {
        execFile(command, args, { timeout: timeoutMs, maxBuffer, windowsHide: true }, (error, stdout, stderr) => {
            if (!error) return resolve({ code: 0, stdout, stderr });
            if (error.killed || error.signal) {
                const timeoutError = new Error(`${command} excedeu o tempo limite.`);
                timeoutError.timedOut = true;
                return reject(timeoutError);
            }
            if (typeof error.code === 'number') return resolve({ code: error.code, stdout, stderr });
            reject(error);
        });
    });
}

// Executa um container com privilégios mínimos. O nome permite remover o container caso o
// cliente docker seja encerrado por tempo limite (com --rm, o container continuaria rodando).
async function runContainer({ image, args, mounts = [], network = 'none', memory = '2g', timeoutMs, extra = [] }) {
    const name = `sentinela-${crypto.randomUUID()}`;
    const dockerArgs = [
        'run', '--rm', '--name', name,
        '--security-opt', 'no-new-privileges',
        '--cap-drop', 'ALL',
        '--pids-limit', '1024',
        '--memory', memory,
        '--cpus', process.env.SCANNER_CPUS || '2',
        '--network', network,
        ...mounts.flatMap((mount) => ['--mount', `type=bind,source=${mount.source},target=${mount.target}${mount.readonly ? ',readonly' : ''}`]),
        ...extra,
        image,
        ...args
    ];
    try {
        return await runCommand('docker', dockerArgs, { timeoutMs });
    } catch (error) {
        if (error.timedOut) await runCommand('docker', ['rm', '-f', name], { timeoutMs: 20000 }).catch(() => {});
        throw error;
    }
}

async function writeWorkspace(files) {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinela-src-'));
    for (const file of files) {
        const target = path.resolve(directory, file.path);
        if (!target.startsWith(directory + path.sep)) continue;
        await fs.mkdir(path.dirname(target), { recursive: true });
        await fs.writeFile(target, file.content, 'utf8');
    }
    return directory;
}

async function removeDirectory(directory) {
    if (directory) await fs.rm(directory, { recursive: true, force: true }).catch(() => {});
}

// Roda Semgrep e Gitleaks sobre o código enviado. Nunca lança exceção: falhas viram avisos.
async function runCodeTools(files, { redact }) {
    const result = { findings: [], warnings: [], checks: { semgrep: false, gitleaks: false } };
    if (process.env.DEEP_SCAN_DISABLED === 'true') {
        result.warnings.push('Semgrep e Gitleaks estão desativados (DEEP_SCAN_DISABLED=true).');
        return result;
    }
    if (!await isDockerAvailable()) {
        result.warnings.push('Docker indisponível no servidor: Semgrep (SAST) e Gitleaks (segredos) não foram executados.');
        return result;
    }
    const fileLines = new Map(files.map((file) => [file.path, file.content.split(/\r?\n/)]));
    const lineAt = (file, line) => redact((fileLines.get(file)?.[line - 1] || '').trim().slice(0, 220));
    let workspace;
    try {
        workspace = await writeWorkspace(files);
        const [semgrep, gitleaks] = await Promise.allSettled([
            runSemgrep(workspace, lineAt),
            runGitleaks(workspace)
        ]);
        // O mesmo segredo pode ser apontado pelas duas ferramentas; mantém o achado do Gitleaks.
        const gitleaksLines = new Set(gitleaks.status === 'fulfilled' ? gitleaks.value.map((item) => `${item.file}:${item.line}`) : []);
        if (semgrep.status === 'fulfilled') {
            result.findings.push(...semgrep.value.filter((item) => !gitleaksLines.has(`${item.file}:${item.line}`)));
            result.checks.semgrep = true;
        } else {
            console.error('[Sentinela/Semgrep]', semgrep.reason?.message);
            result.warnings.push(`Semgrep não concluiu a análise: ${semgrep.reason?.timedOut ? 'tempo limite excedido' : 'falha na execução'}.`);
        }
        if (gitleaks.status === 'fulfilled') {
            result.findings.push(...gitleaks.value);
            result.checks.gitleaks = true;
        } else {
            console.error('[Sentinela/Gitleaks]', gitleaks.reason?.message);
            result.warnings.push(`Gitleaks não concluiu a análise: ${gitleaks.reason?.timedOut ? 'tempo limite excedido' : 'falha na execução'}.`);
        }
    } finally {
        await removeDirectory(workspace);
    }
    return result;
}

async function runSemgrep(workspace, lineAt) {
    const configs = (process.env.SEMGREP_CONFIGS || 'p/default,p/owasp-top-ten,p/cwe-top-25')
        .split(',').map((item) => item.trim()).filter(Boolean);
    // Rede liberada apenas para baixar as regras do registro Semgrep; métricas desativadas
    // e código montado somente leitura. O Semgrep não executa o código analisado.
    const { code, stdout, stderr } = await runContainer({
        image: getToolImages().semgrep,
        network: 'bridge',
        mounts: [{ source: workspace, target: '/src', readonly: true }],
        extra: ['--workdir', '/tmp'],
        args: ['semgrep', 'scan', '--json', '--metrics=off', '--disable-version-check', '--timeout', '30',
            '--max-target-bytes', '1000000', ...configs.flatMap((config) => ['--config', config]), '/src'],
        timeoutMs: Number(process.env.SEMGREP_TIMEOUT_SECONDS || 300) * 1000
    });
    let data;
    try {
        data = JSON.parse(stdout);
    } catch {
        throw new Error(`saída inválida (código ${code}): ${stderr.slice(0, 300)}`);
    }
    const severityMap = { ERROR: 'high', WARNING: 'medium', INFO: 'low' };
    return (data.results || []).slice(0, 200).map((item) => {
        const file = String(item.path || '').replace(/^\/src\//, '');
        const metadata = item.extra?.metadata || {};
        let severity = severityMap[item.extra?.severity] || 'medium';
        if (String(metadata.confidence).toUpperCase() === 'LOW' && severity === 'high') severity = 'medium';
        const cwe = [].concat(metadata.cwe || []).slice(0, 2).join('; ');
        const owasp = [].concat(metadata.owasp || []).slice(0, 2).join('; ');
        const ruleName = String(item.check_id || 'regra').split('.').pop().replace(/[-_]+/g, ' ');
        return {
            id: `semgrep:${item.check_id}`,
            severity,
            title: `Semgrep: ${ruleName}`,
            file,
            line: item.start?.line || null,
            evidence: item.start?.line ? lineAt(file, item.start.line) : '',
            description: [String(item.extra?.message || '').trim(), cwe && `CWE: ${cwe}.`, owasp && `OWASP: ${owasp}.`].filter(Boolean).join(' ').slice(0, 1200),
            source: 'semgrep',
            references: [].concat(metadata.references || []).slice(0, 3)
        };
    });
}

async function runGitleaks(workspace) {
    const { code, stdout, stderr } = await runContainer({
        image: getToolImages().gitleaks,
        mounts: [{ source: workspace, target: '/scan', readonly: true }],
        args: ['detect', '--no-git', '--source', '/scan', '--report-format', 'json', '--report-path', '/dev/stdout',
            '--redact', '--no-banner', '--exit-code', '0', '--log-level', 'error'],
        timeoutMs: Number(process.env.GITLEAKS_TIMEOUT_SECONDS || 120) * 1000
    });
    if (code !== 0) throw new Error(`código ${code}: ${stderr.slice(0, 300)}`);
    const trimmed = stdout.trim();
    if (!trimmed) return [];
    let data;
    try {
        data = JSON.parse(trimmed);
    } catch {
        throw new Error('saída JSON inválida');
    }
    return (Array.isArray(data) ? data : []).slice(0, 100).map((item) => ({
        id: `gitleaks:${item.RuleID}`,
        severity: 'high',
        title: `Segredo exposto: ${item.Description || item.RuleID}`,
        file: String(item.File || '').replace(/^\/scan\//, ''),
        line: item.StartLine || null,
        evidence: String(item.Match || '').slice(0, 200), // --redact já substitui o segredo por REDACTED
        description: `O Gitleaks identificou um possível segredo (regra ${item.RuleID}). Se for real, considere-o comprometido: revogue e gere uma nova credencial, remova-a do código e do histórico do Git e passe a usar variáveis de ambiente ou um cofre de segredos.`,
        source: 'gitleaks'
    }));
}

// ---- Teste dinâmico (OWASP ZAP) ----

function getPentestAllowedHosts() {
    return (process.env.PENTEST_ALLOWED_HOSTS || '').split(',').map((item) => item.trim().toLowerCase()).filter(Boolean);
}

function isHostAllowed(hostname, allowedHosts) {
    // "*" sozinho libera qualquer host (pentest sem lista de alvos restrita).
    if (allowedHosts.includes('*')) return true;
    const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
    return allowedHosts.some((entry) => entry.startsWith('*.')
        ? host.endsWith(entry.slice(1)) && host.length > entry.length - 1
        : host === entry);
}

function validatePentestTarget(value) {
    let url;
    try {
        url = new URL(String(value || '').trim());
    } catch {
        return { error: 'Informe uma URL válida, como https://app.homologacao.greylogix.com.br.' };
    }
    if (!['http:', 'https:'].includes(url.protocol)) return { error: 'A URL deve usar http ou https.' };
    if (url.username || url.password) return { error: 'Não inclua usuário ou senha na URL.' };
    const allowedHosts = getPentestAllowedHosts();
    if (!allowedHosts.length) return { error: 'O teste dinâmico está desativado. Configure PENTEST_ALLOWED_HOSTS no servidor.', status: 503 };
    if (!isHostAllowed(url.hostname, allowedHosts)) {
        return { error: `O host ${url.hostname} não está na lista de alvos autorizados (PENTEST_ALLOWED_HOSTS).`, status: 403 };
    }
    url.hash = '';
    return { url: url.toString() };
}

async function runZap(targetUrl, mode, onStage = () => {}) {
    if (!await isDockerAvailable()) throw Object.assign(new Error('Docker indisponível no servidor: o teste dinâmico não pode ser executado.'), { status: 503 });
    // Dentro do container, localhost aponta para o próprio container; usa o gateway do host.
    const containerUrl = new URL(targetUrl);
    if (['localhost', '127.0.0.1', '[::1]'].includes(containerUrl.hostname)) containerUrl.hostname = 'host.docker.internal';

    const maxMinutes = Number(process.env.ZAP_MAX_MINUTES || 30);
    const workDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinela-zap-'));
    await fs.chmod(workDirectory, 0o777).catch(() => {});
    try {
        const script = mode === 'full' ? 'zap-full-scan.py' : 'zap-baseline.py';
        const args = [script, '-t', containerUrl.toString(), '-J', 'report.json', '-m', mode === 'full' ? '5' : '2', '-I'];
        if (mode === 'full') {
            args.push('-z', `-config scanner.maxScanDurationInMins=${Math.max(5, maxMinutes - 10)} -config scanner.maxRuleDurationInMins=5`);
        }
        onStage(mode === 'full' ? 'Executando teste ativo (OWASP ZAP)...' : 'Executando teste passivo (OWASP ZAP)...');
        const { code, stderr, stdout } = await runContainer({
            image: getToolImages().zap,
            network: 'bridge',
            memory: '4g',
            mounts: [{ source: workDirectory, target: '/zap/wrk' }],
            extra: ['--add-host', 'host.docker.internal:host-gateway'],
            args,
            timeoutMs: maxMinutes * 60 * 1000
        });
        let report;
        try {
            report = JSON.parse(await fs.readFile(path.join(workDirectory, 'report.json'), 'utf8'));
        } catch {
            console.error('[Sentinela/ZAP]', `código ${code}`, (stderr || stdout).slice(-800));
            throw Object.assign(new Error('O OWASP ZAP não gerou relatório. Confira se a URL está acessível a partir do servidor do Sentinela.'), { status: 502 });
        }
        const parsed = parseZapReport(report);
        // Mostra no relatório o endereço informado pelo usuário, não o alias interno do Docker.
        const internalOrigin = containerUrl.origin;
        const originalOrigin = new URL(targetUrl).origin;
        if (internalOrigin !== originalOrigin) {
            for (const finding of parsed.findings) {
                finding.file = finding.file.split(internalOrigin).join(originalOrigin);
                finding.evidence = finding.evidence.split(internalOrigin).join(originalOrigin);
            }
        }
        return parsed;
    } catch (error) {
        if (error.timedOut) throw Object.assign(new Error(`O teste dinâmico excedeu ${maxMinutes} minutos e foi interrompido.`), { status: 504 });
        throw error;
    } finally {
        await removeDirectory(workDirectory);
    }
}

function parseZapReport(report) {
    const riskMap = { 3: 'high', 2: 'medium', 1: 'low', 0: 'info' };
    const findings = [];
    const urlsTested = new Set();
    for (const site of report.site || []) {
        for (const alert of site.alerts || []) {
            if (String(alert.confidence) === '0') continue; // marcado como falso positivo
            if (String(alert.pluginid) === '10116') continue; // "ZAP is Out of Date": sobre o próprio ZAP, não sobre o alvo
            const instances = alert.instances || [];
            instances.forEach((instance) => instance.uri && urlsTested.add(instance.uri));
            const first = instances[0] || {};
            findings.push({
                id: `zap:${alert.pluginid}`,
                severity: riskMap[Number(alert.riskcode)] || 'info',
                title: alert.name || alert.alert || 'Alerta OWASP ZAP',
                file: first.uri || site['@name'] || '',
                line: null,
                evidence: instances.slice(0, 3).map((instance) => `${instance.method || 'GET'} ${instance.uri}${instance.param ? ` [parâmetro: ${instance.param}]` : ''}${instance.evidence ? ` → ${instance.evidence}` : ''}`).join('\n').slice(0, 700),
                description: [stripHtml(alert.desc), alert.solution && `Correção sugerida: ${stripHtml(alert.solution)}`, alert.cweid && alert.cweid !== '-1' && `CWE-${alert.cweid}.`, instances.length > 3 && `Ocorre em ${alert.count || instances.length} URLs.`]
                    .filter(Boolean).join(' ').slice(0, 1400),
                source: 'zap',
                references: (String(alert.reference || '').match(/https?:\/\/[^\s<"]+/g) || []).slice(0, 3)
            });
        }
    }
    findings.sort((a, b) => severityRank[b.severity] - severityRank[a.severity]);
    return { findings, urlsTested: urlsTested.size, zapVersion: report['@version'] || '' };
}

function stripHtml(value) {
    return String(value || '').replace(/<[^>]*>/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/\s+/g, ' ').trim();
}

module.exports = {
    getCachedDockerStatus,
    getPentestAllowedHosts,
    getToolImages,
    isDockerAvailable,
    isHostAllowed,
    parseZapReport,
    runCodeTools,
    runZap,
    validatePentestTarget
};
