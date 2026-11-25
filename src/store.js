// Armazenamento persistente simples em JSON (instância única): perfis de acesso,
// conta admin local, histórico de projetos analisados, relatórios e auditoria.
// O diretório de dados (DATA_DIR, padrão ./data) fica fora do Git.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ROLES = ['admin', 'advanced', 'basic'];
const ROLE_LABELS = { admin: 'Administrador', advanced: 'Avançado', basic: 'Básico' };
const LOCAL_ADMIN_USERNAME = 'admin';
const maxAuditEntries = 5000;
const maxProjects = 2000;

const dataDirectory = path.resolve(process.env.DATA_DIR || path.join(__dirname, '..', 'data'));
const reportsDirectory = path.join(dataDirectory, 'reports');
const databaseFile = path.join(dataDirectory, 'sentinela.json');

let state = null;

function emptyState() {
    return { version: 1, users: {}, localAdmin: null, projects: [], audit: [] };
}

function load() {
    if (state) return state;
    fs.mkdirSync(reportsDirectory, { recursive: true });
    if (fs.existsSync(databaseFile)) {
        try {
            state = { ...emptyState(), ...JSON.parse(fs.readFileSync(databaseFile, 'utf8')) };
        } catch (error) {
            const backup = `${databaseFile}.corrompido-${Date.now()}`;
            fs.copyFileSync(databaseFile, backup);
            console.error(`[Sentinela/Store] Arquivo de dados inválido; cópia salva em ${backup}.`, error.message);
            state = emptyState();
        }
    } else {
        state = emptyState();
    }
    return state;
}

function writeFileAtomic(file, content) {
    const temporary = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, content, { mode: 0o600 });
    try {
        fs.renameSync(temporary, file);
    } catch {
        // OneDrive/antivírus podem bloquear o rename no Windows; grava direto como alternativa.
        fs.writeFileSync(file, content, { mode: 0o600 });
        fs.rmSync(temporary, { force: true });
    }
}

let saveTimer = null;
function save() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(flush, 50);
}

function flush() {
    clearTimeout(saveTimer);
    saveTimer = null;
    if (!state) return;
    writeFileAtomic(databaseFile, JSON.stringify(state, null, 2));
}

// ---- Senhas (scrypt) ----

function hashPassword(password) {
    const salt = crypto.randomBytes(16);
    const hash = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
    return `scrypt$16384$8$1$${salt.toString('base64')}$${hash.toString('base64')}`;
}

function verifyPassword(password, encoded) {
    const parts = String(encoded || '').split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') {
        // Executa um hash mesmo assim para não revelar, pelo tempo, se a conta existe.
        crypto.scryptSync(String(password), 'sentinela-dummy-salt', 64);
        return false;
    }
    const [, N, r, p, salt, expected] = parts;
    const expectedBuffer = Buffer.from(expected, 'base64');
    const actual = crypto.scryptSync(String(password), Buffer.from(salt, 'base64'), expectedBuffer.length, { N: Number(N), r: Number(r), p: Number(p) });
    return crypto.timingSafeEqual(actual, expectedBuffer);
}

function validateNewPassword(password) {
    if (typeof password !== 'string' || password.length < 12) return 'A senha deve ter pelo menos 12 caracteres.';
    if (password.length > 200) return 'A senha deve ter no máximo 200 caracteres.';
    const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(password)).length;
    if (classes < 3) return 'Use ao menos três tipos de caractere: minúsculas, maiúsculas, números e símbolos.';
    return null;
}

function generatePassword() {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    const symbols = '!@#%*-_+?';
    let password = '';
    for (let index = 0; index < 16; index += 1) password += alphabet[crypto.randomInt(alphabet.length)];
    password += symbols[crypto.randomInt(symbols.length)] + crypto.randomInt(10) + 'aA'[crypto.randomInt(2)];
    return password;
}

// ---- Conta admin local ----

function getLocalAdmin() {
    return load().localAdmin;
}

function setLocalAdminPassword(password, { mustChange = false } = {}) {
    load().localAdmin = {
        username: LOCAL_ADMIN_USERNAME,
        passwordHash: hashPassword(password),
        mustChangePassword: mustChange,
        failedAttempts: 0,
        lockedUntil: 0,
        passwordChangedAt: new Date().toISOString(),
        lastLoginAt: state.localAdmin?.lastLoginAt || null
    };
    flush();
}

// Garante que exista a conta local. Na primeira execução, gera uma senha e a exibe uma vez no log.
function ensureLocalAdmin() {
    if (getLocalAdmin()) return null;
    const initial = process.env.LOCAL_ADMIN_INITIAL_PASSWORD || generatePassword();
    setLocalAdminPassword(initial, { mustChange: true });
    return process.env.LOCAL_ADMIN_INITIAL_PASSWORD ? null : initial;
}

function verifyLocalAdminLogin(username, password) {
    const admin = getLocalAdmin();
    const now = Date.now();
    if (!admin || typeof username !== 'string' || username.trim().toLowerCase() !== LOCAL_ADMIN_USERNAME) {
        verifyPassword(password, '');
        return { ok: false };
    }
    if (admin.lockedUntil > now) return { ok: false, locked: true, retryAfterSeconds: Math.ceil((admin.lockedUntil - now) / 1000) };
    if (!verifyPassword(password, admin.passwordHash)) {
        admin.failedAttempts = (admin.failedAttempts || 0) + 1;
        if (admin.failedAttempts >= 5) {
            admin.lockedUntil = now + 15 * 60 * 1000;
            admin.failedAttempts = 0;
        }
        save();
        return { ok: false };
    }
    admin.failedAttempts = 0;
    admin.lockedUntil = 0;
    admin.lastLoginAt = new Date().toISOString();
    save();
    return { ok: true, mustChangePassword: Boolean(admin.mustChangePassword) };
}

// ---- Usuários e perfis ----

function normalizeEmail(email) {
    return String(email || '').trim().toLowerCase();
}

function getBootstrapAdmins() {
    return (process.env.ADMIN_EMAILS || '').split(',').map(normalizeEmail).filter(Boolean);
}

function getUser(email) {
    return load().users[normalizeEmail(email)] || null;
}

function listUsers() {
    return Object.values(load().users).sort((a, b) => String(b.lastLoginAt || '').localeCompare(String(a.lastLoginAt || '')));
}

// Registra o login Microsoft e devolve o usuário (com perfil). Novos usuários entram como "basic".
function recordMicrosoftLogin(email, name) {
    const key = normalizeEmail(email);
    const users = load().users;
    const now = new Date().toISOString();
    if (!users[key]) {
        users[key] = {
            email: key,
            name: name || '',
            role: getBootstrapAdmins().includes(key) ? 'admin' : 'basic',
            disabled: false,
            createdAt: now,
            createdBy: 'primeiro login',
            lastLoginAt: null,
            loginCount: 0
        };
    }
    const user = users[key];
    if (name) user.name = name;
    if (getBootstrapAdmins().includes(key) && user.role !== 'admin') user.role = 'admin';
    user.lastLoginAt = now;
    user.loginCount = (user.loginCount || 0) + 1;
    save();
    return user;
}

function upsertUser(email, { role, name, disabled, notes }, actor) {
    const key = normalizeEmail(email);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(key)) throw Object.assign(new Error('Informe um e-mail válido.'), { status: 400 });
    if (role !== undefined && !ROLES.includes(role)) throw Object.assign(new Error('Perfil inválido.'), { status: 400 });
    const users = load().users;
    const now = new Date().toISOString();
    users[key] ||= { email: key, name: '', role: 'basic', disabled: false, createdAt: now, createdBy: actor, lastLoginAt: null, loginCount: 0 };
    const user = users[key];
    if (role !== undefined) user.role = role;
    if (name !== undefined) user.name = String(name).slice(0, 120);
    if (disabled !== undefined) user.disabled = Boolean(disabled);
    if (notes !== undefined) user.notes = String(notes).slice(0, 500);
    user.updatedAt = now;
    user.updatedBy = actor;
    save();
    return user;
}

function deleteUser(email) {
    const key = normalizeEmail(email);
    const existed = Boolean(load().users[key]);
    delete state.users[key];
    save();
    return existed;
}

// ---- Projetos e relatórios ----

function reportPath(scanId) {
    if (!/^[0-9a-f-]{36}$/i.test(String(scanId))) return null;
    return path.join(reportsDirectory, `${scanId}.json`);
}

function saveProject(project, report) {
    const projects = load().projects;
    projects.unshift(project);
    const file = reportPath(project.scanId);
    if (file) writeFileAtomic(file, JSON.stringify(report));
    while (projects.length > maxProjects) {
        const removed = projects.pop();
        const removedFile = reportPath(removed.scanId);
        if (removedFile) fs.rmSync(removedFile, { force: true });
    }
    save();
    return project;
}

function listProjects() {
    return load().projects;
}

function getProject(scanId) {
    return load().projects.find((project) => project.scanId === scanId) || null;
}

function updateProject(scanId, changes) {
    const project = getProject(scanId);
    if (!project) return null;
    Object.assign(project, changes);
    save();
    return project;
}

function deleteProject(scanId) {
    const projects = load().projects;
    const index = projects.findIndex((project) => project.scanId === scanId);
    if (index < 0) return false;
    projects.splice(index, 1);
    const file = reportPath(scanId);
    if (file) fs.rmSync(file, { force: true });
    save();
    return true;
}

function loadReport(scanId) {
    const file = reportPath(scanId);
    if (!file || !fs.existsSync(file)) return null;
    try {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch {
        return null;
    }
}

// ---- Auditoria ----

function audit(actor, action, details = {}) {
    const entries = load().audit;
    entries.unshift({ at: new Date().toISOString(), actor: actor || 'sistema', action, details });
    if (entries.length > maxAuditEntries) entries.length = maxAuditEntries;
    save();
}

function listAudit() {
    return load().audit;
}

module.exports = {
    ROLES,
    ROLE_LABELS,
    LOCAL_ADMIN_USERNAME,
    dataDirectory,
    load,
    flush,
    hashPassword,
    verifyPassword,
    validateNewPassword,
    generatePassword,
    getLocalAdmin,
    setLocalAdminPassword,
    ensureLocalAdmin,
    verifyLocalAdminLogin,
    normalizeEmail,
    getUser,
    listUsers,
    recordMicrosoftLogin,
    upsertUser,
    deleteUser,
    saveProject,
    listProjects,
    getProject,
    updateProject,
    deleteProject,
    loadReport,
    audit,
    listAudit
};
