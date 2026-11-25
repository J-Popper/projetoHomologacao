// Leitura segura de projetos em ZIP (upload ou repositório GitHub).
// Nenhum arquivo é executado; o conteúdo é lido em memória com limites de tamanho e quantidade.
const path = require('node:path');
const AdmZip = require('adm-zip');

const maxUploadBytes = 20 * 1024 * 1024;
const maxExpandedBytes = 50 * 1024 * 1024;
const maxFiles = 1000000;
const maxSourceFiles = 500000;
const maxFileBytes = 500 * 1024;
const textExtensions = new Set([
    '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.php', '.java', '.go',
    '.rb', '.cs', '.html', '.htm', '.vue', '.svelte', '.json', '.yaml', '.yml',
    '.toml', '.xml', '.properties', '.env', '.conf', '.config', '.sql', '.sh',
    '.tf', '.dockerfile', '.prisma', '.md'
]);
const ignoredPath = /(^|\/)(node_modules|vendor|\.git|dist|build|coverage|\.next|\.venv|venv|__pycache__)(\/|$)/i;

function httpError(status, message) {
    const error = new Error(message);
    error.status = status;
    return error;
}

// Assinaturas de ZIP: "PK\x03\x04" (arquivo local) ou "PK\x05\x06" (ZIP vazio).
// Confere o conteúdo real em vez de confiar na extensão ou no Content-Type enviados pelo navegador.
function isZipBuffer(buffer) {
    return Buffer.isBuffer(buffer) && buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4b
        && ((buffer[2] === 0x03 && buffer[3] === 0x04) || (buffer[2] === 0x05 && buffer[3] === 0x06));
}

// Nome do arquivo enviado vira apenas um rótulo: sem diretórios, caracteres de controle
// ou de formatação bidirecional, e com tamanho limitado.
function sanitizeUploadName(value) {
    const base = path.posix.basename(String(value || '').replaceAll('\\', '/'));
    const cleaned = base.replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]/g, '').trim().slice(0, 150);
    return cleaned || 'projeto.zip';
}

function readZip(buffer) {
    if (!isZipBuffer(buffer)) throw httpError(400, 'O arquivo não é um ZIP válido.');
    let zip;
    try {
        zip = new AdmZip(buffer);
    } catch {
        throw httpError(400, 'O arquivo não é um ZIP válido.');
    }
    const entries = zip.getEntries();
    if (!entries.length) throw httpError(400, 'O ZIP não contém arquivos.');
    if (entries.length > maxFiles) throw httpError(413, `O ZIP contém mais de ${maxFiles} arquivos.`);

    // O tamanho declarado é confiável aqui: o adm-zip limita a descompressão a esse valor.
    let expandedBytes = 0;
    for (const entry of entries) {
        if (entry.isDirectory) continue;
        expandedBytes += entry.header.size;
        if (expandedBytes > maxExpandedBytes) throw httpError(413, 'O conteúdo descompactado excede o limite de 50 MB.');
    }

    const files = [];
    let skippedLargeFiles = 0;
    let skippedEnvironmentFiles = 0;
    for (const entry of entries) {
        if (entry.isDirectory) continue;
        const name = entry.entryName.replaceAll('\\', '/').replace(/^\/+/, '');
        if (!name || name.split('/').some((part) => part === '..') || /^[a-z]:/i.test(name) || ignoredPath.test(name)) continue;
        if (isEnvironmentFile(name)) {
            skippedEnvironmentFiles += 1;
            continue;
        }
        if (!isTextFile(name)) continue;
        if (entry.header.size > maxFileBytes) {
            skippedLargeFiles += 1;
            continue;
        }
        let content;
        try {
            content = entry.getData().toString('utf8');
        } catch {
            throw httpError(400, 'O ZIP está corrompido, protegido por senha ou usa um formato não suportado.');
        }
        if (content.length > maxFileBytes * 4 || content.includes('\u0000')) continue;
        files.push({ path: name, content });
        if (files.length > maxSourceFiles) throw httpError(413, `O projeto excede o limite de ${maxSourceFiles} arquivos analisáveis.`);
    }
    if (!files.length) throw httpError(400, 'Nenhum arquivo de código ou manifesto compatível foi encontrado no ZIP.');
    const warnings = [
        ...(skippedLargeFiles ? [`${skippedLargeFiles} arquivo(s) de texto acima de 500 KB foram ignorados.`] : []),
        ...(skippedEnvironmentFiles ? [`${skippedEnvironmentFiles} arquivo(s) de ambiente .env foram excluídos para proteger credenciais.`] : [])
    ];
    return { files, warnings };
}

function isEnvironmentFile(filePath) {
    return /^\.env(?:$|\.)/i.test(path.posix.basename(filePath));
}

function isTextFile(filePath) {
    const basename = path.posix.basename(filePath).toLowerCase();
    return textExtensions.has(path.posix.extname(basename)) || /^dockerfile(?:\..*)?$/.test(basename) || basename === 'makefile' || basename.startsWith('.env');
}

module.exports = { maxUploadBytes, isZipBuffer, sanitizeUploadName, readZip, isEnvironmentFile, isTextFile };
