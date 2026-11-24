// Baixa antecipadamente as imagens Docker usadas pelo Sentinela (Semgrep, Gitleaks, OWASP ZAP),
// evitando que a primeira análise demore ou exceda o tempo limite durante o download.
const path = require('node:path');
const { spawnSync } = require('node:child_process');
require('dotenv').config({ path: path.resolve(__dirname, '..', 'config', '.env') });
const { getToolImages } = require('../src/scanners');

let failed = false;
for (const [tool, image] of Object.entries(getToolImages())) {
    console.log(`\n[${tool}] docker pull ${image}`);
    const result = spawnSync('docker', ['pull', image], { stdio: 'inherit' });
    if (result.status !== 0) {
        failed = true;
        console.error(`[${tool}] falha ao baixar ${image}. O Docker está em execução?`);
    }
}
process.exit(failed ? 1 : 0);
