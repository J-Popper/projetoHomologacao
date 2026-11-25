// Baixa antecipadamente as imagens Docker usadas pelo Sentinela (Semgrep, Gitleaks, OWASP ZAP),
// evitando que a primeira análise demore ou exceda o tempo limite durante o download.
const path = require('node:path');
const { spawnSync } = require('node:child_process');
require('dotenv').config({ path: path.resolve(__dirname, '..', 'config', '.env') });
const { getToolImages } = require('../src/scanners');

let failed = false;
for (const [tool, image] of Object.entries(getToolImages())) {
    console.log('\n[%s] docker pull %s', tool, image);
    const result = spawnSync('docker', ['pull', image], { stdio: 'inherit' });
    if (result.status !== 0) {
        failed = true;
        console.error('[%s] falha ao baixar %s. O Docker está em execução?', tool, image);
    }
}
process.exit(failed ? 1 : 0);
