// Redefine a senha da conta admin local (usuário "admin").
// Uso: pare o servidor e execute `npm run admin:reset-password`.
// Uma senha forte é gerada, exibida uma única vez e a troca é exigida no próximo login.
const path = require('node:path');
require('dotenv').config({ path: path.resolve(__dirname, '..', 'config', '.env'), quiet: true });
const store = require('../src/store');

store.load();
const password = store.generatePassword();
store.setLocalAdminPassword(password, { mustChange: true });
store.audit('linha de comando', 'senha_admin_redefinida');
store.flush();

console.log('Conta admin local redefinida.');
console.log('  Usuário: %s', store.LOCAL_ADMIN_USERNAME);
console.log('  Senha:   %s', password);
console.log('A troca da senha será exigida no primeiro login. Guarde-a em local seguro; ela não será exibida novamente.');
