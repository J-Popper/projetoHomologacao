# Sentinela

Aplicação web para triagem inicial de segurança de projetos enviados em ZIP ou hospedados em repositórios públicos do GitHub.

## Iniciar no Windows

Requer Node.js 20 ou superior. Abra o PowerShell nesta pasta e execute:

```powershell
npm.cmd install
npm.cmd start
```

Preencha os valores necessários em `config\.env` e abra `http://localhost:3000` no navegador. O servidor fica vinculado por padrão apenas a `127.0.0.1`. O arquivo `config/.env` é carregado pelo backend, está excluído do Git e não deve ser compartilhado ou enviado ao repositório. Projetos enviados têm arquivos `.env` e `.env.*` excluídos antes da análise e do envio à IA.

O backend fica em `src/server.js`; a interface e seus arquivos ficam em `public/`, separados em `css/` e `js/`. O arquivo de configuração local fica em `config/`; os arquivos do npm permanecem na raiz para que os comandos de instalação e inicialização funcionem.

Para produção, use `NODE_ENV=production`, mantenha o processo atrás de um proxy reverso com HTTPS e firewall, e prefira manter `HOST=127.0.0.1` quando o proxy estiver no mesmo servidor. Defina `TRUST_PROXY_HOPS` para a quantidade exata de proxies confiáveis entre o cliente e o Node (normalmente `1` quando há um único proxy local); mantenha `0` se o acesso for direto. Configure `HOST=0.0.0.0` somente quando o ambiente exigir acesso de rede direto e tiver controles de rede adequados. A aplicação emitirá um aviso ao iniciar com interface de rede. Nunca exponha o serviço enquanto a autenticação estiver sem configuração.

Execute os testes automatizados com `npm.cmd test`.

## Login Microsoft (SSO)

O acesso à interface e às APIs fica bloqueado até autenticar por Microsoft Entra ID. Para habilitar:

1. Registre um aplicativo no Microsoft Entra ID como aplicativo de **locatário único** (single tenant), com plataforma **Web**.
2. Cadastre a URI de redirecionamento exatamente como `http://localhost:3000/auth/callback` para desenvolvimento local. Em produção, use a URI HTTPS pública do serviço.
3. Configure `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET` e `MICROSOFT_TENANT_ID` em `config\.env` usando os valores do registro. Mantenha o segredo exclusivamente no servidor.
4. Configure `MICROSOFT_REDIRECT_URI` com a mesma URI cadastrada no Entra ID. Por padrão, qualquer endereço `@greylogix.com.br` pode entrar; para alterar essa política, configure `MICROSOFT_ALLOWED_EMAIL_DOMAINS` com domínios separados por vírgula. Reinicie o backend após alterar as configurações.

O servidor usa Authorization Code com PKCE, valida estado/nonce, assinatura e claims do ID token e mantém uma sessão temporária em cookie `HttpOnly`, `SameSite=Lax` e `Secure` em produção. Além de restringir o login ao tenant configurado, compara o domínio do `preferred_username` assinado pela Microsoft com a lista `MICROSOFT_ALLOWED_EMAIL_DOMAINS`, sem diferenciar maiúsculas/minúsculas. Por padrão, apenas `greylogix.com.br` é aceito; domínios externos continuam bloqueados.

As sessões e relatórios são mantidos apenas na memória do processo, expiram em até 8 horas e são perdidos ao reiniciar o servidor. Para múltiplas instâncias, será necessário armazenamento compartilhado de sessões; não use este armazenamento em memória como sessão distribuída.

## Desenvolvimento com Live Server

1. Inicie o backend em um terminal com `npm.cmd start` e mantenha-o em execução.
2. No VS Code, use **Go Live** do Live Server para servir `public/index.html` (porta padrão `5500`).
3. No Edge, abra o endereço informado pelo Live Server, normalmente `http://127.0.0.1:5500`.

O frontend detecta o Live Server em `localhost`/`127.0.0.1` e encaminha as chamadas à API na porta `3000`. A API permite CORS apenas para origens locais de desenvolvimento ou origens HTTPS exatas configuradas em `APP_ORIGINS` (separadas por vírgula); CORS é uma política de navegador e não substitui autenticação. Para o retorno do SSO funcionar, cadastre no Entra ID a URI de callback do backend, não a porta do Live Server.

## Integrações

- OpenAI (obrigatória para analisar projetos): configure `OPENAI_API_KEY`. Todo projeto submetido é enviado à API OpenAI para análise contextual, após mascaramento de padrões conhecidos de credenciais. Sem essa variável, os endpoints de análise ficam indisponíveis e a interface bloqueia o envio. `OPENAI_MODEL` pode selecionar outro modelo compatível com a API Responses e saída JSON estruturada. Envie somente código que você tem autorização para compartilhar.
- E-mail: configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `MAIL_FROM` e `SECURITY_EMAIL`. O relatório só é enviado ao endereço fixo em `SECURITY_EMAIL` quando a pessoa aciona o botão. O transporte SMTP precisa aceitar conexão de saída do servidor.
- Auditoria de dependências: lockfiles reconhecidos são consultados na API pública OSV. Esta consulta depende de conectividade de saída para `api.osv.dev`.
- Microsoft SSO: configure `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, `MICROSOFT_TENANT_ID` e `MICROSOFT_REDIRECT_URI`; o domínio `greylogix.com.br` é permitido por padrão. `MICROSOFT_ALLOWED_EMAIL_DOMAINS` pode substituir essa política por uma lista de domínios. Não coloque credenciais no frontend.

Sem SMTP, o relatório continua disponível para download em DOCX, mas não pode ser enviado por e-mail. O download JSON não é oferecido pela interface.

## Escopo e limitações

A aplicação faz triagem estática baseada em padrões, consulta vulnerabilidades de versões fixas encontradas em alguns lockfiles, identifica indícios de hospedagem e tecnologias/configurações de banco nos arquivos enviados e exige análise contextual por IA. O código analisável é enviado à OpenAI após exclusão de arquivos `.env`/`.env.*` e mascaramento de padrões conhecidos de credenciais; mascaramento não detecta toda credencial possível. Ao baixar repositórios do GitHub, o servidor aceita redirecionamento somente para `codeload.github.com` e limita o download a 20 MB durante a transferência. Não instala nem executa o projeto, não consulta a infraestrutura implantada, não valida conectividade/disponibilidade do banco e não testa endpoints em execução. O achado de CSRF é apenas candidato heurístico: requer endpoint mutável e indícios de sessão/cookie no mesmo arquivo, e precisa ser confirmado manualmente. O prompt de correção recomenda validação e diff revisável; não altera arquivos automaticamente. As conclusões sobre hospedagem e banco são inferências dos arquivos analisados, não confirmação do ambiente de produção. A ferramenta não substitui SAST dedicado, análise de composição de software, pentest ou revisão profissional. Regras podem gerar falsos positivos ou não reconhecer falhas; o resultado não certifica segurança, conformidade com a LGPD ou certificação ISO.

Limites atuais: ZIP de 20 MB, conteúdo descompactado de 50 MB, 1.200 entradas, 300 arquivos de texto e 500 KB por arquivo. A consulta OSV cobre npm, PyPI, Packagist e crates.io nos formatos de lockfile reconhecidos pelo analisador.

Os relatórios ficam apenas na memória do processo para permitir o envio ao destinatário configurado e desaparecem quando o servidor reinicia. Há limitação básica de 30 solicitações de API por IP a cada 15 minutos.

## Exposição em rede

O servidor escuta apenas em loopback por padrão. Mesmo com SSO habilitado, defina retenção de dados, controles operacionais e revisão de segurança antes de expor a aplicação em rede. O acesso é limitado ao tenant configurado e, por padrão, ao domínio `greylogix.com.br`. Use TLS e firewall e analise apenas código que você tenha autorização para enviar.

## Checklist de implantação

- Use uma versão LTS do Node.js compatível com `engines` e instale dependências com `npm ci`.
- Configure `NODE_ENV=production`, `PORT` e as credenciais em um gerenciador de segredos do provedor; não copie segredos para o repositório ou para imagens de container.
- Registre no Entra ID a URI HTTPS pública exata em `MICROSOFT_REDIRECT_URI` e confirme que os domínios autorizados em `MICROSOFT_ALLOWED_EMAIL_DOMAINS` são os pretendidos.
- Configure `OPENAI_API_KEY` e confirme que o envio de código à OpenAI é permitido pela política da organização. Configure SMTP apenas se o envio de relatórios for necessário.
- Termine TLS no proxy reverso e limite o acesso à porta do Node ao próprio proxy; o app não configura TLS.
- Configure `TRUST_PROXY_HOPS` conforme o número real de proxies confiáveis; não habilite confiança ampla de cabeçalhos encaminhados em uma porta acessível diretamente pela Internet.
- Garanta acesso de saída a `login.microsoftonline.com`, `api.openai.com` e `api.osv.dev`; SMTP também precisa de saída quando habilitado.
- Use uma única instância: sessões, tentativas de login e relatórios são mantidos em memória e não sobrevivem a reinicializações. Para alta disponibilidade ou múltiplas instâncias, é necessário implementar armazenamento compartilhado antes da implantação.
- Valide `/api/health`, os logs do processo, autenticação SSO e os fluxos de análise/relatório em homologação. O endpoint de saúde não verifica conectividade ou validade das credenciais dos serviços externos.