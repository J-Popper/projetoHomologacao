# Sentinela

Aplicação web para triagem inicial de segurança de projetos enviados em ZIP ou hospedados no GitHub (públicos ou, com login GitHub corporativo, privados), com perfis de acesso e painel administrativo.

## Iniciar no Windows

Requer Node.js 20 ou superior. Abra o PowerShell nesta pasta e execute:

```powershell
npm.cmd install
npm.cmd start
```

Preencha os valores necessários em `config\.env` e abra `http://localhost:3000` no navegador. O servidor fica vinculado por padrão apenas a `127.0.0.1`. O arquivo `config/.env` é carregado pelo backend, está excluído do Git e não deve ser compartilhado ou enviado ao repositório. Projetos enviados têm arquivos `.env` e `.env.*` excluídos antes da análise e do envio à IA.

Use `http://localhost:3000` nos navegadores para manter a mesma origem durante o login Microsoft. Em desenvolvimento, o backend redireciona `127.0.0.1:3000` para o endereço canônico `localhost:3000`. A porta `3001` está ocupada por outro aplicativo neste ambiente; não use essa porta para abrir o Sentinela.

Use `http://localhost:3000` nos navegadores para manter o mesmo host durante o retorno do login Microsoft. `127.0.0.1` e `localhost` são hosts de cookie diferentes. A porta `3001` pode ser usada por outro aplicativo; não use essa porta para abrir o Sentinela.

O backend fica em `src/server.js`; a interface e seus arquivos ficam em `public/`, separados em `css/` e `js/`. O arquivo de configuração local fica em `config/`; os arquivos do npm permanecem na raiz para que os comandos de instalação e inicialização funcionem.

Para produção, use `NODE_ENV=production`, mantenha o processo atrás de um proxy reverso com HTTPS e firewall, e prefira manter `HOST=127.0.0.1` quando o proxy estiver no mesmo servidor. Defina `TRUST_PROXY_HOPS` para a quantidade exata de proxies confiáveis entre o cliente e o Node (normalmente `1` quando há um único proxy local); mantenha `0` se o acesso for direto. Configure `HOST=0.0.0.0` somente quando o ambiente exigir acesso de rede direto e tiver controles de rede adequados. A aplicação emitirá um aviso ao iniciar com interface de rede. Nunca exponha o serviço enquanto a autenticação estiver sem configuração.

Execute os testes automatizados com `npm.cmd test`.

## Login Microsoft (SSO)

O acesso à interface e às APIs fica bloqueado até autenticar por Microsoft Entra ID. Para habilitar:

1. Registre um aplicativo no Microsoft Entra ID como aplicativo de **locatário único** (single tenant), com plataforma **Web**.
2. Cadastre a URI de redirecionamento exatamente como `http://localhost:3000/auth/callback` para desenvolvimento local. Em produção, use a URI HTTPS pública do serviço.
3. Configure `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET` e `MICROSOFT_TENANT_ID` em `config\.env` usando os valores do registro. Mantenha o segredo exclusivamente no servidor.
4. Configure `MICROSOFT_REDIRECT_URI` com a mesma URI cadastrada no Entra ID. Por padrão, qualquer endereço `@greylogix.com.br` pode entrar; para alterar essa política, configure `MICROSOFT_ALLOWED_EMAIL_DOMAINS` com domínios separados por vírgula. Reinicie o backend após alterar as configurações.

Se o callback retornar `invalid_client`, crie um novo segredo no Entra ID e copie o campo **Value** para `MICROSOFT_CLIENT_SECRET` (não use o **Secret ID**). O valor do segredo só é exibido ao criá-lo; confira também se ele pertence ao aplicativo indicado por `MICROSOFT_CLIENT_ID`. Atualize `config/.env` e reinicie o servidor. Nunca compartilhe ou versione o segredo.

O servidor usa Authorization Code com PKCE, valida estado/nonce, assinatura e claims do ID token e mantém uma sessão temporária em cookie `HttpOnly`, `SameSite=Lax` e `Secure` em produção. Além de restringir o login ao tenant configurado, compara o domínio do `preferred_username` assinado pela Microsoft com a lista `MICROSOFT_ALLOWED_EMAIL_DOMAINS`, sem diferenciar maiúsculas/minúsculas. Por padrão, apenas `greylogix.com.br` é aceito; domínios externos continuam bloqueados.

As sessões são mantidas apenas na memória do processo, expiram em até 8 horas e são perdidas ao reiniciar o servidor. Perfis, histórico de projetos, relatórios e auditoria ficam em `data/` (veja abaixo). Para múltiplas instâncias, será necessário armazenamento compartilhado de sessões; não use este armazenamento em memória como sessão distribuída.

## Perfis de acesso e painel admin

Há três perfis:

| Perfil | Análise de código (ZIP/GitHub) | Teste dinâmico passivo | Teste dinâmico **ativo** | Painel admin |
| --- | --- | --- | --- | --- |
| Básico (padrão no primeiro login) | sim | sim | não | não |
| Avançado | sim | sim | sim | não |
| Administrador | sim | sim | sim | sim |

As permissões são verificadas no servidor; a interface apenas oculta ou desabilita o que o perfil não permite. Mudanças de perfil e bloqueios valem imediatamente, inclusive para sessões abertas.

**Conta admin local.** Existe uma conta local (usuário `admin`) que entra sem Microsoft, pelo link "Entrar com a conta administrativa local" na tela de login, e serve para conceder os primeiros acessos. A senha é armazenada apenas como hash scrypt em `data/sentinela.json`; a troca é obrigatória no primeiro login; após 5 tentativas erradas a conta fica bloqueada por 15 minutos. Para gerar uma nova senha (por exemplo, se ela for esquecida), pare o servidor e execute `npm.cmd run admin:reset-password`. Na primeira inicialização sem conta existente, o servidor gera uma senha e a exibe uma única vez no log (ou usa `LOCAL_ADMIN_INITIAL_PASSWORD`, se definida). `ADMIN_EMAILS` (lista separada por vírgula) promove contas Microsoft a Administrador automaticamente no login.

O painel fica em `http://localhost:3000/admin` (link "Painel admin" no topo da aplicação) e oferece:

- **Visão geral:** totais de projetos, não recomendados, pendentes de decisão, repositórios privados, usuários, sessões e análises em execução; gráfico de análises dos últimos 14 dias; achados acumulados por gravidade; projetos com mais achados críticos/altos.
- **Projetos:** todos os projetos analisados, com descrição breve e responsável sugeridos pela IA (a partir de README, manifestos, CODEOWNERS e dono/contribuidores do GitHub), quem executou, recomendação e achados. Filtros, busca, exportação CSV, detalhes com os principais achados, download do DOCX, edição de descrição/responsável, status da homologação (pendente, em correção, aprovado, reprovado, risco aceito), notas internas e exclusão do registro.
- **Usuários e perfis:** conceder acesso antecipado por e-mail, alterar perfil, bloquear/desbloquear, encerrar sessões e excluir usuários. Um administrador não pode rebaixar nem bloquear a si mesmo.
- **Sessões ativas:** quem está conectado, de onde, com qual conta GitHub, e encerramento de sessões.
- **Análises em execução:** tarefas em andamento e recentes, com etapa, duração e erros.
- **Auditoria:** logins (inclusive falhas), conexões GitHub, análises, testes dinâmicos, acessos negados por perfil e todas as ações administrativas, com busca e exportação CSV.
- **Configuração:** situação das integrações (Microsoft, GitHub, IA, e-mail, Docker, hosts de pentest) e troca de senha da conta local.

Perfis, histórico de projetos, relatórios completos e auditoria são persistidos em `data/` (ou em `DATA_DIR`), excluído do Git. Os relatórios contêm trechos de código (com segredos mascarados): restrinja o acesso a esse diretório e, se o projeto estiver em uma pasta sincronizada (OneDrive), considere apontar `DATA_DIR` para fora dela. São mantidos os 2.000 projetos e 5.000 registros de auditoria mais recentes.

## Login GitHub corporativo (repositórios privados)

Depois do login Microsoft, cada pessoa pode conectar sua conta GitHub corporativa para listar e analisar os repositórios privados aos quais tem acesso. O token do GitHub fica apenas na memória do servidor, nunca vai ao navegador e é revogado ao sair ou desconectar.

1. No GitHub, crie um **OAuth App** na organização (Settings > Developer settings > OAuth Apps > New OAuth App).
2. Em **Authorization callback URL**, use exatamente `http://localhost:3000/auth/github/callback` (em produção, a URL HTTPS pública).
3. Configure em `config\.env`:

| Variável | Uso |
| --- | --- |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | Credenciais do OAuth App (o segredo fica só no servidor). |
| `GITHUB_REDIRECT_URI` | A mesma callback URL cadastrada. |
| `GITHUB_ALLOWED_ORGS` | Organizações aceitas, separadas por vírgula (recomendado). Contas fora delas são recusadas, e só os repositórios dessas organizações aparecem na lista. |
| `GITHUB_LOGIN_REQUIRED` | `true` torna o login GitHub obrigatório logo após o login Microsoft (a conta admin local é dispensada). Padrão: opcional, necessário apenas para repositórios privados. |

**Mesma identidade:** a conta GitHub só é aceita se tiver, **verificado**, exatamente o mesmo e-mail do login Microsoft (ex.: `pessoa@greylogix.com.br`); caso contrário, o token é revogado na hora e a tentativa fica na auditoria. Cada pessoa deve adicionar e verificar o e-mail corporativo em GitHub > Settings > Emails (pode ser um e-mail secundário). Para a conta admin local, que não tem e-mail Microsoft, exige-se um e-mail verificado de um domínio de `MICROSOFT_ALLOWED_EMAIL_DOMAINS`.

O escopo solicitado é `repo read:org read:user user:email`: o GitHub OAuth não oferece escopo somente leitura para repositórios privados, mas o Sentinela só lista repositórios e baixa o ZIP. Se a organização usa restrição de acesso de OAuth Apps, um owner precisa aprovar o app. Para escopo mais restrito por repositório, considere um GitHub App no futuro.

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

## Análise aprofundada e teste dinâmico (Docker)

Com o Docker instalado e em execução no servidor, o Sentinela roda ferramentas de mercado em containers isolados (sem privilégios, com limite de memória e CPU):

- **Semgrep (SAST):** regras `p/default`, `p/owasp-top-ten` e `p/cwe-top-25` sobre o código enviado, montado somente leitura. Precisa de saída para `semgrep.dev` para baixar as regras; métricas desativadas, o código não sai do servidor por essa via. Ajuste com `SEMGREP_CONFIGS` (lista separada por vírgula).
- **Gitleaks:** detecção de segredos, sem acesso à rede. Os valores encontrados são mascarados no relatório.
- **OWASP ZAP (aba "Teste dinâmico"):** testa a aplicação em execução pela URL. O modo **passivo** (`zap-baseline`) só navega e observa; o modo **ativo** (`zap-full-scan`) envia ataques reais e pode alterar dados, por isso use apenas em homologação.

Antes do primeiro uso, baixe as imagens (cerca de 2 GB) com:

```
npm run tools:pull
```

Variáveis:

| Variável | Padrão | Uso |
| --- | --- | --- |
| `PENTEST_ALLOWED_HOSTS` | vazio (teste dinâmico desativado) | Hosts que podem ser testados, separados por vírgula. Aceita `*.dominio` para subdomínios. Ex.: `*.homologacao.greylogix.com.br,localhost` |
| `ZAP_MAX_MINUTES` | `30` | Tempo máximo de um teste dinâmico |
| `AI_MAX_BATCHES` | `5` | Quantos lotes de ~180 mil caracteres a IA revisa por projeto. Projetos maiores ficam parcialmente cobertos pela IA (o relatório avisa) |
| `OPENAI_TIMEOUT_SECONDS` | `180` | Tempo máximo por lote de IA |
| `SEMGREP_TIMEOUT_SECONDS` / `GITLEAKS_TIMEOUT_SECONDS` | `300` / `120` | Tempo máximo das ferramentas |
| `SEMGREP_IMAGE`, `GITLEAKS_IMAGE`, `ZAP_IMAGE` | versões fixadas em `src/scanners.js` | Trocar versão das imagens |
| `DEEP_SCAN_DISABLED` | `false` | `true` desliga Semgrep e Gitleaks |

Sem Docker, a análise de código continua funcionando com as regras próprias, OSV e IA, mas o relatório indica que Semgrep e Gitleaks não rodaram e não emite "APTO". O teste dinâmico exige Docker.

Cada teste dinâmico é registrado no log do servidor com o usuário, o alvo, o modo e o horário. Só é possível um teste dinâmico por vez. As análises rodam em segundo plano e a tela acompanha o progresso. O teste dinâmico não faz login na aplicação: páginas protegidas por autenticação ficam fora da cobertura.

Para uma aplicação rodando na própria máquina do Sentinela, use `localhost` na URL e inclua `localhost` em `PENTEST_ALLOWED_HOSTS`; o Sentinela redireciona o ZAP para `host.docker.internal`.

Sem SMTP, o relatório continua disponível para download em DOCX, mas não pode ser enviado por e-mail. O download JSON não é oferecido pela interface.

## Escopo e limitações

A aplicação faz triagem estática baseada em padrões, consulta vulnerabilidades de versões fixas encontradas em alguns lockfiles, identifica indícios de hospedagem e tecnologias/configurações de banco nos arquivos enviados e exige análise contextual por IA. O código analisável é enviado à OpenAI após exclusão de arquivos `.env`/`.env.*` e mascaramento de padrões conhecidos de credenciais; mascaramento não detecta toda credencial possível. Ao baixar repositórios do GitHub, o servidor aceita redirecionamento somente para `codeload.github.com` e limita o download a 20 MB durante a transferência. A análise de código não instala nem executa o projeto, não consulta a infraestrutura implantada e não valida conectividade/disponibilidade do banco; endpoints em execução só são testados quando alguém aciona explicitamente o teste dinâmico (OWASP ZAP) contra um host autorizado. O achado de CSRF é apenas candidato heurístico: requer endpoint mutável e indícios de sessão/cookie no mesmo arquivo, e precisa ser confirmado manualmente. O prompt de correção recomenda validação e diff revisável; não altera arquivos automaticamente. As conclusões sobre hospedagem e banco são inferências dos arquivos analisados, não confirmação do ambiente de produção. A ferramenta não substitui SAST dedicado, análise de composição de software, pentest ou revisão profissional. Regras podem gerar falsos positivos ou não reconhecer falhas; o resultado não certifica segurança, conformidade com a LGPD ou certificação ISO.

Limites atuais: ZIP de 20 MB, conteúdo descompactado de 50 MB, 1.200 entradas, 300 arquivos de texto e 500 KB por arquivo. A consulta OSV cobre npm, PyPI, Packagist e crates.io nos formatos de lockfile reconhecidos pelo analisador.

Os relatórios ficam apenas na memória do processo para permitir o envio ao destinatário configurado e desaparecem quando o servidor reinicia. Há limitação básica de 30 solicitações de API por IP a cada 15 minutos; a consulta de progresso das análises tem limite próprio.

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
- Use uma única instância: sessões e tentativas de login são mantidas em memória e não sobrevivem a reinicializações; perfis, projetos e auditoria ficam em arquivo local (`DATA_DIR`). Para alta disponibilidade ou múltiplas instâncias, é necessário implementar armazenamento compartilhado antes da implantação.
- Valide `/api/health`, os logs do processo, autenticação SSO e os fluxos de análise/relatório em homologação. O endpoint de saúde não verifica conectividade ou validade das credenciais dos serviços externos.