# Auditoria do ReconForge v2

> **Atualização após correções:** os achados abaixo descrevem a base histórica `de4da31`. O código do workspace foi corrigido posteriormente: isolamento CT/identidades/origens, credenciais vinculadas a hosts HTTPS, DNS fixado ao IP validado com pools separados por hostname, política antes do envio, navegador via HTTPX sem seguir redirects, teto de URLs, reservas persistentes, lock de execução, comparação exata de BOLA, distinção de NXDOMAIN, persistência de candidatos e planos sem headers privados em texto puro. O reprodutor agora executa regressões que esperam o comportamento corrigido. Consulte README para as mudanças de uso e limitações das ferramentas externas. Chromium e scanners externos não foram executados nesta máquina; suas integrações permanecem dependentes da versão instalada. A separação do monólito e a expansão de cobertura funcional seguem como melhorias arquiteturais, não como correções realizadas.

Validação após correções: suíte original e regressões de segurança aprovadas, compilação Python e `git diff --check` aprovados, transporte exercitado contra servidor HTTP local, primeira execução e retomada do CLI verificadas com `--no-enum --passive-only` e zero requisições externas. O Claude foi localizado posteriormente por `orca worktree ps` como sessão de chat estruturada concluída, com última resposta `ok`; não havia novo commit além de `de4da31` antes destas correções.

Data: 2026-11-02. Base: `de4da31c9ae53425d5d72fcc0644d18abbea2e73`, branch `feat/security-modules`. Python local: 3.14.4.

## Parecer

O projeto evoluiu em relação ao pipeline Bash: há controle central de fila, SQLite, coleta assíncrona, proveniência, limites internos e separação entre propostas e execução de scanners. Entretanto, ainda não está pronto para operação autônoma com credenciais ou com exigência estrita de escopo. As falhas mais importantes estão nas fronteiras entre transporte, identidade, navegador e ferramentas externas.

O produto atual é um coletor e priorizador de candidatos. Os módulos BOLA, takeover e bypass não confirmam vulnerabilidades. O roteamento de scanners é uma tabela de expressões regulares sobre nomes de parâmetros, útil como sugestão, mas sem inferência de fluxo de dados, tecnologia de backend, propriedade do objeto ou impacto.

## O que foi possível verificar dos agentes

- Executei `orca terminal list --json` e `orca terminal read` nos dois terminais do workspace Recon. Um contém o histórico do Antigravity; o outro mostra somente um prompt de shell.
- Não havia terminal Claude ativo na listagem. A busca de sessões está desativada no Orca (`enabled: false`); não foi possível recuperar o histórico completo dele por essa via.
- O histórico do Antigravity atribui ao Claude os módulos de segurança e o planner. O Git registra os commits sob a identidade do usuário, portanto não prova autoria individual dos agentes.
- Os commits efetivamente presentes são `c229cd0` (motor v2), `31820f7` (módulos e correções), `de4da31` (planner e perfis).
- O Antigravity identificou corretamente os problemas de headers dos scanners e parte do ruído de BOLA/bypass. Porém, sua aprovação geral foi mais forte que a evidência: passar 17 testes não significa cobertura de 100%; não há medição de cobertura.
- A afirmação de proteção contra DNS rebinding é excessiva: a validação DNS e a conexão são separadas, e a primeira é cacheada. O comentário do Antigravity sobre NXDOMAIN também simplifica indevidamente erros de DNS: o código não distingue essas causas.

## Validação executada

1. `python -m unittest discover -s tests -v`: **17/17 passaram**.
2. `python -m py_compile reconforge.py`: passou.
3. `python audit_reconforge_offline.py`: **10 observações reproduzidas**, com MockTransport, resolução simulada e tokens fictícios. Nenhuma requisição externa foi usada nas reproduções.
4. Leitura integral do motor Python, testes, requisitos, documentação, histórico Git e saída disponível dos terminais.

Não executei scanners contra terceiros. Os executáveis sqlmap, ghauri, commix, dalfox, katana, nuclei e ffuf não foram encontrados na consulta local ao PATH. A compatibilidade real dessas integrações e o comportamento do Chromium não foram validados em execução. A análise do navegador abaixo é estática, apoiada na documentação oficial.

## Achados prioritários

### RF-01 — Alta: headers privados enviados a provedores CT

Referências: `reconforge.py:470`, `reconforge.py:555`, `reconforge.py:584`.

O mesmo `httpx.AsyncClient` recebe todos os `-H` e atende tanto o alvo quanto `crt.sh` e Cert Spotter. Isso encaminha `Authorization`, um `Cookie` configurado explicitamente ou outros headers privados aos provedores. CT é habilitado por padrão. A reprodução confirmou `Authorization: Bearer AUDIT_FAKE_TOKEN` em uma chamada simulada a `crt.sh`.

Impacto: divulgação de credenciais a destinos externos ao alvo. Não depende de um servidor malicioso no escopo.

Correção: cliente separado para provedores passivos, com headers públicos mínimos; credenciais associadas a origens explícitas. Evitar também que credenciais de um host sejam aplicadas indistintamente a todos os subdomínios.

### RF-02 — Alta: identidades e sessão anônima não são isoladas

Referências: `reconforge.py:470`, `reconforge.py:1062`, `reconforge.py:1198`, `reconforge.py:1218`.

Todas as identidades usam o cliente global e seu cookie jar. A coleta inicial pode criar cookies; A pode alterá-los; B e anon os reutilizam. Passar `headers=None` para anon mantém o `Authorization` padrão do cliente. Passar headers de B também mantém headers globais não substituídos.

Reprodução: B recebeu o cookie `session=ACCOUNT_A`; a requisição marcada como anônima carregou esse cookie e o Authorization global.

Impacto: matriz inválida, falsos positivos e negativos, atribuição de dados à conta errada. Identidades com tipos distintos de autenticação podem acabar enviando duas credenciais ao mesmo tempo.

Correção: cliente e cookie jar independentes por identidade, contexto anônimo limpo e apenas headers de identificação não secretos compartilhados. Vincular cada identidade às origens autorizadas e registrar a configuração sem valores sensíveis.

### RF-03 — Alta: exclusões e escopo não formam uma barreira única de envio

Referências: `reconforge.py:492`, `reconforge.py:982`, `reconforge.py:1002`, `reconforge.py:1052`, `reconforge.py:1120`.

- `browser.intercept` verifica host e UNSAFE_GET, mas não `--exclude-path`. `put_url` rejeita o armazenamento e depois `route.continue_()` transmite a requisição mesmo assim.
- `raw_get` não aplica `Scope.url`, exclusões de caminho ou UNSAFE_GET. A reprodução direta confirmou envio simulado para caminho excluído e host externo. Isso demonstra falta de defesa no helper; não demonstra, isoladamente, um caminho atual de entrada externa para host arbitrário.
- `takeover` chama `raw_get` na raiz dos hosts, ignorando uma exclusão de `/`.
- A comparação literal de caminhos não considera equivalências de percent-encoding e normalização do servidor. `/blocked` e `/%62locked` não recebem o mesmo tratamento.
- Katana recebe a regex do domínio, que não contém os hosts excluídos. Filtrar sua saída depois não impede requisições já realizadas pela ferramenta.
- ffuf envia a wordlist antes de passar os resultados por `put_url`; caminhos excluídos e ações como `logout` não são filtrados na geração dessa wordlist.

Correção: decisão central de autorização imediatamente antes de cada envio; política equivalente para adaptadores externos. Validar variantes de caminhos de forma conservadora sem destruir a representação original necessária aos testes.

### RF-04 — Alta, inspeção estática: redirecionamentos do navegador podem escapar da interceptação

Referência: `reconforge.py:1002`.

O navegador continua a requisição e segue redirecionamentos automaticamente. A documentação do Playwright informa que o handler de rota é chamado apenas para a URL inicial quando há redirect. Assim, a interceptação atual não basta para assegurar validação de cada salto nem contagem por salto. O coletor HTTPX, que usa `follow_redirects=False`, tem comportamento mais controlável.

Correção: controlar os redirects em transporte que valide cada destino; validar o comportamento com um servidor local que redirecione entre duas origens e para caminho excluído. Este cenário não foi reproduzido com Chromium nesta auditoria.

### RF-05 — Média/alta: identidade e limites internos não são propagados aos scanners

Referências: `reconforge.py:819`, `reconforge.py:904`, `reconforge.py:1354`, `reconforge.py:1384`.

Os comandos não recebem `-H` nem o User-Agent do ReconForge. SQLMap nos perfis fast/deep recebe `--random-agent`. Scanners podem testar uma aplicação diferente daquela descoberta, perder autenticação e deixar de enviar a identificação exigida pelo programa.

`--max-requests` limita apenas parte do tráfego interno. `--concurrency` não governa os threads dos scanners: fast define SQLMap/ghauri com 10 threads e Dalfox com 40 workers. O delay é por mecanismo/ferramenta; não prova uma taxa global de `--rate`. O perfil fast usa SQLMap risk 2; deep usa risk 3. A documentação do SQLMap descreve testes pesados de tempo no risco 2 e testes OR no risco 3.

Correção: adaptadores com configuração explícita de headers, cookies, redirects, exclusões, taxa e versão; registrar quais limites são garantidos. O modo de proposta é um bom padrão, mas o nome safe não deve substituir a definição concreta das operações permitidas.

### RF-06 — Média: BOLA confunde respostas distintas e redirects com acesso válido

Referências: `reconforge.py:1230`, `reconforge.py:1234`.

`same()` retorna verdadeiro se a diferença de tamanho for menor que 64 bytes, mesmo com hashes diferentes. Na reprodução, os corpos `AAAA` e `BBBB` geraram `cross_identity_identical`. `ok()` aceita qualquer status menor que 400, incluindo 302 para login e 304 sem conteúdo. O detalhe do achado fala em corpo 2xx idêntico, mas essa condição não é exigida.

Além disso, uma API pública que responde em `/api` pode virar `anonymous_access`. Sem mapa de propriedade e permissões esperadas, corpos iguais entre contas não comprovam IDOR.

Correção: separar semelhança de identidade; comparar conteúdo estruturado e campos relevantes, exigir resultado semântico de sucesso, validar sessão e propriedade de objetos de teste. Preservar evidências para reprodução manual sem expor valores secretos.

### RF-07 — Média: max_urls não é mais um teto

Referência: `reconforge.py:331`.

A checagem só rejeita novas URLs das fontes gau, subfinder e dns_wordlist. HTML, JSON, JS, sitemaps e outras fontes podem crescer sem esse teto. Reprodução: Store(max_urls=1) aceitou duas URLs HTML. A correção anterior da saturação passiva resolveu uma prioridade à custa de eliminar o limite global.

Impacto: consumo de disco/memória, fila excessiva e processamento improdutivo diante de conteúdo que gera muitas URLs. `max_requests` não limita quantos links são extraídos de uma resposta.

Correção: teto total real, cotas por fonte e reserva para descoberta ativa; registrar contagem de URLs descartadas e limitar variantes por rota/assinatura de parâmetros.

### RF-08 — Média: retomada não garante persistência do orçamento em falhas abruptas

Referências: `reconforge.py:1320`, `reconforge.py:1534`, `reconforge.py:1568`.

Os contadores cumulativos são salvos em `export`, ao final. Um kill do processo ou queda da máquina pode deixar filas já confirmadas no SQLite e contadores antigos. Uma retomada pode enviar mais requisições do que o histórico persistido indica. Dois processos sobre o mesmo `--out` também não têm reserva exclusiva de orçamento/fila.

Há ainda um problema de ordem: uma configuração incompatível é rejeitada em `run`, mas o `finally` chama `export` mesmo assim, podendo sobrescrever relatórios do diretório anterior com metadados da nova tentativa.

Correção: validar configuração antes de abrir estado mutável; lock exclusivo de execução; reservar orçamento persistentemente antes do envio, aceitando eventual subutilização após crash. Checkpoints e exportações atômicas.

### RF-09 — Média: falsos positivos em takeover e bypass

Referências: `reconforge.py:617`, `reconforge.py:1117`, `reconforge.py:1160`.

`resolves()` retorna False para NXDOMAIN, timeout, erro de resolver e IP não público. O takeover interpreta esse booleano como `cname_nxdomain`, uma causa que não foi comprovada. Fingerprints genéricos como `project not found` e `Repository not found` também não provam que o recurso pode ser reivindicado.

O bypass aceita status menor que 400 e corpo diferente do 403, inclusive redirect para login, página de erro, homepage ou resposta menor que 200. Quando o orçamento acaba no meio de `bypass_403`, o return precede a gravação do arquivo: candidatos já encontrados podem não ser exportados.

Correção: resultado DNS estruturado, classificação por evidência e sem declaração de claimability; controles negativos e comparação do recurso protegido; persistir candidatos incrementalmente e exportar mesmo com orçamento esgotado.

### RF-10 — Média: normalização muda o request observado

Referência: `reconforge.py:235`.

`urlencode(sorted(parse_qsl(...)))` altera ordem de parâmetros repetidos e representação de caracteres. Reprodução: `?x=2&x=1` vira `?x=1&x=2`. Aplicações podem considerar primeiro/último valor ou validar assinatura da query original. Isso afeta fidelidade, autenticação e pesquisa de parameter pollution.

Correção: guardar e enviar a URL original validada; usar uma chave de deduplicação separada e configurável. Não tratar equivalência sintática como equivalência funcional universal.

## Outras limitações relevantes

- DNS: o IP validado não é fixado à conexão e o booleano fica cacheado. Há uma janela de rebinding; não é proteção completa contra SSRF. Ferramentas externas têm seus próprios resolvers.
- OpenAPI: métodos são ignorados; caminhos de operações POST/DELETE entram na fila GET, sem construção de parâmetros, substituição de `{id}`, `servers` ou `basePath`. O scanner por regex de JSON pode reenfileirar a mesma rota. Formulários HTML também não incluem os nomes dos inputs.
- Playwright: `response.body()` lê o corpo inteiro antes de aplicar `max_body`; não há teto de download/memória equivalente ao HTTPX. Os headers `-H` também não são configurados no contexto do navegador. Exceções amplamente silenciadas dificultam saber o que falhou.
- Soft-404: calibração ocorre somente com `--fuzz`; a comparação por tamanho com diferença menor que 100 bytes pode marcar conteúdo legítimo, e o sinal não exclui os candidatos do planner.
- Arquivos de candidatos/plano são escritos apenas quando há resultados e podem permanecer antigos em uma retomada sem novos resultados. Contagens do summary e arquivos podem divergir. `scan_plan_endpoints` conta URLs parametrizadas vivas, não o número de entradas efetivamente roteadas.
- Ferramentas: o timeout mata o processo direto, sem gestão explícita de descendentes; cancelamento não possui limpeza própria. Logs externos não têm limite de tamanho; o stderr é lido inteiro antes de recortar os últimos caracteres. Reexecutar scanners no resume pode repetir trabalho e sobrescrever logs.
- Evidências: hashes são úteis, mas falta amostra redigida, horário, identificação da execução e representação reprodutível do request. JS integral, query strings, source URLs e saídas de TruffleHog podem conter segredos; hash no relatório interno não torna todos os artefatos seguros para compartilhar.
- Portabilidade: o plano gerado é Bash mesmo no Windows. Dependências têm somente limites mínimos, não há lockfile nem contrato de versão dos CLIs. README menciona Dalfox v3 `scan`, mas o comando atual gerado usa `url`; requer verificação com a versão instalada.
- Arquitetura: apesar das classes, o motor continua em um arquivo de cerca de 1.700 linhas; a classe Recon acumula transporte, parsing, política, armazenamento, execução e exportação. Algumas funções são tipadas; não há evidência de verificação estática rigorosa.
- Qualidade de testes: o teste do teto de 20 MB replica a expressão de clamp em vez de exercitar `main`; o teste do Throttle não mede taxa/backoff concorrente. Faltam testes de isolamento de sessão, CT, redirects, exclusões no transporte, crash, subprocessos e contratos dos CLIs. Alguns testes criam AsyncClient sem fechá-lo.

## Ordem de correção recomendada

1. Separar transporte CT e credenciais; isolar completamente as identidades e anon.
2. Centralizar política antes do envio e fechar as lacunas do navegador, raw_get, Katana e ffuf.
3. Tornar limites, retomada e exportação consistentes, inclusive em falhas e concorrência de processos.
4. Corrigir comparação BOLA e classificar sinais DNS/HTTP com evidências verificáveis.
5. Criar adaptadores versionados para scanners com identificação, escopo e controles explícitos.
6. Separar módulos, preservar requests originais e ampliar testes de integração locais antes de adicionar mais scanners.

O maior ganho para bug bounty agora vem de precisão, isolamento de contas, fidelidade de requests e evidência reproduzível. Adicionar mais fingerprints ou aumentar threads antes dessas correções tende a aumentar ruído e risco operacional.

## Referências oficiais consultadas

- HTTPX: configuração de clientes e persistência de cookies: https://www.python-httpx.org/advanced/clients/
- Playwright: interceptação de rede e redirects: https://playwright.dev/python/docs/network
- Playwright: API Route: https://playwright.dev/python/docs/api/class-route
- SQLMap: significado de level/risk e opções: https://github.com/sqlmapproject/sqlmap/wiki/Usage

O arquivo `audit_reconforge_offline.py` reproduz defeitos existentes; seus asserts esperam observá-los. Após as correções, deve ser convertido em testes de regressão com as expectativas invertidas.
