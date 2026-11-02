# ReconForge — revisão e teste prático

Base analisada: `7296631` (2026-11-02). Alterações desta revisão permanecem no workspace, sem commit criado pelo agente.

Durante os testes entrou também o commit `244b0d6` (escape de badges Rich e telemetria visual de secrets/fuzz). A suíte final de 71 testes foi executada sobre o workspace atualizado. O laboratório temporário foi parado após a validação; imagem, container e evidências foram preservados.

## Execuções realizadas

O usuário autorizou explicitamente `seidorcloud.com.br`, `b1cloud.com.br`, seus subdomínios e testes ativos. As execuções usaram o preset full com perfil safe, taxa interna 2 req/s, concorrência 2, limite de 100 probes/200 requests internos e timeout de 45 segundos por ferramenta. Chromium, Amass, Nuclei com um template local GET de inventário e o planner automático foram habilitados explicitamente. O tráfego dos subprocessos não integra o contador HTTP interno.

Comando reproduzível das duas rodadas: `python scripts/run_practical_validation.py`. As linhas completas de cada comando e códigos de término estão em `runs/practical-2026-11-02/manifest.json`. Ambas as execuções principais terminaram com código 0; isso não significa que todas as ferramentas completaram os seus testes.

| Escopo | Hosts no inventário | URLs | Respostas 2xx/3xx | Probes | HTTP interno | URLs pendentes |
|---|---:|---:|---:|---:|---:|---:|
| seidorcloud.com.br | 27 | 720 | 67 | 100 | 178 | 619 |
| b1cloud.com.br | 10 | 149 | 25 | 100 | 134 | 47 |
| Juice Shop local, rodada inicial | 1 | 215 | 70 | 80 | 120 | 135 |

As contagens são inventário, não comprovação de recursos distintos ou de vulnerabilidades. Respostas 302 e fallbacks de SPA podem inflar os números. `max-hosts` governa a seleção inicial de hosts, não o tamanho total do inventário passivo.

Os dois domínios principais tinham delegação NS válida no Route 53, mas sem respostas A/AAAA para o apex. A descoberta passiva encontrou subdomínios utilizáveis. Não alterei a resolução DNS nem testei IPs ou domínios terceiros fora dos escopos.

## Resultado nos domínios autorizados

Nenhuma vulnerabilidade foi confirmada nesta amostra.

- **Seidor:** nenhum candidato a takeover, bypass ou BOLA. Um indicador `private_key_header` em bundle público; a triagem local não encontrou bloco PEM completo. Gitleaks retornou lista vazia e TruffleHog não produziu findings. Trata-se de marcador não confirmado, não de uma chave privada demonstrada. Não se deve reportá-lo como vazamento sem evidência adicional.
- **B1:** nenhum candidato a takeover, bypass ou BOLA e nenhum indicador interno de segredo. O planner inicial selecionou dois assets `livewire.js?id=<hash>`, uma seleção inadequada corrigida nesta revisão.
- **BOLA:** não foi efetivamente exercitado nos alvos, porque não foram fornecidas identidades de teste. Contagem zero não prova controle de acesso correto.
- **Nuclei:** o teste usou um template local revisado com um GET no alvo e extração de cabeçalhos; não foi uma varredura de todos os templates/CVEs.

### Cobertura das ferramentas

- Seidor: Subfinder, Katana, ffuf, Gitleaks, TruffleHog e Nuclei completaram com código 0. Amass e gau atingiram o limite de 45 segundos. O planner não produziu endpoints de injeção nessa amostra.
- B1: Katana, ffuf, Gitleaks, TruffleHog e Nuclei completaram com código 0. Subfinder, Amass e gau atingiram o timeout. Dois SQLMap atingiram o timeout em assets estáticos. Ghauri falhou na leitura do delay decimal antes da correção. Não repeti esses testes remotos em assets irrelevantes.
- Os logs, bancos e dashboards preservam o histórico inicial, inclusive erros e seleção anterior do planner. As correções afetam execuções futuras; os registros não foram reescritos para aparentar sucesso.

## Laboratório para aferir o scanner

Usei **OWASP Juice Shop 20.3.0**, imagem `bkimminich/juice-shop:latest`, digest `sha256:42843723a7bf4246aa5d63c324978b17ef296ac78434aeddd34c427bfb5853f4`. O container foi publicado exclusivamente em `127.0.0.1:80`, com limite de 1 CPU e 1 GiB. Seu nome é `reconforge-juice-validation`.

O teste inicial usou `--full --no-subdomains --allow-private --http-too --no-enum --browser --scan-profile safe`, limites menores e todos os scanners explícitos, limitados a um endpoint cada. A URL pública de busca de produtos foi adicionada como `validation_seed`; não veio da descoberta automática. O teste não realizou dump de banco nem usou dados de terceiros.

O SQLMap retornou negativo com level/risk 1 e o orçamento limitado. Entretanto, uma comparação manual somente de leitura em `/rest/products/search` mostrou:

| Entrada q no laboratório | HTTP | Contagem retornada |
|---|---:|---:|
| vazia | 200 | 46 |
| `')) AND 1=1--` | 200 | 56 |
| `')) AND 1=2--` | 200 | 0 |

A diferença entre condições verdadeira e falsa confirma que a entrada altera a condição SQL nesse laboratório intencionalmente vulnerável. Persisti somente as contagens em `manual-readonly-check.json`, não os registros. Isso evidencia um falso negativo do teste automatizado nessa configuração; perfil safe não garante detecção universal.

Outros resultados locais:

- Katana, ffuf, Gitleaks, TruffleHog e Nuclei completaram.
- Dalfox e Ghauri corrigido atingiram seus timeouts; não há conclusão positiva ou negativa válida a partir deles.
- Ghauri e Commix inicialmente rejeitaram delay decimal. A correção foi validada em novos testes e na execução real: ambos passaram a iniciar seus testes HTTP.
- Commix inicialmente também encerrava com mensagem crítica de dependência ausente, mesmo retornando 0. Instalei `pyreadline3` e acrescentei a dependência/checagem no Windows. Depois disso ele iniciou os testes, mas atingiu o timeout de 30 segundos. Não deve ser contado como scan completo.
- Dois candidatos de bypass iniciais eram a página inicial devolvida ao enviar `X-Original-URL`/`X-Rewrite-URL`; não representavam acesso ao recurso protegido. O filtro foi corrigido e `scripts/validate_lab_fixes.py` comprovou **zero candidatos** no mesmo cenário real.

## Revisão das últimas atualizações

Os recursos novos são úteis: Rich TUI, inventário de ferramentas, auto-instalação, limpeza de payloads históricos, GUI/exportação HTML, acompanhamento de subprocessos e checkpoints de retomada. Porém, testes unitários sozinhos não cobriam contratos dos executáveis instalados nem o ruído real das SPAs.

Corrigi nesta rodada:

1. **Preset full:** agora respeita perfil, limites e diretório explicitamente informados. `--no-subdomains` restringe o full ao hostname exato; `--no-takeover` também é respeitado. Antes, `--full --scan-profile safe` continuava deep.
2. **Planner entre origens:** a deduplicação agora inclui esquema e hostname, evitando perder endpoints de outro subdomínio com o mesmo caminho/parâmetros.
3. **Assets de versão:** arquivos JS/CSS com `id=<hash hexadecimal>` e parâmetros de build deixam de ser enviados automaticamente a scanners de injeção. Endpoints dinâmicos com id permanecem elegíveis.
4. **Windows/BAT:** shims Python simples, como o Commix instalado, são executados pelo Python diretamente, sem shell interpretar `&` e outros caracteres das URLs.
5. **Delay de Ghauri/Commix:** usam segundos inteiros arredondados para cima, conforme as CLIs instaladas. SQLMap continua usando seu delay fracionário compatível.
6. **Dependência Windows:** `pyreadline3` está nos requisitos e na checagem do Commix.
7. **SPA fingindo asset:** uma resposta HTML em URL `.js/.mjs/.map` não é mais dissecada como JavaScript nem gera recursão de rotas falsas.
8. **Dashboard estático:** JSON embutido escapa `<`, `>`, `&` e separadores de linha, impedindo encerramento do elemento script por conteúdo do alvo. Os dashboards já produzidos nesta rodada também foram sanitizados.
9. **Bypass genérico:** respostas iguais à página inicial de controle deixam de ser reportadas como acesso ao recurso protegido.

Validação final: **71 testes aprovados**, incluindo regressões dos problemas acima. Os scripts de execução e os artefatos reais complementam os testes simulados.

## Comandos completos e limites reais

`--full` habilita descoberta, Katana/JSLuice, fuzzing, ffuf, takeover, bypass e scanners locais de segredos. Por padrão expande o perfil para deep. Ele **não** habilita sozinho browser, GUI, Amass, auto-scan, Nuclei ou identidades BOLA.

Comando abrangente em um escopo autorizado, com browser visível e injeção roteada:

```powershell
python reconforge.py seidorcloud.com.br --full --visual --amass --auto-scan --scan-profile fast
```

Para incluir Nuclei com o template de inventário revisado usado nesta validação:

```powershell
python reconforge.py seidorcloud.com.br --full --visual --amass --auto-scan --scan-profile fast --scanners nuclei --nuclei-templates runs/practical-2026-11-02/technology-check.yaml --out runs/seidor-full-fast
```

Para maior profundidade, substitua `fast` por `deep`; isto aumenta intrusividade e volume, incluindo SQLMap risk 3. Não é sinônimo de encontrar tudo. Para headless, troque `--visual` por `--browser`. Para B1, substitua o domínio e use outro `--out`.

Retome com o **mesmo comando e diretório**. Checkpoints passivos/DNS e orçamento interno são reaproveitados; nem todas as fases externas possuem checkpoint por ferramenta/alvo, portanto algumas podem repetir tráfego. Não some `--scanners sqlmap ghauri commix dalfox` ao auto-scan rotineiramente: o caminho manual aplica ferramentas em lote e pode duplicar o trabalho do planner.

Para BOLA faltam contas de teste: adicione `--identity` somente com contas autorizadas e `--credential-host` para hosts HTTPS adicionais quando necessário. Isso é uma dimensão de cobertura distinta de simplesmente ativar mais scanners.

## Artefatos

- `runs/practical-2026-11-02/manifest.json`: comandos e término das rodadas remotas.
- Diretórios `seidorcloud.com.br` e `b1cloud.com.br`: inventários, SQLite, stdout/stderr, resumos e dashboards.
- `juice-shop`: primeira rodada e prova manual somente de leitura.
- `juice-shop-corrected`: controle real após correções de bypass e dependência do Commix.
- `runs/practical-preflight`: help das CLIs instaladas e log dos testes automatizados.
- `runs/practical-2026-11-02/external-scanner-output`: diretório `.output/127.0.0.1` produzido pelos scanners locais, preservado junto à auditoria.

Esses diretórios contêm JS e logs dos alvos; devem ser tratados como material de auditoria, mesmo quando os indicadores internos de segredos usam hashes.

Referências: o [repositório oficial do Juice Shop](https://github.com/juice-shop/juice-shop) distingue a aplicação autohospedada do demo público, que não deve ser usado para hacking. A [documentação da Acunetix](https://www.acunetix.com/support/docs/faqs/registration-evaluation/) identifica seus sites de testes; `testphp.vulnweb.com` teve timeout nesta rede e `testasp.vulnweb.com` respondeu, mas a aferição ativa foi feita no laboratório local para ter controle do ambiente.
