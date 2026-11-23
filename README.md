# Cybersecurity Phishing Study Lab

Plataforma educacional em português para estudar cibersegurança pelo navegador no Windows.

## Estado atual

A interface existente foi preservada. O projeto inclui:
- Painel inicial e trilhas de estudo.
- Exercício fictício para identificar sinais de phishing.
- Conteúdo introdutório de segurança web.
- Cenário de conscientização com feedback.
- Progresso local no navegador.
- API Node.js com autenticação e persistência PostgreSQL (configuração por variáveis de ambiente).

## Referência ao Zphisher original

O projeto de referência [htr-tech/zphisher](https://github.com/htr-tech/zphisher) foi documentado em `modules/zphisher-reference/`. O registro técnico e os limites de compatibilidade estão em [docs/INTEGRACAO-ZPHISHER.md](docs/INTEGRACAO-ZPHISHER.md).

**Importante:** o código operacional de páginas falsas de login, captura de credenciais e túneis de phishing não foi incorporado nem ativado. O Security Lab oferece exercícios defensivos e simulações fictícias, sem coletar senhas reais. A referência upstream é Bash/PHP para ambientes Linux/Termux; Netlify não executa Bash e a API Node.js no Render não é, por si só, um ambiente de execução compatível.

## Segurança e escopo

Este projeto é voltado à defesa, conscientização e análise. Não coleta senhas, não envia campanhas, não clona páginas de login e não contém ferramenta operacional de phishing. Todos os exemplos são fictícios. Use somente sistemas e ambientes para os quais você tenha autorização.

## Executar no Windows

Não é necessário instalar Linux. Abra `index.html` no navegador ou use a opção de deploy do Netlify.

## Publicar no Netlify

1. Entre no Netlify.
2. Escolha **Add new site** e depois **Import an existing project**.
3. Conecte o GitHub e selecione `cybersecurity-phishing-study-lab`.
4. Branch: `main`.
5. Build command: deixe vazio.
6. Publish directory: `.`.
7. Clique em **Deploy**.

## Próximas etapas

- Conectar os exercícios defensivos à API existente.
- Sincronizar o progresso entre dispositivos pelo PostgreSQL.
- Expandir os módulos de análise de URLs, conscientização e relatórios.
- Ambientes de prática isolados e autorizados, sem acesso a alvos externos.
