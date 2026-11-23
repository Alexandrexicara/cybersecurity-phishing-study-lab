# Cybersecurity Phishing Study Lab

Plataforma educacional em português para estudar cibersegurança pelo navegador no Windows.

## Estado atual

Primeira versão estática da interface, com:
- Painel inicial e trilhas de estudo.
- Exercício fictício para identificar sinais de phishing.
- Conteúdo introdutório de segurança web.
- Cenário de conscientização com feedback.
- Progresso local no navegador.

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

- API no Render para autenticação e dados de conta.
- PostgreSQL no Neon para progresso sincronizado.
- Mais módulos e relatórios.
- Ambientes de prática isolados e autorizados, sem acesso a alvos externos.

A interface atual não depende de backend. O backend será integrado em uma etapa posterior.