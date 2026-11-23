# Integração do projeto original — Security Lab

## Repositórios

- Interface e API mantidas neste repositório: https://github.com/Alexandrexicara/cybersecurity-phishing-study-lab
- Projeto de referência: https://github.com/htr-tech/zphisher

## Estado da integração

A referência técnica do Zphisher foi adicionada em `modules/zphisher-reference/`. A interface existente, o README principal e a API Node.js/PostgreSQL devem ser preservados.

O código operacional do upstream não foi copiado nem conectado: ele implementa páginas falsas de autenticação e fluxos de captura de credenciais. A integração permitida neste laboratório é defensiva e simulada, sem coleta de dados reais.

## Compatibilidade

O upstream é Bash/PHP e foi concebido para ambientes Linux/Termux. Netlify hospeda a interface estática e não executa Bash; o serviço atual do Render é uma API Node.js, não um terminal Linux persistente. Apenas copiar os arquivos para a pasta não cria uma execução compatível.

## Próxima etapa de desenvolvimento

Conectar a interface existente a exercícios defensivos do módulo: análise de URL, checklist de indicadores, cenário de conscientização e relatório de aprendizagem. Não alterar autenticação, banco ou rotas existentes sem revisão específica.
