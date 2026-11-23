# Módulo de estudo: Zphisher (referência técnica)

Este diretório registra a referência ao projeto original [htr-tech/zphisher](https://github.com/htr-tech/zphisher), sem incorporar nem executar seus componentes de captura de credenciais, páginas falsas de autenticação ou túneis de phishing.

## O que foi identificado no projeto upstream

- Projeto original: Zphisher, versão 2.3.5 conforme o README consultado.
- Implementação: Bash, com dependências de ambiente Linux/Termux e PHP.
- O projeto upstream documenta múltiplos modelos de páginas de login e opções de tunelamento.
- O navegador/Netlify não executa scripts Bash. O backend atual em Node.js/Render também não é um ambiente de shell Linux interativo.

## Como este laboratório usa a referência

O Security Lab mantém a interface, autenticação e API existentes e transforma os conceitos em exercícios defensivos:
1. reconhecer sinais de páginas de login suspeitas;
2. analisar URLs e domínios;
3. estudar indicadores de engenharia social;
4. registrar resultados de simulações fictícias sem receber senhas reais.

## Limite técnico

Este módulo é documentação e trilha defensiva. Não é uma cópia funcional do Zphisher e não inicia campanhas, túneis, páginas de coleta ou captura/armazenamento/encaminhamento de credenciais.

## Fonte

- Repositório original: https://github.com/htr-tech/zphisher
- Licença e avisos: consulte sempre os arquivos atuais do repositório upstream antes de redistribuir qualquer parte do código.
