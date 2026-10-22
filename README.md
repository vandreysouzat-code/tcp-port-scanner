# TCP Port Scanner

Scanner de portas TCP desenvolvido em Python como projeto educacional durante meus estudos de programação e cibersegurança no curso Hackers do Bem.

## Funcionalidades

- Verificação de portas TCP.
- Aceita IP ou domínio como alvo.
- Recebe portas como argumentos pelo terminal.
- Valida os números das portas.
- Trata erros de conexão e interrupção com Ctrl+C.
- Utiliza apenas bibliotecas nativas: `socket` e `sys`.

## Requisitos

- Python 3
- Nenhuma dependência externa.

## Como executar

```bash
python3 scanner.py <alvo> <porta1> [porta2 ...]
```

Exemplo:

```bash
python3 scanner.py scanme.nmap.org 22 80 443
```

## Conceitos praticados

- Variáveis e listas.
- Funções e estruturas condicionais.
- Argumentos de linha de comando.
- Conexões TCP com `socket`.
- Tratamento de exceções.

## Uso responsável

Utilize esta ferramenta somente em sistemas próprios, laboratórios autorizados ou alvos cujo teste seja permitido. Respeite as regras de cada programa de segurança.

## Tecnologias

- Python 3
- TCP/IP
- Linux
