# TCP Port Scanner v2.0.0

Scanner TCP em Python com verificações HTTP/TLS e relatórios HTML, JSON e CSV.

## Recursos
- Portas individuais, listas e intervalos TCP.
- Varredura concorrente com limites configuráveis.
- Estados: aberta, fechada, sem resposta e erro.
- Verificação de certificado TLS, validade e expiração próxima.
- Verificações básicas de redirecionamento HTTP/HTTPS e cabeçalhos HTTP.
- Sinais de possível exposição de serviços sensíveis, com evidências e recomendações.
- Relatórios HTML, JSON e CSV.
- Sem dependências externas.

## Requisitos
Python 3.10+.

## Uso
```bash
python3 scanner.py example.com
python3 scanner.py example.com --ports 22,80,443
python3 scanner.py example.com --ports 1-1024 --timeout 1.5 --workers 64
python3 scanner.py example.com --out reports/example
python3 scanner.py example.com --no-web-checks
```

O padrão verifica portas comuns para manter a execução mais rápida. `--out` define o prefixo dos três relatórios.

## Interpretação
- A severidade indica prioridade de revisão, não garantia de exploração.
- Porta aberta não confirma vulnerabilidade nem identifica a versão real do serviço.
- Cabeçalho ausente é um sinal de hardening, não prova isolada de falha.
- HTTP 5xx não é automaticamente vulnerabilidade.
- Timeout/sem resposta não prova que a porta esteja filtrada ou segura.
- A análise web verifica somente a página raiz e não testa autenticação, lógica de negócio ou toda a aplicação.

## Uso responsável
Execute apenas em sistemas próprios ou com autorização explícita. Respeite o escopo e os limites do programa de testes.

## Licença
MIT

## Teste funcional local

O scanner foi testado em `127.0.0.1` com um servidor HTTP temporário
na porta TCP 8000. A ferramenta detectou a porta como aberta e gerou
os relatórios HTML, JSON e CSV. O teste validou a detecção básica de
conectividade TCP em ambiente local; não representa uma auditoria
completa de segurança.
