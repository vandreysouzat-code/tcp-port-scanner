# TCP Port Scanner v2.1.0

Scanner TCP escrito em Python para reconhecimento de portas e verificações básicas de HTTP/TLS. Gera relatórios HTML, JSON e CSV.

## Recursos

- Varredura TCP concorrente de portas individuais, listas e intervalos.
- Identificação básica de serviços por porta.
- Verificações básicas de certificados TLS, redirecionamentos e cabeçalhos HTTP.
- Saída de terminal resumida.
- Relatórios detalhados em HTML, JSON e CSV.
- Sem dependências externas de execução.

## Requisitos

- Python 3.10 ou superior.
- `pipx` para instalar o comando globalmente, ou Git para clonar o projeto.

## Instalação recomendada: pipx

### Kali Linux / Debian

Instale o pipx, se necessário:

    sudo apt update
    sudo apt install pipx git
    pipx ensurepath

Feche e reabra o terminal, se solicitado. Instale o scanner:

    pipx install git+https://github.com/vandreysouzat-code/tcp-port-scanner.git

Verifique a instalação:

    tcp-scanner --help

Para atualizar quando uma nova versão for publicada:

    pipx upgrade tcp-port-scanner-vandreysouzat

### Windows ou macOS

Instale Python 3.10+ e pipx seguindo a documentação oficial:
https://pipx.pypa.io/stable/installation/

Depois, execute:

    pipx install git+https://github.com/vandreysouzat-code/tcp-port-scanner.git

Se o comando não for reconhecido, siga as instruções do pipx para adicionar os executáveis ao PATH e reabra o terminal.

## Executar sem instalar o comando

Com Python 3.10+ e Git instalados:

    git clone https://github.com/vandreysouzat-code/tcp-port-scanner.git
    cd tcp-port-scanner
    python3 scanner.py --help

No Windows, se `python3` não existir, tente `python scanner.py --help`.

## Exemplos de uso

Verificar as portas comuns de um domínio autorizado:

    tcp-scanner example.com

Verificar portas específicas:

    tcp-scanner example.com --ports 22,80,443

Verificar um intervalo:

    tcp-scanner example.com --ports 1-1024 --timeout 1.5 --workers 64

Salvar relatórios com um prefixo personalizado:

    tcp-scanner example.com --out reports/example

Desativar verificações HTTP/TLS:

    tcp-scanner example.com --no-web-checks

Ao executar `python3 scanner.py`, use os mesmos argumentos dos exemplos, substituindo `tcp-scanner` por `python3 scanner.py`.

## Relatórios

O scanner gera três arquivos usando o prefixo definido por `--out`:

- `.html`: relatório legível no navegador.
- `.json`: dados estruturados da execução.
- `.csv`: achados em formato tabular.

O diretório de saída é criado automaticamente quando necessário.

## Interpretar os resultados

O scanner faz reconhecimento TCP e verificações web limitadas. Não é um substituto para uma auditoria completa.

- Uma porta aberta não prova a existência de uma vulnerabilidade.
- Um cabeçalho HTTP ausente não comprova, isoladamente, uma falha explorável.
- Uma resposta HTTP 5xx não é automaticamente uma vulnerabilidade.
- A análise web verifica a página raiz e não avalia toda a aplicação.
- Resultados não confirmados não devem ser tratados como vulnerabilidades comprovadas.
- O scanner não garante detectar todas as vulnerabilidades.

## Uso responsável

Use somente em sistemas próprios ou para os quais você tenha autorização explícita. Respeite o escopo, as regras e os limites do programa de segurança aplicável.

## Testes de desenvolvimento

No diretório do projeto:

    python3 -m py_compile scanner.py
    python3 -m unittest -v test_scanner

## Licença

MIT. Consulte o arquivo [LICENSE](LICENSE).
