
import socket
import sys

# Verifica se o usuário informou alvo e portas.
if len(sys.argv) < 3:
    print("Uso: python3 scanner.py <alvo> <porta1> [porta2 ...]")
    sys.exit(1)

alvo = sys.argv[1]

# Converte as portas recebidas em números inteiros.
try:
    portas = [int(p) for p in sys.argv[2:]]
except ValueError:
    print("[ERRO] As portas devem ser números.")
    sys.exit(1)

# Valida o intervalo permitido de portas TCP.
if any(p < 1 or p > 65535 for p in portas):
    print("[ERRO] Use portas entre 1 e 65535.")
    sys.exit(1)

# Verifica se o domínio pode ser resolvido.
try:
    socket.getaddrinfo(alvo, None)
except socket.gaierror:
    print(f"[ERRO] Alvo inválido: {alvo}")
    sys.exit(1)

print(f"\nTCP PORT SCANNER | Alvo: {alvo}")
print("-" * 35)

try:
    for porta in portas:
        try:
            with socket.create_connection(
                (alvo, porta), timeout=2
            ):
                print(f"Porta {porta:<5} ABERTA")

        except ConnectionRefusedError:
            print(f"Porta {porta:<5} FECHADA")

        except socket.timeout:
            print(f"Porta {porta:<5} SEM RESPOSTA")

        except OSError:
            print(f"Porta {porta:<5} ERRO DE CONEXÃO")

except KeyboardInterrupt:
    print("\n[!] Scanner interrompido pelo usuário.")
    sys.exit(130)

print("-" * 35)
print("Verificação concluída.")

import socket

# Nosso alvo de teste
alvo = "scanme.nmap.org"

# Portas que queremos verificar
portas = [22, 80, 443]

# Testa cada porta
for porta in portas:
    try:
        conexao = socket.create_connection(
            (alvo, porta), timeout=2
        )
        conexao.close()
        print(f"Porta {porta}: ABERTA")

    except ConnectionRefusedError:
        print(f"Porta {porta}: FECHADA")

    except OSError:
        print(f"Porta {porta}: SEM RESPOSTA")
