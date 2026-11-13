from collections import defaultdict
import csv
from datetime import datetime, timedelta

LOGS_FILE = "soc_network_telemetry.csv"

# Regra SIEM: Acima de 5 falhas da mesma origem em 5 minutos
THRESHOLD_FAILURES = 5
TIME_WINDOW_MINUTES = 5

def parse_time(ts_str):
    clean_ts = ts_str.replace(" UTC", "")
    return datetime.strptime(clean_ts, "%Y-%m-%d %H:%M:%S")

def run_bruteforce_detection():
    print(f"[*] Executando regra de correlação para Força Bruta em {LOGS_FILE}...")

    # Mapear tentativas suspeitas por IP de origem
    auth_failures = defaultdict(list)

    with open(LOGS_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            status = row.get("status_code")
            action = row.get("action")
            port = row.get("destination_port")

            # Indicadores de falha de login / autenticação
            is_auth_failure = (status in ["401", "403"]) or (action == "BLOCK" and port in ["22", "3389", "445"])

            if is_auth_failure:
                auth_failures[row["source_ip"]].append({
                    "timestamp": parse_time(row["timestamp"]),
                    "target_ip": row["destination_ip"],
                    "target_port": port,
                    "attempted_user": row.get("source_user", "desconhecido"),
                    "action": action
                })

    alerts = []

    # Janela deslizante de detecção
    for src_ip, events in auth_failures.items():
        events.sort(key=lambda x: x["timestamp"])

        for i in range(len(events)):
            window_start = events[i]["timestamp"]
            window_end = window_start + timedelta(minutes=TIME_WINDOW_MINUTES)

            # Contar eventos que caem dentro dessa janela de 5 minutos
            events_in_window = [e for e in events if window_start <= e["timestamp"] <= window_end]

            if len(events_in_window) >= THRESHOLD_FAILURES:
                targeted_users = list(set(e["attempted_user"] for e in events_in_window))
                targets = list(set(e["target_ip"] for e in events_in_window))
                port = events_in_window[0]["target_port"]

                alerts.append({
                    "attacker_ip": src_ip,
                    "target_ip": targets[0] if len(targets) == 1 else "Múltiplos",
                    "target_port": port,
                    "event_count": len(events_in_window),
                    "window_start": window_start,
                    "window_end": events_in_window[-1]["timestamp"],
                    "usernames": targeted_users
                })
                # Evita duplicar alertas dentro da mesma rajada
                break

    # Exibição do relatório de alertas
    print(f"\n================ ALERTA DE SEGURANÇA: BRUTE FORCE ================")
    print(f"Total de incidentes detectados: {len(alerts)}\n")

    if not alerts:
        print("[+] Nenhuma rajada de falhas de autenticação detectada.")
        return

    for alert in alerts:
        print(f"[!] REGRA DISPARADA: Tentativa de Força Bruta / Password Spraying")
        print(f"    IP Atacante         : {alert['attacker_ip']}")
        print(f"    Servidor Alvo       : {alert['target_ip']} (Porta {alert['target_port']})")
        print(f"    Tentativas no bloco : {alert['event_count']} falhas")
        print(f"    Período do ataque   : {alert['window_start']} até {alert['window_end']}")
        print(f"    Usuários tentados   : {', '.join(alert['usernames'][:8])}")
        print("-" * 60)

if __name__ == "__main__":
    run_bruteforce_detection()