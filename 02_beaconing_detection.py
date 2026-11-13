from collections import defaultdict
import csv
from datetime import datetime
import statistics

LOGS_FILE = "soc_network_telemetry.csv"

# Critérios para classificar Beaconing
MIN_REQUESTS = 6          # Mínimo de conexões para analisar estatisticamente
MAX_JITTER_SECONDS = 30   # Desvio padrão tolerado para ser considerado "periódico"

def parse_time(ts_str):
    # Trata formato ISO: "2026-11-06 01:23:45 UTC"
    clean_ts = ts_str.replace(" UTC", "")
    return datetime.strptime(clean_ts, "%Y-%m-%d %H:%M:%S")

def run_beaconing_analysis():
    print(f"[*] Analisando fluxos de tráfego de rede em {LOGS_FILE}...")

    # Agrupar carimbos de data/hora por sessão: (origem, destino, porta)
    traffic_sessions = defaultdict(list)

    with open(LOGS_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Avaliamos tráfego de saída permitido
            if row.get("action") == "ALLOW":
                key = (row["source_ip"], row["destination_ip"], row["domain"], row["destination_port"])
                traffic_sessions[key].append(parse_time(row["timestamp"]))

    beacon_candidates = []

    for (src_ip, dest_ip, domain, port), timestamps in traffic_sessions.items():
        if len(timestamps) < MIN_REQUESTS:
            continue

        timestamps.sort()

        # Calcular deltas em segundos: delta_t = t[i+1] - t[i]
        deltas = [(timestamps[i+1] - timestamps[i]).total_seconds() for i in range(len(timestamps) - 1)]

        # Filtro de sanidade: evitar conexões simultâneas (burst de recursos web normais)
        clean_deltas = [d for d in deltas if d > 5]
        if len(clean_deltas) < MIN_REQUESTS - 1:
            continue

        mean_interval = statistics.mean(clean_deltas)
        std_deviation = statistics.stdev(clean_deltas) if len(clean_deltas) > 1 else 0

        # Se o desvio padrão for baixo, temos um pulso regular (Beacon)
        if std_deviation <= MAX_JITTER_SECONDS and mean_interval >= 30:
            beacon_candidates.append({
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "domain": domain,
                "port": port,
                "total_requests": len(timestamps),
                "mean_interval": round(mean_interval, 2),
                "jitter": round(std_deviation, 2),
                "start": timestamps[0],
                "end": timestamps[-1]
            })

    # Exibição dos resultados
    print(f"\n================ ANÁLISE DE BEACONING C2 ================")
    print(f"Sessões suspeitas identificadas: {len(beacon_candidates)}\n")

    if not beacon_candidates:
        print("[+] Nenhum padrão de beaconing regular detectado.")
        return

    for c in beacon_candidates:
        print(f"[!] DETECÇÃO DE CANAL C2:")
        print(f"    Origem          : {c['src_ip']}")
        print(f"    Destino         : {c['dest_ip']} (Porta {c['port']})")
        print(f"    Domínio         : {c['domain']}")
        print(f"    Total conexões  : {c['total_requests']}")
        print(f"    Intervalo médio : ~{c['mean_interval']}s (a cada {round(c['mean_interval']/60, 1)} min)")
        print(f"    Variação/Jitter : +/- {c['jitter']}s")
        print(f"    Duração total   : {c['start']} até {c['end']}")
        print("-" * 60)

if __name__ == "__main__":
    run_beaconing_analysis()