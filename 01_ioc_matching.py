import csv
from datetime import datetime
import json
import os
import re

FEED_FILE = "cti_threat_feed.json"
STIX_FEED_FILE = "synthetic_cti_feed.json"
LOGS_FILE = "soc_network_telemetry.csv"

STIX_PATTERN_RE = re.compile(r"\[(?:ipv4-addr|ipv6-addr|domain-name|url):value\s*=\s*'([^']+)'\]")

def load_custom_feed(filepath, ioc_database):
    if not os.path.isfile(filepath):
        print(f"[!] Aviso: Arquivo {filepath} não encontrado.")
        return 0

    with open(filepath, "r", encoding="utf-8") as f:
        feed_data = json.load(f)

    count = 0
    for item in feed_data.get("indicators", []):
        ioc_database[item["value"]] = {
            "threat_actor": item.get("threat_actor", "Desconhecido"),
            "mitre_technique": item.get("mitre_technique", "N/A"),
            "technique_name": item.get("technique_name", "N/A"),
            "confidence": item.get("confidence", 0),
            "source_feed": filepath
        }
        count += 1
    return count

def load_stix_feed(filepath, ioc_database):
    if not os.path.isfile(filepath):
        print(f"[!] Aviso: Arquivo STIX {filepath} não encontrado.")
        return 0

    with open(filepath, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    if bundle.get("type") != "bundle":
        return 0

    objects = bundle.get("objects", [])
    actors = {obj["id"]: obj for obj in objects if obj.get("type") == "threat-actor"}
    malwares = {obj["id"]: obj for obj in objects if obj.get("type") == "malware"}
    relationships = [obj for obj in objects if obj.get("type") == "relationship"]

    # Resolver ator e família de malware padrão do bundle STIX
    default_actor = next((a.get("name") for a in actors.values()), "Desconhecido")
    default_malware = next((m.get("name") for m in malwares.values()), None)

    for rel in relationships:
        src = rel.get("source_ref", "")
        tgt = rel.get("target_ref", "")
        if src in actors and tgt in malwares:
            default_actor = actors[src].get("name", default_actor)
            default_malware = malwares[tgt].get("name", default_malware)

    count = 0
    for obj in objects:
        if obj.get("type") == "indicator" and obj.get("pattern_type") == "stix":
            match = STIX_PATTERN_RE.search(obj.get("pattern", ""))
            if match:
                ioc_value = match.group(1)
                tech_desc = f"STIX Indicator: {obj.get('name', ioc_value)}"
                if default_malware:
                    tech_desc += f" [Malware: {default_malware}]"

                ioc_database[ioc_value] = {
                    "threat_actor": default_actor,
                    "mitre_technique": "T1071",
                    "technique_name": tech_desc,
                    "confidence": obj.get("confidence", 80),
                    "source_feed": f"{filepath} (STIX 2.1)"
                }
                count += 1
    return count

def run_ioc_matching():
    # 1. Carregar e indexar os feeds de CTI (JSON Customizado + Bundle STIX 2.1)
    ioc_database = {}
    custom_count = load_custom_feed(FEED_FILE, ioc_database)
    stix_count = load_stix_feed(STIX_FEED_FILE, ioc_database)

    if not ioc_database:
        print("[!] Erro: Nenhum IoC carregado. Verifique os arquivos de feed.")
        return

    print(f"[*] {len(ioc_database)} IoCs carregados na memória ({custom_count} do feed padrão + {stix_count} do bundle STIX 2.1).")
    print("[*] Iniciando varredura nos logs de rede...")

    matches = []
    matched_events_count = 0

    # 2. Varredura do arquivo de logs avaliando todos os campos candidatos por linha
    with open(LOGS_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            dest_ip = row.get("destination_ip")
            domain = row.get("domain")
            src_ip = row.get("source_ip")

            # Verifica todos os indicadores presentes na mesma conexão (IP de destino, domínio e IP de origem)
            row_matched_values = []
            for candidate in (dest_ip, domain, src_ip):
                if candidate and candidate in ioc_database and candidate not in row_matched_values:
                    row_matched_values.append(candidate)

            if row_matched_values:
                matched_events_count += 1
                for matched_value in row_matched_values:
                    intel = ioc_database[matched_value]
                    matches.append({
                        "timestamp": row["timestamp"],
                        "source_host": row.get("source_hostname"),
                        "source_ip": row.get("source_ip"),
                        "source_user": row.get("source_user"),
                        "matched_ioc": matched_value,
                        "threat_actor": intel["threat_actor"],
                        "technique": f"{intel['mitre_technique']} ({intel['technique_name']})",
                        "source_feed": intel["source_feed"],
                        "action": row.get("action")
                    })

    # 3. Exibição do relatório de triagem
    print(f"\n================ RELATÓRIO DE THREAT HUNTING ================")
    print(f"Total de eventos comprometidos : {matched_events_count}")
    print(f"Total de correspondências IoC  : {len(matches)}\n")

    if not matches:
        print("[+] Nenhum IoC conhecido encontrado no tráfego analisado.")
        return

    # Agrupar por máquina interna comprometida e consolidar múltiplos IoCs/técnicas
    compromised_hosts = {}
    for hit in matches:
        host_key = f"{hit['source_host']} ({hit['source_ip']})"
        compromised_hosts.setdefault(host_key, []).append(hit)

    for host, hits in compromised_hosts.items():
        users = sorted(set(h["source_user"] for h in hits if h.get("source_user")))
        actors = sorted(set(h["threat_actor"] for h in hits if h.get("threat_actor")))
        techniques = sorted(set(h["technique"] for h in hits if h.get("technique")))
        feeds = sorted(set(h["source_feed"] for h in hits if h.get("source_feed")))
        unique_timestamps = sorted(set(h["timestamp"] for h in hits))

        ioc_counts = {}
        for h in hits:
            ioc_counts[h["matched_ioc"]] = ioc_counts.get(h["matched_ioc"], 0) + 1
        ioc_summary = ", ".join(f"{ioc} ({cnt}x)" for ioc, cnt in ioc_counts.items())

        print(f"[-] ALERTA CRÍTICO: Host {host}")
        print(f"    Usuários associados : {', '.join(users)}")
        print(f"    Atores da ameaça    : {', '.join(actors)}")
        print(f"    Técnicas MITRE      : {' | '.join(techniques)}")
        print(f"    IoCs detectados     : {ioc_summary}")
        print(f"    Fontes CTI          : {', '.join(feeds)}")
        print(f"    Eventos / Matches   : {len(unique_timestamps)} conexões ({len(hits)} hits de IoC)")
        print(f"    Primeira conexão    : {hits[0]['timestamp']}")
        print(f"    Última conexão      : {hits[-1]['timestamp']}")
        print("-" * 60)

if __name__ == "__main__":
    run_ioc_matching()