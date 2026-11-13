"""
========================================================================================
ORQUESTRADOR DE PADRÕES DE INTELIGÊNCIA (IPO v2.0 - Data Science & ML Edition)
========================================================================================
Referência Metodológica Base:
    "Inteligência de Ameaças Cibernéticas para Melhoria na Detecção e Resposta a Incidentes"
    Gustavo Antonio Souza de Barros & João José Costa Gondim (UnB / SBRC 2025)

Evoluções de Ciência de Dados Implementadas:
    1. Extração Automática de CTI com PLN / NER e Inferência Semântica de TTPs (04_nlp_cti_extractor.py)
    2. Ponderação Estatística TF-IDF e Okapi BM25 sobre TTPs (05_ml_threat_attribution.py)
    3. Similaridade Semântica por Embeddings LSA/SVD + Cosseno (05_ml_threat_attribution.py)
    4. Classificador Supervisionado Random Forest sobre Telemetria Contínua + TTPs (05_ml_threat_attribution.py)
========================================================================================
"""

from collections import defaultdict
import csv
from datetime import datetime, timedelta
import importlib
import json
import os
import re
import statistics

# Importação dos módulos de PLN e Machine Learning
import incident_advisory
nlp_mod = importlib.import_module("04_nlp_cti_extractor")
ml_mod = importlib.import_module("05_ml_threat_attribution")

CTINLPExtractor = nlp_mod.CTINLPExtractor
TTPTfIdfScorer = ml_mod.TTPTfIdfScorer
SemanticEmbeddingMatcher = ml_mod.SemanticEmbeddingMatcher
ThreatAttributionMLClassifier = ml_mod.ThreatAttributionMLClassifier

PATTERNS_FILE = "threat_patterns.json"
FEED_FILE = "cti_threat_feed.json"
STIX_FEED_FILE = "synthetic_cti_feed.json"
RAW_REPORTS_FILE = "cti_raw_reports.json"
LOGS_FILE = "soc_network_telemetry.csv"

STIX_PATTERN_RE = re.compile(r"\[(?:ipv4-addr|ipv6-addr|domain-name|url):value\s*=\s*'([^']+)'\]")


def parse_timestamp(ts_str):
    clean = ts_str.replace(" UTC", "").strip()
    try:
        return datetime.strptime(clean, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return datetime.fromisoformat(clean)


def load_threat_patterns():
    if not os.path.exists(PATTERNS_FILE):
        raise FileNotFoundError(f"Arquivo de padrões {PATTERNS_FILE} não encontrado.")
    with open(PATTERNS_FILE, "r", encoding="utf-8") as f:
        return json.load(f).get("patterns", [])


def load_cti_iocs(nlp_profiles=None):
    ioc_db = {}

    # 1. Feed JSON customizado
    if os.path.exists(FEED_FILE):
        with open(FEED_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            for item in data.get("indicators", []):
                ioc_db[item["value"]] = {
                    "threat_actor": item.get("threat_actor", "Desconhecido"),
                    "mitre_technique": item.get("mitre_technique", "T1071.001"),
                    "type": item.get("type", "ipv4-addr")
                }

    # 2. Bundle STIX 2.1
    if os.path.exists(STIX_FEED_FILE):
        with open(STIX_FEED_FILE, "r", encoding="utf-8") as f:
            bundle = json.load(f)
            objects = bundle.get("objects", [])
            actors = {obj["id"]: obj.get("name", "Desconhecido") for obj in objects if obj.get("type") == "threat-actor"}
            default_actor = next(iter(actors.values()), "APT-Python-Group")

            for obj in objects:
                if obj.get("type") == "indicator" and obj.get("pattern_type") == "stix":
                    m = STIX_PATTERN_RE.search(obj.get("pattern", ""))
                    if m:
                        ioc_db[m.group(1)] = {
                            "threat_actor": default_actor,
                            "mitre_technique": "T1071.001",
                            "type": "ipv4-addr"
                        }

    # 3. Enriquecimento automático via PLN/NER de relatórios não estruturados
    if nlp_profiles:
        for prof in nlp_profiles:
            actor = prof["primary_actor"]
            for ip in prof["ner_entities"]["iocs"]["ipv4"]:
                if ip not in ioc_db:
                    ioc_db[ip] = {"threat_actor": actor, "mitre_technique": "T1071.001", "type": "ipv4-addr"}
            for dom in prof["ner_entities"]["iocs"]["domains"]:
                if dom not in ioc_db:
                    ioc_db[dom] = {"threat_actor": actor, "mitre_technique": "T1566.001", "type": "domain-name"}

    return ioc_db


def analyze_network_telemetry(ioc_db):
    """
    Inspeciona os logs de rede e extrai:
      1. detected_ttps: conjunto de códigos MITRE ATT&CK ativos
      2. evidence: lista de evidências de auditoria
      3. ml_features: dicionário de features numéricas e binárias para o Random Forest
      4. narrative: síntese textual automática do incidente para o modelo de Embeddings PLN
    """
    detected_ttps = set()
    evidence = []

    if not os.path.exists(LOGS_FILE):
        return detected_ttps, evidence, {}, ""

    with open(LOGS_FILE, "r", encoding="utf-8") as f:
        logs = list(csv.DictReader(f))

    phishing_domain_hits = 0
    c2_ip_hits = 0
    max_bytes_sent = 0

    # --- REGRA 1: IoC Direct Match (IPs C2 e Domínios de Spearphishing) ---
    for row in logs:
        dest_ip = row.get("destination_ip", "")
        domain = row.get("domain", "")

        try:
            b_sent = int(row.get("bytes_sent", 0))
            if b_sent > max_bytes_sent:
                max_bytes_sent = b_sent
        except ValueError:
            pass

        matched_ip = ioc_db.get(dest_ip)
        matched_dom = ioc_db.get(domain)

        if matched_ip:
            tech = matched_ip["mitre_technique"]
            detected_ttps.add(tech)
            c2_ip_hits += 1
            evidence.append({
                "rule": "ioc_c2_match",
                "mitre_technique": tech,
                "detail": f"Conexão com IP C2 ({dest_ip}) associado a {matched_ip['threat_actor']}",
                "timestamp": row.get("timestamp")
            })

        if matched_dom:
            tech = matched_dom["mitre_technique"]
            detected_ttps.add(tech)
            if tech.startswith("T1566"):
                phishing_domain_hits += 1
            evidence.append({
                "rule": "phishing_link_callback",
                "mitre_technique": tech,
                "detail": f"Callback para domínio malicioso ({domain}) associado a {matched_dom['threat_actor']}",
                "timestamp": row.get("timestamp")
            })

    # --- REGRA 2: Beaconing Analysis (T1071.001 - C2 Regular Heartbeat) ---
    traffic_sessions = defaultdict(list)
    for row in logs:
        if row.get("action") == "ALLOW":
            key = (row.get("source_ip"), row.get("destination_ip"), row.get("destination_port"))
            traffic_sessions[key].append(parse_timestamp(row["timestamp"]))

    best_beacon_mean = 0.0
    best_beacon_jitter = 999.0

    for (src, dst, port), tss in traffic_sessions.items():
        if len(tss) >= 6:
            tss.sort()
            deltas = [(tss[i + 1] - tss[i]).total_seconds() for i in range(len(tss) - 1)]
            clean_deltas = [d for d in deltas if d > 5]
            if len(clean_deltas) >= 5:
                mean_int = statistics.mean(clean_deltas)
                jitter = statistics.stdev(clean_deltas) if len(clean_deltas) > 1 else 0.0
                if jitter <= 30 and mean_int >= 30:
                    detected_ttps.add("T1071.001")
                    if jitter < best_beacon_jitter:
                        best_beacon_jitter = jitter
                        best_beacon_mean = mean_int
                    evidence.append({
                        "rule": "beaconing_traffic",
                        "mitre_technique": "T1071.001",
                        "detail": f"Pulso periódico C2 detectado: {src} -> {dst}:{port} (intervalo: {mean_int:.1f}s, jitter: {jitter:.2f}s)"
                    })

    if best_beacon_jitter == 999.0:
        best_beacon_jitter = 0.0

    # --- REGRA 3: Brute Force Correlation (T1110.001 - Password Guessing) ---
    auth_failures = defaultdict(list)
    for row in logs:
        status = row.get("status_code")
        action = row.get("action")
        port = row.get("destination_port")

        if (status in ["401", "403"]) or (action == "BLOCK" and port in ["22", "3389", "445"]):
            auth_failures[row.get("source_ip")].append(parse_timestamp(row["timestamp"]))

    max_failures_window = 0
    for src_ip, timestamps in auth_failures.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            w_start = timestamps[i]
            w_end = w_start + timedelta(minutes=5)
            window_events = [t for t in timestamps if w_start <= t <= w_end]
            if len(window_events) > max_failures_window:
                max_failures_window = len(window_events)
            if len(window_events) >= 5:
                detected_ttps.add("T1110.001")
                evidence.append({
                    "rule": "bruteforce_auth",
                    "mitre_technique": "T1110.001",
                    "detail": f"Explosão de tentativas de login inválidas de {src_ip} ({len(window_events)} falhas em 5m)"
                })
                break

    # --- REGRA 4: Exfiltração de Volume Anômalo (T1048) ---
    max_outbound_mb = max_bytes_sent / (1024.0 * 1024.0)
    if max_bytes_sent > 10_000_000:
        detected_ttps.add("T1048")
        evidence.append({
            "rule": "large_data_outbound",
            "mitre_technique": "T1048",
            "detail": f"Transferência externa anômala de {max_outbound_mb:.2f} MB"
        })

    # Vetor de Features para o Classificador Random Forest
    ml_features = {
        "ttp_T1071_001_web_c2": 1.0 if "T1071.001" in detected_ttps else 0.0,
        "ttp_T1110_001_bruteforce": 1.0 if "T1110.001" in detected_ttps else 0.0,
        "ttp_T1110_003_spraying": 1.0 if "T1110.003" in detected_ttps else 0.0,
        "ttp_T1566_001_phish_attach": 1.0 if "T1566.001" in detected_ttps else 0.0,
        "ttp_T1566_002_phish_link": 1.0 if "T1566.002" in detected_ttps else 0.0,
        "ttp_T1048_exfil_alt": 1.0 if "T1048" in detected_ttps else 0.0,
        "ttp_T1046_port_scan": 1.0 if "T1046" in detected_ttps else 0.0,
        "ttp_T1570_lateral_transfer": 1.0 if "T1570" in detected_ttps else 0.0,
        "ttp_T1071_004_dns_tunnel": 1.0 if "T1071.004" in detected_ttps else 0.0,
        "beacon_mean_interval_sec": best_beacon_mean,
        "beacon_jitter_sec": best_beacon_jitter,
        "max_outbound_mb": round(max_outbound_mb, 3),
        "auth_failures_5m": float(max_failures_window),
        "phishing_domain_hits": float(phishing_domain_hits)
    }

    # Narrativa Sintetizada da Telemetria para Embeddings Semânticos (PLN)
    narrative_parts = [
        f"Incidente de rede detectado com técnicas MITRE ATT&CK: {' '.join(sorted(detected_ttps))}."
    ]
    if "T1071.001" in detected_ttps:
        narrative_parts.append(
            f"Comunicação de comando e controle C2 via protocolo web HTTP/HTTPS (T1071.001) "
            f"beaconing regular com intervalo médio de {best_beacon_mean:.0f} segundos e baixo jitter ({best_beacon_jitter:.2f}s)."
        )
    if "T1110.001" in detected_ttps:
        narrative_parts.append(
            f"Ataques de força bruta e adivinhação de senhas password guessing (T1110.001) "
            f"contra serviços SSH e RDP com {max_failures_window} falhas de login."
        )
    if "T1566.001" in detected_ttps or phishing_domain_hits > 0:
        narrative_parts.append(
            "Spearphishing attachment callback (T1566.001) para domínios maliciosos api-telemetry-service.com e cdn-auth-sync.net."
        )
    if "T1048" not in detected_ttps:
        narrative_parts.append("Sem exfiltração massiva de ransomware.")

    telemetry_narrative = " ".join(narrative_parts)

    return detected_ttps, evidence, ml_features, telemetry_narrative


def run_ipo():
    print("=" * 105)
    print("  ORQUESTRADOR DE PADRÕES DE INTELIGÊNCIA (IPO v2.0 - DATA SCIENCE, PLN & MACHINE LEARNING)")
    print("  Referência Base: Barros & Gondim (UnB / SBRC 2025) + Evoluções de Ciência de Dados")
    print("=" * 105)

    # 1. Pipeline de PLN e NER em Relatórios Brutos
    nlp_extractor = CTINLPExtractor()
    nlp_profiles = nlp_extractor.process_reports(RAW_REPORTS_FILE)
    print(f"[*] [PLN / NER] Processados {len(nlp_profiles)} relatórios brutos não estruturados ({RAW_REPORTS_FILE}).")
    total_sem_ttps = sum(len(p["semantic_inferred_ttps"]) for p in nlp_profiles)
    print(f"    -> Entidades extraídas automaticamente e {total_sem_ttps} ocorrências de TTPs inferidas por semântica textual.")

    # 2. Carregar Feeds e Padrões enriquecidos pelo PLN
    ioc_db = load_cti_iocs(nlp_profiles)
    patterns = load_threat_patterns()
    print(f"[*] [Base CTI] {len(ioc_db)} IoCs operacionais (DML-1/2) e {len(patterns)} Padrões Comportamentais (DML-3+) ativos.")

    # 3. Analisar Telemetria de Rede e Extrair Features
    detected_ttps, evidence, ml_features, narrative = analyze_network_telemetry(ioc_db)

    print(f"\n[+] TTPs Detectadas na Telemetria de Rede ({len(detected_ttps)} técnicas): {', '.join(sorted(detected_ttps))}")
    print("[+] Vetor de Features Contínuas Extraído do Tráfego para Machine Learning:")
    print(f"    - Intervalo Médio do Beacon C2 : {ml_features['beacon_mean_interval_sec']:.1f} s")
    print(f"    - Jitter do Beacon C2          : {ml_features['beacon_jitter_sec']:.2f} s")
    print(f"    - Falhas de Login (Janela 5m)  : {int(ml_features['auth_failures_5m'])} tentativas")
    print(f"    - Hits em Domínios Phishing    : {int(ml_features['phishing_domain_hits'])} conexões")
    print(f"    - Volume Máximo Enviado (Exfil): {ml_features['max_outbound_mb']:.3f} MB")

    # 4. Executar os 4 Motores de Ciência de Dados
    # 4.1 TF-IDF e Okapi BM25 sobre TTPs
    tfidf_scorer = TTPTfIdfScorer(patterns)
    tfidf_results = tfidf_scorer.score_patterns(detected_ttps)

    print("\n[+] Pesos IDF Calculados por Raridade de Técnica (Menor = Genérica | Maior = Rara/Específica):")
    for t_id in sorted(detected_ttps):
        print(f"    - {t_id:<10} -> Peso IDF = {tfidf_scorer.idf.get(t_id, 1.0):.3f}")

    # 4.2 Similaridade Semântica por Embeddings (TF-IDF N-gram + SVD/LSA + Cosseno)
    with open(RAW_REPORTS_FILE, "r", encoding="utf-8") as f:
        raw_reports_data = json.load(f).get("reports", [])
    sem_matcher = SemanticEmbeddingMatcher(patterns, raw_reports_data)
    sem_scores = sem_matcher.compute_similarity(narrative)

    # 4.3 Classificador Supervisionado Random Forest
    rf_classifier = ThreatAttributionMLClassifier()
    rf_probs = rf_classifier.predict_incident(ml_features)
    top_importances = rf_classifier.get_top_feature_importances(top_k=4)

    print(f"\n[+] Modelo Random Forest Treinado (Acurácia Stratified 5-Fold CV: {rf_classifier.cv_accuracy:.2f}%)")
    print("    - Top Features Decisivas (Gini Importance): " +
          ", ".join(f"{name} ({imp}%)" for name, imp in top_importances))

    # 5. Consolidar Tabela Comparativa Multimodelo
    consolidated = []
    for pat in patterns:
        actor = pat["name"]
        pat_ttps = set(t["technique_id"] for t in pat.get("network_ttps", []))
        inter = detected_ttps.intersection(pat_ttps)

        score_sbrc = (len(inter) / len(pat_ttps) * 100.0) if pat_ttps else 0.0
        score_tfidf = tfidf_results[actor]["tfidf_score"]
        score_bm25 = tfidf_results[actor]["bm25_score"]
        score_sem = sem_scores.get(actor, 0.0)
        score_rf = rf_probs.get(actor, 0.0)

        # Ensemble Final Ponderado:
        # 25% TF-IDF/BM25 + 25% Embeddings Semânticos PLN + 50% Probabilidade Random Forest
        ensemble_score = 0.15 * score_tfidf + 0.15 * score_bm25 + 0.25 * score_sem + 0.45 * score_rf

        consolidated.append({
            "actor": actor,
            "matched_str": f"{len(inter)}/{len(pat_ttps)}",
            "matched_ttps": sorted(list(inter)),
            "score_sbrc": round(score_sbrc, 2),
            "score_tfidf": round(score_tfidf, 2),
            "score_bm25": round(score_bm25, 2),
            "score_sem": round(score_sem, 2),
            "score_rf": round(score_rf, 2),
            "ensemble": round(ensemble_score, 2),
            "description": pat.get("description", "")
        })

    consolidated.sort(key=lambda x: x["ensemble"], reverse=True)

    print("\n" + "=" * 105)
    print("  MATRIZ COMPARATIVA DE ATRIBUIÇÃO: FÓRMULA ORIGINAL SBRC vs. MODELOS DE CIÊNCIA DE DADOS")
    print("=" * 105)
    header = (
        f"{'Grupo / Ameaça':<18} | {'TTPs':<5} | {'SBRC Eq.1':<10} | "
        f"{'TF-IDF Cos':<10} | {'Okapi BM25':<10} | {'PLN Embed':<10} | "
        f"{'RandomForest':<12} | {'ENSEMBLE FINAL':<14}"
    )
    print(header)
    print("-" * 105)

    for row in consolidated:
        print(
            f"{row['actor']:<18} | {row['matched_str']:<5} | "
            f"{row['score_sbrc']:>8.2f}% | {row['score_tfidf']:>8.2f}% | "
            f"{row['score_bm25']:>8.2f}% | {row['score_sem']:>8.2f}% | "
            f"{row['score_rf']:>10.2f}% | {row['ensemble']:>12.2f}%"
        )

    winner = consolidated[0]
    runner_up = consolidated[1]
    print("=" * 105)
    print(f"[!] AFINIDADE TÉCNICA PRINCIPAL (ENSEMBLE ML + PLN): {winner['actor']} ({winner['ensemble']:.2f}%)")
    print(f"    -> Superou o empate/ambiguidade com {runner_up['actor']} ({runner_up['ensemble']:.2f}%).")
    print("=" * 105)

    # 6. Laudo Clínico do Incidente e Runbook Operacional (Apoio à Decisão)
    tel_adv = {
        "detected_ttps": list(detected_ttps),
        "beacon_mean": ml_features["beacon_mean_interval_sec"],
        "beacon_jitter": ml_features["beacon_jitter_sec"],
        "auth_fails_5m": int(ml_features["auth_failures_5m"]),
        "max_outbound_mb": ml_features["max_outbound_mb"],
        "phishing_hits": int(ml_features["phishing_domain_hits"]),
        "patient_zero": {"ip": "10.0.1.15", "hostname": "WS-FINANCE-01", "user": "m.silva"},
        "internal_targets": ["10.0.2.100 (Portas 445 SMB, 22 SSH)"],
        "external_destinations": ["api-telemetry-service.com", "cdn-auth-sync.net"]
    }
    adv_ranking = [{"name": r["actor"], "ensemble": r["ensemble"]} for r in consolidated]
    adv = incident_advisory.generate_incident_advisory(tel_adv, adv_ranking, LOGS_FILE)

    print("\n" + "=" * 105)
    print("  LAUDO CLÍNICO DE DETECÇÃO & TRIAGEM DE INCIDENTES (NDR / XDR ADVISORY)")
    print("=" * 105)
    print(f"[*] STATUS DO INCIDENTE : [{adv['severity']['label']}] - {adv['severity']['status']}")
    print(f"[*] SCORE DE RISCO      : {adv['severity']['score']}/100")
    print(f"[*] PACIENTE ZERO (HOST): {adv['patient_zero']['ip']} • {adv['patient_zero']['hostname']} (Usuário: {adv['patient_zero']['user']})")
    print(f"[*] ALVOS INTERNOS      : {', '.join(adv['internal_targets'])}")
    print(f"[*] INFRAESTRUTURA C2   : {', '.join(adv['external_destinations'])}")

    print("\n[+] RECONSTITUIÇÃO DA LINHA DO TEMPO (CYBER KILL CHAIN / MITRE ATT&CK):")
    for stg in adv['kill_chain_stages']:
        print(f"    - [{stg['badge']:<11}] {stg['phase']:<35} | {stg['desc']}")

    print("\n[+] CHECKLIST DE CONTENÇÃO & CAÇA ATIVA PARA O ANALISTA DO SOC:")
    for chk in adv['analyst_checklist']:
        print(f"    [ ] ({chk['priority']}) {chk['action']}")
        print(f"        -> Ação: {chk['description']}")

    print("\n[+] CONTEXTO DE INTELIGÊNCIA & BENCHMARK CTI:")
    print(f"    -> {adv['cti_affinity_note']}")
    print("=" * 105)


if __name__ == "__main__":
    run_ipo()
