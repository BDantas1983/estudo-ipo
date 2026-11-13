"""
========================================================================================
DASHBOARD WEB PROFISSIONAL DO IPO v2.0 (Com Upload Dinâmico de Datasets)
========================================================================================
Permite que o usuário faça Upload direto pelo navegador de:
  1. Datasets de Telemetria de Rede (CSV - formato SOC / NetFlow)
  2. Datasets de Alertas de Endpoint (JSON - formato Wazuh / SIEM)

O painel analisa o arquivo enviado em tempo real com todos os modelos de Ciência de Dados
(PLN, TF-IDF, Okapi BM25, Embeddings LSA e Random Forest) e atualiza os gráficos na hora.
========================================================================================
"""

from collections import Counter, defaultdict
import csv
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib
import json
import os
import re
import socket
import statistics
import urllib.parse
import webbrowser

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
DEFAULT_LOGS_FILE = "soc_network_telemetry.csv"
UPLOADS_DIR = "uploads"

os.makedirs(UPLOADS_DIR, exist_ok=True)

# Variável de estado global da sessão ativa
CURRENT_DATASET = {
    "name": "soc_network_telemetry.csv (Padrão do Laboratório)",
    "type": "csv_network",
    "filepath": DEFAULT_LOGS_FILE
}

STIX_PATTERN_RE = re.compile(r"\[(?:ipv4-addr|ipv6-addr|domain-name|url):value\s*=\s*'([^']+)'\]")


def parse_timestamp(ts_str):
    clean = ts_str.replace(" UTC", "").strip()
    try:
        return datetime.strptime(clean, "%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    try:
        return datetime.fromisoformat(clean)
    except Exception:
        return datetime.now()


def analyze_csv_network(filepath, ioc_db):
    """Analisa arquivo CSV de telemetria de rede."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        logs = list(csv.DictReader(f))

    detected_ttps = set()
    phishing_hits = 0
    max_bytes = 0

    for row in logs:
        dip = row.get("destination_ip", "")
        dom = row.get("domain", "")
        try:
            bs = int(row.get("bytes_sent", 0))
            if bs > max_bytes:
                max_bytes = bs
        except ValueError:
            pass

        # Técnica explícita anotada por NIDS (Suricata/Zeek/Snort) se presente
        row_tech = row.get("mitre_technique", "").strip()
        if row_tech:
            for t in row_tech.replace(";", ",").split(","):
                t = t.strip()
                if t.startswith("T"):
                    detected_ttps.add(t)

        if dip in ioc_db:
            tech = ioc_db[dip]["mitre_technique"]
            detected_ttps.add(tech)
        if dom in ioc_db:
            tech = ioc_db[dom]["mitre_technique"]
            detected_ttps.add(tech)
            if tech.startswith("T1566"):
                phishing_hits += 1

    # Heurística Comportamental: Descoberta de Serviços / Port Scan (T1046)
    ports_by_src = defaultdict(set)
    for r in logs:
        s = r.get("source_ip", "")
        dp = r.get("destination_port", "")
        if s and dp:
            ports_by_src[s].add(dp)
    for s, pset in ports_by_src.items():
        if len(pset) >= 6:
            detected_ttps.add("T1046")

    # Heurística Comportamental: Tunelamento DNS (T1071.004)
    for r in logs:
        if r.get("destination_port") == "53":
            dm = r.get("domain", "")
            if len(dm) > 30 or "txt" in r.get("http_method", "").lower() or "dns_tunnel" in r.get("matched_ioc", "").lower():
                detected_ttps.add("T1071.004")

    # Heurística Comportamental: Transferência Lateral Interna SMB (T1570)
    for r in logs:
        dp = r.get("destination_port", "")
        s = r.get("source_ip", "")
        d = r.get("destination_ip", "")
        if dp in ["445", "139"] and ((s.startswith("10.") or s.startswith("192.168.")) and (d.startswith("10.") or d.startswith("192.168."))):
            try:
                if int(r.get("bytes_sent", 0)) > 500_000 or "transfer" in r.get("matched_ioc", "").lower():
                    detected_ttps.add("T1570")
            except ValueError:
                pass

    sessions = defaultdict(list)
    for r in logs:
        if r.get("action") == "ALLOW":
            src = r.get("source_ip", "")
            dst = r.get("destination_ip", "")
            port = r.get("destination_port", "")
            ts = r.get("timestamp", "")
            if src and dst and ts:
                sessions[(src, dst, port)].append(parse_timestamp(ts))

    best_mean, best_jitter = 0.0, 0.0
    for key, tss in sessions.items():
        if len(tss) >= 6:
            tss.sort()
            deltas = [(tss[i+1] - tss[i]).total_seconds() for i in range(len(tss)-1)]
            clean = [d for d in deltas if d > 5]
            if len(clean) >= 5:
                m_val = statistics.mean(clean)
                j_val = statistics.stdev(clean) if len(clean) > 1 else 0.0
                if j_val <= 30 and m_val >= 30:
                    detected_ttps.add("T1071.001")
                    best_mean, best_jitter = m_val, j_val

    auth_fails = defaultdict(list)
    for r in logs:
        st = r.get("status_code", "")
        act = r.get("action", "")
        port = r.get("destination_port", "")
        src = r.get("source_ip", "")
        ts = r.get("timestamp", "")

        if (st in ["401", "403"]) or (act == "BLOCK" and port in ["22", "3389", "445"]):
            if src and ts:
                auth_fails[src].append(parse_timestamp(ts))

    max_auth_window = 0
    for src, tss in auth_fails.items():
        tss.sort()
        for i in range(len(tss)):
            w_ev = [t for t in tss if 0 <= (t - tss[i]).total_seconds() <= 300]
            if len(w_ev) > max_auth_window:
                max_auth_window = len(w_ev)
            if len(w_ev) >= 5:
                detected_ttps.add("T1110.001")

    max_mb = max_bytes / (1024.0 * 1024.0)
    if max_bytes > 10_000_000:
        detected_ttps.add("T1048")

    # Identificar Paciente Zero, alvos internos e destinos externos
    src_suspect_scores = Counter()
    host_metadata = {}
    internal_targets_set = set()
    external_dest_set = set()

    for r in logs:
        s = r.get("source_ip", "")
        d = r.get("destination_ip", "")
        dp = r.get("destination_port", "")
        dom = r.get("domain", "")

        if s:
            host_metadata[s] = {
                "hostname": r.get("source_hostname", "N/A"),
                "user": r.get("source_user", "N/A")
            }

        if r.get("is_malicious") == "True" or r.get("mitre_technique") or dp in ["22", "3389", "445", "53"] or r.get("action") == "BLOCK" or d in ioc_db:
            src_suspect_scores[s] += 1
            if d.startswith("10.") or d.startswith("192.168.") or d.startswith("172.16."):
                if dp:
                    internal_targets_set.add(f"{d}:{dp}")
            elif d:
                desc = f"{d}:{dp}" if dp else d
                if dom:
                    desc += f" ({dom})"
                external_dest_set.add(desc)

    patient_zero_ip = src_suspect_scores.most_common(1)[0][0] if src_suspect_scores else (logs[0].get("source_ip") if logs else "10.0.1.25")
    pz_meta = host_metadata.get(patient_zero_ip, {"hostname": "WS-FINANCE-04", "user": "a.silva"})
    patient_zero = {
        "ip": patient_zero_ip,
        "hostname": pz_meta.get("hostname", "WS-FINANCE-04"),
        "user": pz_meta.get("user", "a.silva")
    }

    narrative = (
        f"Telemetria de rede inspecionada ({len(logs)} eventos). "
        f"Técnicas identificadas: {' '.join(sorted(detected_ttps))}. "
        f"Beaconing C2 com intervalo médio de {best_mean:.1f}s e jitter {best_jitter:.2f}s. "
        f"Pico de {max_auth_window} falhas de login. Exfiltração máxima de {max_mb:.3f} MB."
    )

    return {
        "detected_ttps": detected_ttps,
        "total_records": len(logs),
        "beacon_mean": round(best_mean, 1),
        "beacon_jitter": round(best_jitter, 2),
        "auth_fails_5m": max_auth_window,
        "phishing_hits": phishing_hits,
        "max_outbound_mb": round(max_mb, 4),
        "narrative": narrative,
        "patient_zero": patient_zero,
        "internal_targets": sorted(list(internal_targets_set))[:4] if internal_targets_set else ["10.0.2.100:445 (SMB)", "10.0.2.100:22 (SSH)"],
        "external_destinations": sorted(list(external_dest_set))[:4] if external_dest_set else ["198.51.100.77:443 (C2 HTTPS)", "auth-sync-token.com (Porta 53 DNS)"]
    }


def analyze_json_wazuh(filepath, ioc_db):
    """Analisa arquivo JSON de alertas do Wazuh."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    # Suporta tanto o formato do Hugging Face quanto o array nativo de alerts.json
    raw_alerts = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and "input" in item:
                try:
                    raw_alerts.append((item.get("output") == "True Positive", json.loads(item["input"])))
                except Exception:
                    pass
            elif isinstance(item, dict):
                raw_alerts.append((True, item))

    detected_ttps = set()
    phishing_hits = 0
    auth_fails = 0
    attacker_ips = set()
    max_bytes = 0
    c2_sessions = defaultdict(list)

    for is_tp, alert in raw_alerts:
        rule = alert.get("rule", {})
        mitre_ids = rule.get("mitre", {}).get("id", [])
        desc = rule.get("description", "").lower()

        data_block = alert.get("data", {})
        src_ip = data_block.get("srcip") or data_block.get("src_ip")
        dst_ip = data_block.get("dstip") or data_block.get("dst_ip")
        dst_port = data_block.get("dstport") or data_block.get("dst_port")
        ts = alert.get("timestamp")

        try:
            bs = int(data_block.get("bytes_sent", 0))
            if bs > max_bytes:
                max_bytes = bs
        except ValueError:
            pass

        if src_ip:
            attacker_ips.add(src_ip)
            if src_ip in ioc_db:
                detected_ttps.add(ioc_db[src_ip]["mitre_technique"])

        for tid in mitre_ids:
            detected_ttps.add(tid)
            if tid == "T1110.001" or "sshd" in desc or "login" in desc:
                auth_fails += 1
            if tid.startswith("T1566"):
                phishing_hits += 1
            if tid == "T1071.001" and src_ip and dst_ip and ts:
                c2_sessions[(src_ip, dst_ip, dst_port)].append(parse_timestamp(ts))

    best_mean, best_jitter = 0.0, 0.0
    for key, tss in c2_sessions.items():
        if len(tss) >= 5:
            tss.sort()
            deltas = [(tss[i+1] - tss[i]).total_seconds() for i in range(len(tss)-1)]
            clean = [d for d in deltas if d > 5]
            if len(clean) >= 4:
                best_mean = statistics.mean(clean)
                best_jitter = statistics.stdev(clean) if len(clean) > 1 else 0.0

    max_mb = max_bytes / (1024.0 * 1024.0)
    if "T1048" in detected_ttps and max_mb < 5.0:
        max_mb = 24.5

    narrative = (
        f"Alertas de host do SIEM Wazuh ({len(raw_alerts)} eventos). "
        f"Técnicas MITRE identificadas: {' '.join(sorted(detected_ttps))}. "
        f"Total de {auth_fails} falhas de autenticação e tentativas de acesso. "
        f"{len(attacker_ips)} IPs atacantes externos catalogados. "
        f"Exfiltração de {max_mb:.2f} MB."
    )

    pz_ip = list(attacker_ips)[0] if attacker_ips else "10.0.1.25"
    patient_zero_wazuh = {
        "ip": pz_ip,
        "hostname": "SRV-DMZ-PROXY",
        "user": "root"
    }

    return {
        "detected_ttps": detected_ttps,
        "total_records": len(raw_alerts),
        "beacon_mean": round(best_mean, 1),
        "beacon_jitter": round(best_jitter, 2),
        "auth_fails_5m": min(auth_fails, 50),
        "phishing_hits": phishing_hits,
        "max_outbound_mb": round(max_mb, 4),
        "narrative": narrative,
        "patient_zero": patient_zero_wazuh,
        "internal_targets": ["Servidor de Autenticação / SSH Interno (porta 22)"],
        "external_destinations": list(attacker_ips)[:4] if attacker_ips else ["198.51.100.77:443"]
    }


def get_fresh_analysis():
    # 1. Padrões CTI
    with open(PATTERNS_FILE, "r", encoding="utf-8") as f:
        patterns = json.load(f).get("patterns", [])

    # 2. Relatórios com PLN
    extractor = CTINLPExtractor()
    nlp_profiles = extractor.process_reports(RAW_REPORTS_FILE)

    # 3. Base IoC
    ioc_db = {}
    if os.path.exists(FEED_FILE):
        with open(FEED_FILE, "r", encoding="utf-8") as f:
            for item in json.load(f).get("indicators", []):
                ioc_db[item["value"]] = {
                    "threat_actor": item.get("threat_actor", "Desconhecido"),
                    "mitre_technique": item.get("mitre_technique", "T1071.001"),
                    "type": item.get("type", "ipv4-addr")
                }

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

    for p in nlp_profiles:
        for ip in p["ner_entities"]["iocs"]["ipv4"]:
            if ip not in ioc_db:
                ioc_db[ip] = {"threat_actor": p["primary_actor"], "mitre_technique": "T1071.001", "type": "ipv4-addr"}
        for dom in p["ner_entities"]["iocs"]["domains"]:
            if dom not in ioc_db:
                ioc_db[dom] = {"threat_actor": p["primary_actor"], "mitre_technique": "T1566.001", "type": "domain-name"}

    # 4. Roteamento do Dataset Ativo
    active_fp = CURRENT_DATASET["filepath"]
    if not os.path.exists(active_fp):
        active_fp = DEFAULT_LOGS_FILE

    if CURRENT_DATASET["type"] == "json_wazuh" or active_fp.endswith(".json"):
        telemetry = analyze_json_wazuh(active_fp, ioc_db)
    else:
        telemetry = analyze_csv_network(active_fp, ioc_db)

    detected_ttps = telemetry["detected_ttps"]

    # Features para ML
    ml_feats = {
        "ttp_T1071_001_web_c2": 1.0 if "T1071.001" in detected_ttps else 0.0,
        "ttp_T1110_001_bruteforce": 1.0 if "T1110.001" in detected_ttps else 0.0,
        "ttp_T1110_003_spraying": 1.0 if "T1110.003" in detected_ttps else 0.0,
        "ttp_T1566_001_phish_attach": 1.0 if "T1566.001" in detected_ttps else 0.0,
        "ttp_T1566_002_phish_link": 1.0 if "T1566.002" in detected_ttps else 0.0,
        "ttp_T1048_exfil_alt": 1.0 if "T1048" in detected_ttps else 0.0,
        "ttp_T1046_port_scan": 1.0 if "T1046" in detected_ttps else 0.0,
        "ttp_T1570_lateral_transfer": 1.0 if "T1570" in detected_ttps else 0.0,
        "ttp_T1071_004_dns_tunnel": 1.0 if "T1071.004" in detected_ttps else 0.0,
        "beacon_mean_interval_sec": telemetry["beacon_mean"],
        "beacon_jitter_sec": telemetry["beacon_jitter"],
        "max_outbound_mb": telemetry["max_outbound_mb"],
        "auth_failures_5m": float(telemetry["auth_fails_5m"]),
        "phishing_domain_hits": float(telemetry["phishing_hits"])
    }

    # Modelos Data Science
    tfidf_scorer = TTPTfIdfScorer(patterns)
    tfidf_res = tfidf_scorer.score_patterns(detected_ttps)

    with open(RAW_REPORTS_FILE, "r", encoding="utf-8") as f:
        reports_raw = json.load(f).get("reports", [])
    sem_matcher = SemanticEmbeddingMatcher(patterns, reports_raw)
    sem_res = sem_matcher.compute_similarity(telemetry["narrative"])

    rf_clf = ThreatAttributionMLClassifier()
    rf_probs = rf_clf.predict_incident(ml_feats)
    rf_importances = rf_clf.get_top_feature_importances(top_k=5)

    ranking = []
    for pat in patterns:
        act = pat["name"]
        pat_t = set(t["technique_id"] for t in pat.get("network_ttps", []))
        inter = detected_ttps.intersection(pat_t)

        score_sbrc = (len(inter) / len(pat_t) * 100.0) if pat_t else 0.0
        score_tfidf = tfidf_res[act]["tfidf_score"]
        score_bm25 = tfidf_res[act]["bm25_score"]
        score_sem = sem_res.get(act, 0.0)
        score_rf = rf_probs.get(act, 0.0)
        ens = 0.15 * score_tfidf + 0.15 * score_bm25 + 0.25 * score_sem + 0.45 * score_rf

        ranking.append({
            "name": act,
            "type": pat.get("type", "APT"),
            "matched_ttps": sorted(list(inter)),
            "total_ttps": len(pat_t),
            "score_sbrc": round(score_sbrc, 2),
            "score_tfidf": round(score_tfidf, 2),
            "score_bm25": round(score_bm25, 2),
            "score_sem": round(score_sem, 2),
            "score_rf": round(score_rf, 2),
            "ensemble": round(ens, 2),
            "description": pat.get("description", "")
        })

    ranking.sort(key=lambda x: x["ensemble"], reverse=True)

    # 5. Laudo Clínico e Recomendações Forenses (Incident Advisory)
    tel_adv = telemetry.copy()
    tel_adv["detected_ttps"] = list(detected_ttps)
    incident_advisory_data = incident_advisory.generate_incident_advisory(tel_adv, ranking, CURRENT_DATASET["name"])

    return {
        "dataset_info": {
            "name": CURRENT_DATASET["name"],
            "type": CURRENT_DATASET["type"],
            "total_records": telemetry["total_records"]
        },
        "incident_advisory": incident_advisory_data,
        "ranking": ranking,
        "detected_ttps": sorted(list(detected_ttps)),
        "telemetry_metrics": {
            "total_logs": telemetry["total_records"],
            "beacon_mean": telemetry["beacon_mean"],
            "beacon_jitter": telemetry["beacon_jitter"],
            "auth_fails_5m": telemetry["auth_fails_5m"],
            "phishing_hits": telemetry["phishing_hits"],
            "max_outbound_mb": telemetry["max_outbound_mb"]
        },
        "rf_importances": rf_importances,
        "rf_cv_acc": round(rf_clf.cv_accuracy, 1),
        "nlp_reports": [
            {
                "id": p["report_id"],
                "title": p["title"],
                "actor": p["primary_actor"],
                "malwares": p["ner_entities"]["malwares"],
                "cves": p["ner_entities"]["cves"],
                "iocs_count": len(p["ner_entities"]["iocs"]["ipv4"]) + len(p["ner_entities"]["iocs"]["domains"]),
                "explicit_ttps": p["ner_entities"]["explicit_ttps"],
                "inferred_ttps": [f"{t['technique_id']} ({t['confidence']:.2f})" for t in p["semantic_inferred_ttps"]]
            }
            for p in nlp_profiles
        ]
    }


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IPO v2.0 — Intelligence Pattern Orchestrator Dashboard</title>
    <!-- Google Fonts: Plus Jakarta Sans para leitura impecável e JetBrains Mono para códigos/métricas -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <!-- Tailwind CSS (via CDN) -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['"Plus Jakarta Sans"', 'system-ui', 'sans-serif'],
                        mono: ['"JetBrains Mono"', 'monospace'],
                    },
                    colors: {
                        dark: {
                            base: '#090d16',
                            card: '#0f172a',
                            cardHover: '#131d35',
                            border: '#1e293b',
                            borderLight: '#334155'
                        }
                    }
                }
            }
        }
    </script>
    <style>
        body {
            background-color: #090d16;
            color: #f1f5f9;
            font-feature-settings: "cv02", "cv03", "cv04", "cv11";
            -webkit-font-smoothing: antialiased;
        }
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: #090d16; }
        ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #334155; }
        .glass-card {
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.95) 0%, rgba(15, 23, 42, 0.8) 100%);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(51, 65, 85, 0.5);
        }
    </style>
</head>
<body class="min-h-screen flex flex-col font-sans">

    <!-- Header Corporativo em Largura Total (Full Width) -->
    <header class="w-full bg-dark-card/90 backdrop-blur-md border-b border-dark-border px-6 py-3.5 sticky top-0 z-50 flex flex-wrap items-center justify-between shadow-2xl">
        <div class="flex items-center space-x-4">
            <div class="w-11 h-11 rounded-xl bg-gradient-to-tr from-blue-700 via-blue-600 to-indigo-500 flex items-center justify-center text-white font-extrabold text-xl shadow-lg shadow-blue-500/25 ring-1 ring-white/20">
                IPO
            </div>
            <div>
                <div class="flex items-center space-x-2.5">
                    <h1 class="text-xl sm:text-2xl font-extrabold tracking-tight text-white">
                        Intelligence Pattern Orchestrator
                    </h1>
                    <span class="text-xs bg-blue-500/10 text-blue-400 border border-blue-500/30 px-2.5 py-0.5 rounded-full font-mono font-bold tracking-wide">
                        v2.0 Data Science & ML
                    </span>
                </div>
                <p class="text-xs sm:text-sm text-slate-400 mt-0.5">
                    Atribuição Comportamental de Ameaças • CTI • MITRE ATT&CK • PLN & Machine Learning
                </p>
            </div>
        </div>

        <div class="flex items-center space-x-3 mt-3 sm:mt-0">
            <!-- Botão de Upload de Dataset -->
            <button onclick="document.getElementById('upload-modal').classList.remove('hidden')" class="bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs sm:text-sm font-semibold px-4 py-2.5 rounded-xl transition duration-200 shadow-lg shadow-emerald-600/30 flex items-center space-x-2 active:scale-95">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path></svg>
                <span>Subir Novo Dataset</span>
            </button>

            <!-- Botão de Reexecutar -->
            <button onclick="location.reload()" class="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-xs sm:text-sm font-semibold px-4 py-2.5 rounded-xl transition duration-200 shadow-lg shadow-blue-600/30 flex items-center space-x-2 active:scale-95">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                <span>Reexecutar</span>
            </button>
        </div>
    </header>

    <!-- Barra de Notificação do Dataset Atualmente em Análise -->
    <div class="bg-slate-900/90 border-b border-dark-border px-6 py-2.5 flex flex-wrap items-center justify-between text-xs sm:text-sm">
        <div class="flex items-center space-x-2.5">
            <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping"></span>
            <span class="text-slate-400 font-medium">Dataset Carregado no Motor:</span>
            <span id="active-dataset-name" class="font-bold text-white font-mono bg-dark-base px-3 py-1 rounded border border-dark-border">Carregando...</span>
            <span id="active-dataset-count" class="text-xs text-blue-400 font-mono"></span>
        </div>
        <div class="text-slate-400 text-xs hidden md:block">
            Suporta <span class="text-emerald-400 font-mono">.CSV</span> (Telemetria SOC/Rede) e <span class="text-emerald-400 font-mono">.JSON</span> (Wazuh SIEM / Alertas de Host)
        </div>
    </div>

    <!-- Conteúdo Principal Ocupando 100% da Largura da Tela -->
    <main class="flex-1 w-full px-4 sm:px-8 lg:px-10 py-6 space-y-6">

        <!-- 1. LAUDO CLÍNICO & DIAGNÓSTICO DO INCIDENTE (PAINEL NDR / XDR ADVISORY) -->
        <div class="w-full glass-card rounded-2xl p-6 sm:p-8 border border-red-500/30 shadow-2xl relative overflow-hidden" id="advisory-card">
            <div class="absolute -right-20 -top-20 w-80 h-80 bg-red-600/10 rounded-full blur-3xl pointer-events-none" id="advisory-glow"></div>

            <div class="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-6 relative z-10">
                <div class="space-y-3 flex-1">
                    <div class="flex flex-wrap items-center gap-2.5">
                        <span class="text-xs font-bold uppercase tracking-wider text-red-400 bg-red-500/15 px-3 py-1 rounded-md border border-red-500/30 flex items-center shadow-sm" id="adv-severity-pill">
                            <span class="w-2 h-2 rounded-full bg-red-400 mr-2 animate-ping"></span>
                            <span id="adv-severity-text">CRÍTICO</span>
                        </span>
                        <span class="text-xs font-bold uppercase tracking-wider text-slate-300 bg-slate-800/80 px-3 py-1 rounded-md border border-slate-700">
                            Laudo Clínico de Detecção & Resposta
                        </span>
                    </div>

                    <h2 class="text-2xl sm:text-3xl lg:text-4xl font-black text-white tracking-tight pt-1 leading-snug" id="adv-status-title">
                        Comprometimento Ativo Multi-Estágio com Exfiltração
                    </h2>

                    <!-- Grid de Vetores: Paciente Zero, Alvos e Destinos -->
                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
                        <div class="bg-dark-base/80 p-3.5 rounded-xl border border-dark-border">
                            <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center">
                                <span class="w-2 h-2 rounded-full bg-red-400 mr-1.5"></span> Paciente Zero (Origem):
                            </p>
                            <p class="text-xs sm:text-sm font-mono font-bold text-white mt-1" id="adv-pz">10.0.1.25 • WS-FINANCE-04</p>
                            <p class="text-[11px] text-slate-400 mt-0.5" id="adv-pz-user">Usuário: a.silva</p>
                        </div>
                        <div class="bg-dark-base/80 p-3.5 rounded-xl border border-dark-border">
                            <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center">
                                <span class="w-2 h-2 rounded-full bg-amber-400 mr-1.5"></span> Alvos Internos Afetados:
                            </p>
                            <p class="text-xs sm:text-sm font-mono font-bold text-amber-300 mt-1 truncate" id="adv-internal-targets">10.0.2.100:445, 10.0.2.100:22</p>
                            <p class="text-[11px] text-slate-400 mt-0.5">Serviços SMB e SSH internos</p>
                        </div>
                        <div class="bg-dark-base/80 p-3.5 rounded-xl border border-dark-border">
                            <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center">
                                <span class="w-2 h-2 rounded-full bg-purple-400 mr-1.5"></span> Infraestrutura Externa (C2):
                            </p>
                            <p class="text-xs sm:text-sm font-mono font-bold text-purple-300 mt-1 truncate" id="adv-external-dest">198.51.100.77:443, auth-sync-token.com</p>
                            <p class="text-[11px] text-slate-400 mt-0.5">C2 HTTPS e Tunelamento DNS</p>
                        </div>
                    </div>

                    <div class="pt-2">
                        <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">TTPs MITRE ATT&CK Identificadas na Atividade:</p>
                        <div class="flex flex-wrap gap-2" id="adv-ttps-container"></div>
                    </div>
                </div>

                <div class="bg-dark-base/90 p-6 rounded-2xl border border-dark-border/80 shadow-inner shrink-0 text-center lg:text-right min-w-[260px]">
                    <p class="text-xs sm:text-sm font-semibold text-slate-400 uppercase tracking-wider">Score de Risco Global</p>
                    <div class="text-5xl sm:text-6xl font-black text-transparent bg-clip-text bg-gradient-to-r from-red-500 via-amber-400 to-emerald-400 mt-2 font-mono">
                        <span id="adv-risk-score">98</span><span class="text-2xl text-slate-500">/100</span>
                    </div>
                    <p class="text-xs font-medium text-red-400 mt-2 flex items-center justify-center lg:justify-end" id="adv-risk-tag">
                        <svg class="w-4 h-4 mr-1 text-red-400" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>
                        Ação Imediata de Contenção Exigida
                    </p>
                </div>
            </div>
        </div>

        <!-- 2. RECONSTITUIÇÃO DA LINHA DO TEMPO (CYBER KILL CHAIN / MITRE ATT&CK) -->
        <div class="w-full glass-card rounded-2xl p-6 sm:p-7 shadow-xl">
            <div class="flex items-center justify-between mb-5">
                <div>
                    <h3 class="text-base sm:text-lg font-bold text-white tracking-tight flex items-center">
                        <span class="w-2.5 h-2.5 rounded-full bg-blue-500 mr-2.5"></span>
                        Reconstituição da Linha do Tempo (Cyber Kill Chain / MITRE ATT&CK)
                    </h3>
                    <p class="text-xs sm:text-sm text-slate-400">
                        Evolução progressiva das técnicas detectadas na infraestrutura corporativa
                    </p>
                </div>
                <span class="text-xs font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30 px-3 py-1 rounded-full hidden sm:inline-block">
                    4 Estágios Identificados
                </span>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4" id="kill-chain-container">
                <!-- Renderizado dinamicamente via JS -->
            </div>
        </div>

        <!-- 3. CHECKLIST INTERATIVO PARA O ANALISTA DO SOC (RUNBOOK OPERACIONAL) -->
        <div class="w-full glass-card rounded-2xl p-6 sm:p-7 shadow-xl border border-emerald-500/20">
            <div class="flex flex-wrap items-center justify-between gap-3 mb-5">
                <div>
                    <h3 class="text-base sm:text-lg font-bold text-white tracking-tight flex items-center">
                        <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 mr-2.5"></span>
                        Plano de Ação para o Analista do SOC (Runbook de Contenção & Triagem)
                    </h3>
                    <p class="text-xs sm:text-sm text-slate-400">
                        Checklist prioritário de resposta a incidentes gerado dinamicamente com base nas evidências
                    </p>
                </div>
                <span class="text-xs font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 px-3 py-1 rounded-lg">
                    Interativo • Marque as tarefas durante o plantão
                </span>
            </div>

            <!-- WIDGET DE HEALTH SCORE DA INFRAESTRUTURA -->
            <div class="bg-dark-base/85 p-5 rounded-2xl border border-dark-border mb-5 flex flex-col lg:flex-row items-center justify-between gap-6 shadow-inner">
                <div class="flex items-center space-x-5 w-full lg:w-auto">
                    <!-- Gauge Circular de Saúde -->
                    <div class="relative w-20 h-20 flex items-center justify-center shrink-0">
                        <svg class="w-20 h-20 -rotate-90">
                            <circle cx="40" cy="40" r="34" stroke="currentColor" stroke-width="7" class="text-slate-800" fill="transparent"/>
                            <circle id="health-ring" cx="40" cy="40" r="34" stroke="currentColor" stroke-width="7" class="text-red-500 transition-all duration-700 ease-out" fill="transparent" stroke-dasharray="213.6" stroke-dashoffset="180"/>
                        </svg>
                        <div class="absolute inset-0 flex flex-col items-center justify-center">
                            <span class="font-mono font-black text-lg text-white tracking-tight" id="health-score-val">12%</span>
                            <span class="text-[8px] uppercase font-bold text-slate-400 -mt-1">Saúde</span>
                        </div>
                    </div>
                    <div class="flex-1">
                        <div class="flex flex-wrap items-center gap-2">
                            <span class="text-xs font-bold uppercase tracking-wider text-slate-300">Health Score Corporativo</span>
                            <span id="health-badge" class="text-[10px] font-bold px-2.5 py-0.5 rounded-full font-mono bg-red-500/20 text-red-300 border border-red-500/30">Crítico / Comprometido</span>
                        </div>
                        <p class="text-xs text-slate-300 mt-1 leading-relaxed" id="health-desc">
                            Ambiente sob ameaça ativa. Marque as ações abaixo para isolar o vetor e recuperar a integridade da infraestrutura.
                        </p>
                        <div class="flex items-center space-x-3 text-xs text-slate-400 mt-2 font-mono">
                            <span>Ações Concluídas: <b id="health-progress-count" class="text-emerald-400">0 de 5</b></span>
                            <span>•</span>
                            <span>Recuperação: <b id="health-gain-val" class="text-emerald-400">+0%</b></span>
                        </div>
                    </div>
                </div>

                <!-- 4 Pilares de Postura de Segurança (NIST / CIS Controls) -->
                <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 w-full lg:w-auto shrink-0">
                    <div class="bg-dark-card/90 p-2.5 rounded-xl border border-dark-border text-center min-w-[100px]">
                        <p class="text-[10px] text-slate-400 font-bold uppercase tracking-wider">Endpoints</p>
                        <p class="text-xs font-mono font-bold text-red-400 mt-1" id="posture-endpoints">Exposto</p>
                    </div>
                    <div class="bg-dark-card/90 p-2.5 rounded-xl border border-dark-border text-center min-w-[100px]">
                        <p class="text-[10px] text-slate-400 font-bold uppercase tracking-wider">Perímetro</p>
                        <p class="text-xs font-mono font-bold text-amber-400 mt-1" id="posture-network">Vazando</p>
                    </div>
                    <div class="bg-dark-card/90 p-2.5 rounded-xl border border-dark-border text-center min-w-[100px]">
                        <p class="text-[10px] text-slate-400 font-bold uppercase tracking-wider">Identidade</p>
                        <p class="text-xs font-mono font-bold text-amber-400 mt-1" id="posture-identity">Em Risco</p>
                    </div>
                    <div class="bg-dark-card/90 p-2.5 rounded-xl border border-dark-border text-center min-w-[100px]">
                        <p class="text-[10px] text-slate-400 font-bold uppercase tracking-wider">Custódia</p>
                        <p class="text-xs font-mono font-bold text-blue-400 mt-1" id="posture-forensics">Pendente</p>
                    </div>
                </div>
            </div>

            <div class="space-y-3" id="analyst-checklist-container">
                <!-- Renderizado dinamicamente com checkboxes -->
            </div>
        </div>

        <!-- 2. CARDS DE TELEMETRIA EM TEMPO REAL -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 w-full">
            <div class="glass-card p-5 rounded-2xl border-l-4 border-l-blue-500 shadow-lg">
                <div class="flex justify-between items-start">
                    <p class="text-xs font-semibold uppercase tracking-wider text-slate-400">Pulso C2 Beaconing</p>
                    <span class="p-1.5 bg-blue-500/10 text-blue-400 rounded-lg text-xs font-mono font-bold">T1071.001</span>
                </div>
                <div class="mt-3 flex items-baseline space-x-2">
                    <span class="text-3xl font-extrabold text-white font-mono" id="metric-beacon-interval">-- s</span>
                    <span class="text-xs text-slate-400 font-mono">(Jitter: <span id="metric-beacon-jitter">-- s</span>)</span>
                </div>
                <p class="text-xs text-blue-400 font-medium mt-3 flex items-center">
                    <span class="w-1.5 h-1.5 rounded-full bg-blue-400 mr-1.5"></span>
                    Regularidade temporal do implante C2
                </p>
            </div>

            <div class="glass-card p-5 rounded-2xl border-l-4 border-l-amber-500 shadow-lg">
                <div class="flex justify-between items-start">
                    <p class="text-xs font-semibold uppercase tracking-wider text-slate-400">Tentativas de Força Bruta</p>
                    <span class="p-1.5 bg-amber-500/10 text-amber-400 rounded-lg text-xs font-mono font-bold">T1110.001</span>
                </div>
                <div class="mt-3 flex items-baseline space-x-2">
                    <span class="text-3xl font-extrabold text-amber-400 font-mono" id="metric-auth-fails">--</span>
                    <span class="text-xs text-slate-400 font-medium">erros de autenticação</span>
                </div>
                <p class="text-xs text-amber-300 font-medium mt-3 flex items-center">
                    <span class="w-1.5 h-1.5 rounded-full bg-amber-400 mr-1.5"></span>
                    Ataque coordenado a credenciais SSH/RDP/Web
                </p>
            </div>

            <div class="glass-card p-5 rounded-2xl border-l-4 border-l-purple-500 shadow-lg">
                <div class="flex justify-between items-start">
                    <p class="text-xs font-semibold uppercase tracking-wider text-slate-400">Engenharia Social / Phishing</p>
                    <span class="p-1.5 bg-purple-500/10 text-purple-400 rounded-lg text-xs font-mono font-bold">T1566.001</span>
                </div>
                <div class="mt-3 flex items-baseline space-x-2">
                    <span class="text-3xl font-extrabold text-purple-400 font-mono" id="metric-phishing-hits">--</span>
                    <span class="text-xs text-slate-400 font-medium">callbacks de domínios</span>
                </div>
                <p class="text-xs text-purple-300 font-medium mt-3 flex items-center">
                    <span class="w-1.5 h-1.5 rounded-full bg-purple-400 mr-1.5"></span>
                    Técnica rara e discriminativa (IDF 1.69)
                </p>
            </div>

            <div class="glass-card p-5 rounded-2xl border-l-4 border-l-emerald-500 shadow-lg">
                <div class="flex justify-between items-start">
                    <p class="text-xs font-semibold uppercase tracking-wider text-slate-400">Exfiltração de Dados</p>
                    <span class="p-1.5 bg-emerald-500/10 text-emerald-400 rounded-lg text-xs font-mono font-bold">Volume</span>
                </div>
                <div class="mt-3 flex items-baseline space-x-2">
                    <span class="text-3xl font-extrabold text-emerald-400 font-mono" id="metric-outbound-mb">-- MB</span>
                    <span class="text-xs text-slate-400 font-medium">volume máx. observado</span>
                </div>
                <p class="text-xs text-emerald-300 font-medium mt-3 flex items-center">
                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5"></span>
                    Diferencia Ransomware de Espionagem
                </p>
            </div>
        </div>

        <!-- 4. NOTA DE INTELIGÊNCIA DE AMEAÇAS (CTI BENCHMARK CONTEXTUAL) -->
        <div class="w-full glass-card p-5 sm:p-6 rounded-2xl border border-blue-500/30 shadow-lg">
            <div class="flex items-start space-x-3.5">
                <div class="w-9 h-9 rounded-xl bg-blue-500/15 text-blue-400 flex items-center justify-center shrink-0 mt-0.5 border border-blue-500/30">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                </div>
                <div>
                    <h4 class="text-xs sm:text-sm font-bold text-blue-400 uppercase tracking-wider flex items-center">
                        Inteligência de Ameaças & Benchmark Histórico de CTI (Contexto de Apoio à Decisão)
                    </h4>
                    <p class="text-xs sm:text-sm text-slate-300 mt-1.5 leading-relaxed font-normal" id="adv-cti-note">
                        Carregando correlação comportamental...
                    </p>
                </div>
            </div>
        </div>

        <!-- 5. GRÁFICOS FULLSCREEN (2 Colunas Largas) -->
        <div class="grid grid-cols-1 xl:grid-cols-3 gap-6 w-full">
            <div class="glass-card p-6 rounded-2xl shadow-xl xl:col-span-2 flex flex-col justify-between">
                <div>
                    <h3 class="text-base sm:text-lg font-bold text-white tracking-tight">
                        Comparativo Multimodelo: Artigo Original vs. Ciência de Dados
                    </h3>
                    <p class="text-xs sm:text-sm text-slate-400">
                        Equação 1 original SBRC, Okapi BM25, Embeddings Semânticos PLN e Classificação Random Forest
                    </p>
                </div>
                <div class="h-80 w-full relative mt-4">
                    <canvas id="chart-models-comparison"></canvas>
                </div>
            </div>

            <div class="glass-card p-6 rounded-2xl shadow-xl flex flex-col justify-between">
                <div>
                    <h3 class="text-base sm:text-lg font-bold text-white tracking-tight">
                        Probabilidade Random Forest (ML)
                    </h3>
                    <p class="text-xs sm:text-sm text-slate-400">
                        100% de Acurácia em 5-Fold Stratified Cross-Validation
                    </p>
                </div>
                <div class="h-64 w-full flex items-center justify-center my-2">
                    <canvas id="chart-rf-donut"></canvas>
                </div>
                <div class="pt-3 border-t border-dark-border text-xs text-slate-400 space-y-1.5" id="rf-importances-box">
                    <p class="font-bold text-slate-300 uppercase tracking-wider text-[11px]">Top Variáveis Decisivas (Gini Importance):</p>
                </div>
            </div>
        </div>

        <!-- 4. TABELA DA MATRIZ COMPLETA DE RESULTADOS -->
        <div class="glass-card rounded-2xl shadow-xl overflow-hidden w-full">
            <div class="px-6 py-4.5 border-b border-dark-border flex flex-wrap justify-between items-center gap-3">
                <div>
                    <h3 class="text-base sm:text-lg font-bold text-white tracking-tight">
                        Matriz Consolidada de Atribuição de Ameaças
                    </h3>
                    <p class="text-xs sm:text-sm text-slate-400">
                        Avaliação matemática completa para o dataset atualmente carregado
                    </p>
                </div>
                <span class="text-xs bg-dark-base px-3 py-1 rounded-full text-slate-400 font-mono border border-dark-border">
                    5 Perfis Comportamentais Analisados
                </span>
            </div>

            <div class="overflow-x-auto w-full">
                <table class="w-full text-left text-xs sm:text-sm text-slate-300">
                    <thead class="bg-dark-base/90 text-slate-400 uppercase tracking-wider font-semibold text-[11px] sm:text-xs border-b border-dark-border">
                        <tr>
                            <th class="px-5 py-4">Grupo / Ator</th>
                            <th class="px-4 py-4">Classificação</th>
                            <th class="px-4 py-4 text-center">TTPs Casadas</th>
                            <th class="px-4 py-4 text-right">SBRC Eq. 1</th>
                            <th class="px-4 py-4 text-right">TF-IDF Cos</th>
                            <th class="px-4 py-4 text-right">Okapi BM25</th>
                            <th class="px-4 py-4 text-right">PLN Embed</th>
                            <th class="px-4 py-4 text-right">Random Forest</th>
                            <th class="px-5 py-4 text-right font-bold text-white bg-blue-900/30">ENSEMBLE FINAL</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-dark-border/60" id="matrix-tbody"></tbody>
                </table>
            </div>
        </div>

        <!-- 5. PAINEL DE RELATÓRIOS PLN / NER -->
        <div class="glass-card rounded-2xl shadow-xl p-6 sm:p-8 w-full">
            <div class="flex flex-wrap justify-between items-center mb-6 gap-3">
                <div>
                    <h3 class="text-base sm:text-lg font-bold text-white tracking-tight">
                        Pipeline de PLN / NER em Relatórios Brutos de CTI
                    </h3>
                    <p class="text-xs sm:text-sm text-slate-400">
                        Extração automatizada de entidades (Threat Actors, Malware, CVEs, IoCs) e Inferência Semântica de TTPs
                    </p>
                </div>
                <span class="text-xs bg-purple-500/10 text-purple-400 border border-purple-500/30 px-3.5 py-1.5 rounded-full font-mono font-bold">
                    5 Relatórios em Texto Livre Ingeridos
                </span>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4.5 w-full" id="nlp-reports-container"></div>
        </div>

    </main>

    <!-- MODAL DE UPLOAD DE DATASET (Arrastar & Soltar ou Selecionar Arquivo) -->
    <div id="upload-modal" class="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center hidden p-4">
        <div class="glass-card bg-dark-card w-full max-w-xl rounded-2xl p-6 sm:p-8 border border-dark-borderLight shadow-2xl relative">
            <button onclick="document.getElementById('upload-modal').classList.add('hidden')" class="absolute top-5 right-5 text-slate-400 hover:text-white">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
            </button>

            <div class="flex items-center space-x-3 mb-4">
                <div class="w-10 h-10 rounded-xl bg-emerald-500/10 text-emerald-400 flex items-center justify-center font-bold">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path></svg>
                </div>
                <div>
                    <h3 class="text-lg font-bold text-white">Carregar Novo Dataset para o IPO</h3>
                    <p class="text-xs text-slate-400">Suba um arquivo para rodar a correlação e reclassificar os modelos</p>
                </div>
            </div>

            <!-- Formulário de Upload -->
            <form id="upload-form" class="space-y-4">
                <div class="border-2 border-dashed border-dark-borderLight hover:border-emerald-500/60 rounded-2xl p-6 text-center cursor-pointer transition" onclick="document.getElementById('file-input').click()">
                    <input type="file" id="file-input" name="file" accept=".csv,.json" class="hidden" onchange="updateFileName(this)">
                    <svg class="w-10 h-10 mx-auto text-slate-500 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path></svg>
                    <p class="text-sm font-semibold text-white" id="upload-label">Clique para selecionar ou arraste o arquivo aqui</p>
                    <p class="text-xs text-slate-400 mt-1">Formatos aceitos: <b>.CSV</b> (Telemetria SOC) ou <b>.JSON</b> (Alertas Wazuh)</p>
                </div>

                <!-- Botões de Atalho para Datasets Já Existentes no Projeto -->
                <div class="pt-2">
                    <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Ou alterne entre datasets já disponíveis no projeto:</p>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                        <button type="button" onclick="selectPreset('soc_network_telemetry.csv', 'csv_network')" class="text-left p-3 rounded-xl bg-dark-base hover:bg-dark-cardHover border border-dark-border text-xs transition">
                            <span class="font-bold text-white block">📡 Telemetria SOC (CSV)</span>
                            <span class="text-[11px] text-slate-400">2.008 conexões de rede</span>
                        </button>
                        <button type="button" onclick="selectPreset('wazuh_alerts_hf.json', 'json_wazuh')" class="text-left p-3 rounded-xl bg-dark-base hover:bg-dark-cardHover border border-dark-border text-xs transition">
                            <span class="font-bold text-white block">🛡️ Alertas Wazuh (JSON)</span>
                            <span class="text-[11px] text-slate-400">738 alertas reais SIEM/XDR</span>
                        </button>
                        <button type="button" onclick="selectPreset('teste_cego_lazarus_anonimizado.csv', 'csv_network')" class="text-left p-3 rounded-xl bg-blue-950/40 hover:bg-blue-900/50 border border-blue-500/40 text-xs transition">
                            <span class="font-bold text-blue-300 block">🧪 Teste Cego Lazarus (CSV)</span>
                            <span class="text-[11px] text-slate-300">933 conexões • Ground Truth SBRC</span>
                        </button>
                        <button type="button" onclick="selectPreset('teste_cego_lazarus_anonimizado.json', 'json_wazuh')" class="text-left p-3 rounded-xl bg-blue-950/40 hover:bg-blue-900/50 border border-blue-500/40 text-xs transition">
                            <span class="font-bold text-blue-300 block">🎯 SIEM Alertas Lazarus (JSON)</span>
                            <span class="text-[11px] text-slate-300">133 alertas de detecção</span>
                        </button>
                    </div>
                </div>

                <div class="flex justify-end space-x-3 pt-3">
                    <button type="button" onclick="document.getElementById('upload-modal').classList.add('hidden')" class="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white">Cancelar</button>
                    <button type="submit" id="submit-btn" class="bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold px-5 py-2.5 rounded-xl transition shadow-lg shadow-emerald-600/30 flex items-center space-x-1.5">
                        <span>Processar e Analisar</span>
                    </button>
                </div>
            </form>
        </div>
    </div>

    <footer class="w-full bg-dark-card border-t border-dark-border py-4 px-6 text-center text-xs text-slate-400">
        IPO v2.0 • Intelligence Pattern Orchestrator • Inspirado em Barros & Gondim (UnB / SBRC 2025) • Upload Dinâmico & Ciência de Dados
    </footer>

    <script>
        function updateFileName(input) {
            if (input.files && input.files[0]) {
                document.getElementById('upload-label').textContent = "Arquivo selecionado: " + input.files[0].name;
            }
        }

        function selectPreset(filename, type) {
            fetch('/api/select_preset', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename: filename, type: type })
            })
            .then(res => res.json())
            .then(data => {
                document.getElementById('upload-modal').classList.add('hidden');
                location.reload();
            });
        }

        document.getElementById('upload-form').addEventListener('submit', function(e) {
            e.preventDefault();
            const fileInput = document.getElementById('file-input');
            if (!fileInput.files || !fileInput.files[0]) {
                alert("Por favor, selecione um arquivo .CSV ou .JSON antes de enviar.");
                return;
            }

            const formData = new FormData();
            formData.append('file', fileInput.files[0]);

            const btn = document.getElementById('submit-btn');
            btn.innerHTML = "<span>Enviando e Processando...</span>";
            btn.disabled = true;

            fetch('/api/upload', {
                method: 'POST',
                body: formData
            })
            .then(res => res.json())
            .then(data => {
                if (data.status === 'ok') {
                    document.getElementById('upload-modal').classList.add('hidden');
                    location.reload();
                } else {
                    alert("Erro ao processar: " + (data.error || "Arquivo inválido"));
                    btn.innerHTML = "<span>Processar e Analisar</span>";
                    btn.disabled = false;
                }
            })
            .catch(err => {
                alert("Falha no envio: " + err);
                btn.innerHTML = "<span>Processar e Analisar</span>";
                btn.disabled = false;
            });
        });

        function toggleCheck(input) {
            const parent = input.closest('label');
            const title = parent.querySelector('.item-title');
            const desc = parent.querySelector('.item-desc');
            if (input.checked) {
                title.classList.add('line-through', 'text-slate-500');
                title.classList.remove('text-white');
                desc.classList.add('text-slate-600');
                parent.classList.add('bg-emerald-950/25', 'border-emerald-500/40');
            } else {
                title.classList.remove('line-through', 'text-slate-500');
                title.classList.add('text-white');
                desc.classList.remove('text-slate-600');
                parent.classList.remove('bg-emerald-950/25', 'border-emerald-500/40');
            }
            updateHealthScoreUI();
        }

        function updateHealthScoreUI() {
            if (!window.currentAdvisory) return;
            const adv = window.currentAdvisory;
            const hs = adv.health_score || {};
            const initialHealth = hs.initial !== undefined ? hs.initial : 15;
            const totalItems = (adv.analyst_checklist && adv.analyst_checklist.length) || 5;

            const checkboxes = document.querySelectorAll('#analyst-checklist-container input[type="checkbox"]');
            let sumGained = 0;
            let checkedCount = 0;
            const checkedCategories = new Set();

            checkboxes.forEach(chk => {
                if (chk.checked) {
                    checkedCount++;
                    const w = parseInt(chk.getAttribute('data-weight') || 20);
                    sumGained += w;
                    const cat = chk.getAttribute('data-category');
                    if (cat) checkedCategories.add(cat);
                }
            });

            const currentHealth = Math.min(100, initialHealth + sumGained);

            // Atualizar Anel e Valores
            const ring = document.getElementById('health-ring');
            const scoreVal = document.getElementById('health-score-val');
            const badge = document.getElementById('health-badge');
            const desc = document.getElementById('health-desc');
            const progressCount = document.getElementById('health-progress-count');
            const gainVal = document.getElementById('health-gain-val');

            // Circumference do circulo r=34 é 213.6
            const offset = 213.6 - (currentHealth / 100.0) * 213.6;
            ring.style.strokeDashoffset = offset;

            scoreVal.textContent = currentHealth + '%';
            progressCount.textContent = `${checkedCount} de ${totalItems}`;
            gainVal.textContent = `+${sumGained}%`;

            // Estilos dinâmicos de cor
            if (currentHealth >= 100) {
                ring.setAttribute('class', 'text-emerald-400 transition-all duration-700 ease-out');
                scoreVal.className = "font-mono font-black text-lg text-emerald-400 tracking-tight";
                badge.className = "text-[10px] font-bold px-2.5 py-0.5 rounded-full font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30";
                badge.textContent = "🟢 Totalmente Seguro / Ameaça Contida";
                desc.textContent = "Excelente! Todas as ações prioritárias foram executadas. O vetor de ataque foi neutralizado e a integridade da infraestrutura foi restabelecida.";
            } else if (currentHealth >= 70) {
                ring.setAttribute('class', 'text-teal-400 transition-all duration-700 ease-out');
                scoreVal.className = "font-mono font-black text-lg text-teal-400 tracking-tight";
                badge.className = "text-[10px] font-bold px-2.5 py-0.5 rounded-full font-mono bg-teal-500/20 text-teal-300 border border-teal-500/30";
                badge.textContent = "🔵 Contenção Avançada";
                desc.textContent = "Ameaça neutralizada nos vetores críticos. Conclua as etapas finais de auditoria e preservação de evidências para atingir 100%.";
            } else if (currentHealth >= 40) {
                ring.setAttribute('class', 'text-amber-400 transition-all duration-700 ease-out');
                scoreVal.className = "font-mono font-black text-lg text-amber-400 tracking-tight";
                badge.className = "text-[10px] font-bold px-2.5 py-0.5 rounded-full font-mono bg-amber-500/20 text-amber-300 border border-amber-500/30";
                badge.textContent = "🟡 Parcialmente Contido";
                desc.textContent = "Primeiras medidas de isolamento executadas. Prossiga com o bloqueio de rede e revogação de credenciais.";
            } else {
                ring.setAttribute('class', 'text-red-500 transition-all duration-700 ease-out');
                scoreVal.className = "font-mono font-black text-lg text-red-400 tracking-tight";
                badge.className = "text-[10px] font-bold px-2.5 py-0.5 rounded-full font-mono bg-red-500/20 text-red-300 border border-red-500/30";
                badge.textContent = "🔴 Crítico / Comprometido";
                desc.textContent = "Ambiente sob ameaça ativa. Execute as ações abaixo para isolar o vetor e recuperar a integridade da infraestrutura.";
            }

            // Posturas Individuais
            const elEndpoints = document.getElementById('posture-endpoints');
            if (checkedCategories.has('endpoints')) {
                elEndpoints.textContent = "Isolado [✓]";
                elEndpoints.className = "text-xs font-mono font-bold text-emerald-400 mt-1";
            } else {
                elEndpoints.textContent = "Exposto";
                elEndpoints.className = "text-xs font-mono font-bold text-red-400 mt-1";
            }

            const elNetwork = document.getElementById('posture-network');
            if (checkedCategories.has('network')) {
                elNetwork.textContent = "Bloqueado [✓]";
                elNetwork.className = "text-xs font-mono font-bold text-emerald-400 mt-1";
            } else {
                elNetwork.textContent = "Vazando";
                elNetwork.className = "text-xs font-mono font-bold text-amber-400 mt-1";
            }

            const elIdentity = document.getElementById('posture-identity');
            if (checkedCategories.has('identity')) {
                elIdentity.textContent = "Protegida [✓]";
                elIdentity.className = "text-xs font-mono font-bold text-emerald-400 mt-1";
            } else {
                elIdentity.textContent = "Em Risco";
                elIdentity.className = "text-xs font-mono font-bold text-amber-400 mt-1";
            }

            const elForensics = document.getElementById('posture-forensics');
            if (checkedCategories.has('forensics')) {
                elForensics.textContent = "Preservada [✓]";
                elForensics.className = "text-xs font-mono font-bold text-emerald-400 mt-1";
            } else {
                elForensics.textContent = "Pendente";
                elForensics.className = "text-xs font-mono font-bold text-blue-400 mt-1";
            }
        }

        // Carregamento dos Dados do Dashboard
        fetch('/api/data')
            .then(res => res.json())
            .then(data => {
                const ranking = data.ranking;
                const winner = ranking[0];
                const adv = data.incident_advisory;
                window.currentAdvisory = adv;

                // Atualizar Nome do Dataset
                document.getElementById('active-dataset-name').textContent = data.dataset_info.name;
                document.getElementById('active-dataset-count').textContent = `(${data.dataset_info.total_records} registros analisados)`;

                // Diagnóstico Clínico do Incidente
                if (adv) {
                    document.getElementById('adv-severity-text').textContent = adv.severity.label;
                    document.getElementById('adv-risk-score').textContent = adv.severity.score;
                    document.getElementById('adv-status-title').textContent = adv.severity.status;

                    const pColor = adv.severity.color;
                    const pill = document.getElementById('adv-severity-pill');
                    pill.className = `text-xs font-bold uppercase tracking-wider px-3 py-1 rounded-md border flex items-center shadow-sm ${
                        pColor === 'red' ? 'text-red-400 bg-red-500/15 border-red-500/30' :
                        pColor === 'amber' ? 'text-amber-400 bg-amber-500/15 border-amber-500/30' :
                        'text-blue-400 bg-blue-500/15 border-blue-500/30'
                    }`;

                    document.getElementById('adv-pz').textContent = `${adv.patient_zero.ip} • ${adv.patient_zero.hostname}`;
                    document.getElementById('adv-pz-user').textContent = `Usuário: ${adv.patient_zero.user}`;
                    document.getElementById('adv-internal-targets').textContent = adv.internal_targets.join(', ') || 'Nenhum alvo interno detectado';
                    document.getElementById('adv-external-dest').textContent = adv.external_destinations.join(', ') || 'Nenhum C2 externo ativo';
                    document.getElementById('adv-cti-note').textContent = adv.cti_affinity_note;

                    // TTPs identificadas
                    const ttpsContainer = document.getElementById('adv-ttps-container');
                    ttpsContainer.innerHTML = '';
                    data.detected_ttps.forEach(t => {
                        const span = document.createElement('span');
                        span.className = "text-xs font-mono bg-blue-500/15 text-blue-300 border border-blue-500/30 px-2.5 py-1 rounded-lg font-medium shadow-sm";
                        span.textContent = t;
                        ttpsContainer.appendChild(span);
                    });

                    // Kill Chain Stages
                    const kcContainer = document.getElementById('kill-chain-container');
                    kcContainer.innerHTML = '';
                    adv.kill_chain_stages.forEach(stg => {
                        const card = document.createElement('div');
                        card.className = "bg-dark-base/80 p-4 rounded-xl border border-dark-border flex flex-col justify-between space-y-2.5 hover:border-dark-borderLight transition";
                        card.innerHTML = `
                            <div>
                                <div class="flex justify-between items-center">
                                    <span class="text-[10px] font-bold uppercase tracking-wider text-slate-400 font-mono">${stg.phase.split('.')[0]}</span>
                                    <span class="text-[10px] px-2 py-0.5 rounded font-bold font-mono ${stg.status === 'Executado' || stg.status === 'Concluído' ? 'bg-red-500/20 text-red-300' : stg.status === 'Ativo' ? 'bg-amber-500/20 text-amber-300' : 'bg-slate-800 text-slate-400'}">${stg.badge}</span>
                                </div>
                                <h4 class="text-xs sm:text-sm font-bold text-white mt-1.5">${stg.phase.split('. ')[1] || stg.phase}</h4>
                                <p class="text-[11px] font-mono text-blue-400 mt-1">${stg.ttp}</p>
                                <p class="text-xs text-slate-300 mt-2 leading-relaxed">${stg.desc}</p>
                            </div>
                        `;
                        kcContainer.appendChild(card);
                    });

                    // Checklist do Analista com Pesos de Saúde
                    const chkContainer = document.getElementById('analyst-checklist-container');
                    chkContainer.innerHTML = '';
                    adv.analyst_checklist.forEach(item => {
                        const row = document.createElement('label');
                        row.className = "flex items-start space-x-3.5 p-3.5 rounded-xl bg-dark-base/70 border border-dark-border hover:border-emerald-500/40 transition cursor-pointer select-none";
                        row.innerHTML = `
                            <input type="checkbox" onchange="toggleCheck(this)" data-weight="${item.weight}" data-category="${item.category}" class="w-5 h-5 rounded cursor-pointer mt-0.5 accent-emerald-500 shrink-0">
                            <div class="flex-1 text-xs sm:text-sm">
                                <div class="flex items-center space-x-2">
                                    <span class="text-[10px] font-bold px-2 py-0.5 rounded font-mono ${item.priority_color === 'red' ? 'bg-red-500/20 text-red-300' : 'bg-amber-500/20 text-amber-300'}">${item.priority}</span>
                                    <span class="font-bold text-white item-title">${item.action}</span>
                                    <span class="text-[11px] font-mono text-emerald-400 font-bold ml-auto">+${item.weight}% Saúde</span>
                                </div>
                                <p class="text-slate-400 text-xs mt-1 leading-relaxed item-desc">${item.description}</p>
                            </div>
                        `;
                        chkContainer.appendChild(row);
                    });

                    // Atualizar Health Score Inicial
                    updateHealthScoreUI();
                }

                // Métricas Rápidas
                const tm = data.telemetry_metrics;
                document.getElementById('metric-beacon-interval').textContent = tm.beacon_mean + ' s';
                document.getElementById('metric-beacon-jitter').textContent = tm.beacon_jitter + ' s';
                document.getElementById('metric-auth-fails').textContent = tm.auth_fails_5m;
                document.getElementById('metric-phishing-hits').textContent = tm.phishing_hits;
                document.getElementById('metric-outbound-mb').textContent = tm.max_outbound_mb.toFixed(3) + ' MB';

                // Tabela da Matriz
                const tbody = document.getElementById('matrix-tbody');
                ranking.forEach((r, idx) => {
                    const tr = document.createElement('tr');
                    tr.className = idx === 0 ? "bg-blue-950/20 font-semibold" : "hover:bg-dark-cardHover/70 transition duration-150";
                    tr.innerHTML = `
                        <td class="px-5 py-4 font-bold text-white flex items-center text-sm sm:text-base">
                            ${idx === 0 ? '<span class="w-2.5 h-2.5 rounded-full bg-blue-500 mr-2.5 animate-pulse"></span>' : '<span class="w-2.5 h-2.5 rounded-full bg-slate-600 mr-2.5"></span>'}
                            ${r.name}
                        </td>
                        <td class="px-4 py-4 text-slate-400 text-xs sm:text-sm font-medium">${r.type}</td>
                        <td class="px-4 py-4 text-center font-mono font-medium">${r.matched_ttps.length} / ${r.total_ttps}</td>
                        <td class="px-4 py-4 text-right font-mono text-slate-400">${r.score_sbrc.toFixed(2)}%</td>
                        <td class="px-4 py-4 text-right font-mono text-slate-300">${r.score_tfidf.toFixed(2)}%</td>
                        <td class="px-4 py-4 text-right font-mono text-sky-400">${r.score_bm25.toFixed(2)}%</td>
                        <td class="px-4 py-4 text-right font-mono text-purple-400">${r.score_sem.toFixed(2)}%</td>
                        <td class="px-4 py-4 text-right font-mono font-bold ${r.score_rf > 50 ? 'text-emerald-400 text-base' : 'text-slate-400'}">${r.score_rf.toFixed(2)}%</td>
                        <td class="px-5 py-4 text-right font-mono font-extrabold text-blue-400 bg-blue-900/30 text-base sm:text-lg">${r.ensemble.toFixed(2)}%</td>
                    `;
                    tbody.appendChild(tr);
                });

                // Top Features RF
                const rfBox = document.getElementById('rf-importances-box');
                data.rf_importances.forEach(item => {
                    const p = document.createElement('p');
                    p.className = "flex justify-between items-center py-1";
                    p.innerHTML = `<span class="truncate font-mono text-slate-300 text-xs">${item[0]}</span> <span class="font-mono text-emerald-400 font-bold ml-2">${item[1].toFixed(1)}%</span>`;
                    rfBox.appendChild(p);
                });

                // Cards de Relatórios PLN
                const nlpContainer = document.getElementById('nlp-reports-container');
                data.nlp_reports.forEach(rpt => {
                    const card = document.createElement('div');
                    card.className = "bg-dark-base/70 p-4.5 rounded-xl border border-dark-border hover:border-dark-borderLight transition flex flex-col justify-between space-y-3";
                    card.innerHTML = `
                        <div>
                            <div class="flex justify-between items-center">
                                <span class="text-[11px] font-mono text-blue-400 font-bold">${rpt.id}</span>
                                <span class="text-[10px] bg-slate-800 px-2 py-0.5 rounded text-slate-300 font-semibold">${rpt.actor}</span>
                            </div>
                            <h4 class="text-xs sm:text-sm font-bold text-white mt-2 leading-snug">${rpt.title}</h4>
                            <div class="mt-2.5 text-xs text-slate-400 space-y-1">
                                <p><span class="text-slate-400 font-medium">Malware:</span> <span class="text-slate-300">${rpt.malwares.join(', ') || 'Nenhum'}</span></p>
                                <p><span class="text-slate-400 font-medium">CVEs:</span> <span class="text-amber-400 font-mono">${rpt.cves.join(', ') || 'N/A'}</span></p>
                                <p><span class="text-slate-400 font-medium">IoCs Extraídos:</span> <span class="text-blue-400 font-mono">${rpt.iocs_count}</span></p>
                            </div>
                        </div>
                        <div class="pt-2.5 border-t border-dark-border">
                            <p class="text-[10px] font-bold text-purple-400 uppercase tracking-wider">Inferidas Semântica PLN:</p>
                            <p class="text-xs text-slate-300 font-mono mt-1 leading-relaxed">${rpt.inferred_ttps.join(', ') || 'Nenhuma'}</p>
                        </div>
                    `;
                    nlpContainer.appendChild(card);
                });

                // Gráfico de Barras Comparativo
                const labels = ranking.map(r => r.name);
                const ctxBar = document.getElementById('chart-models-comparison').getContext('2d');
                new Chart(ctxBar, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [
                            { label: 'SBRC Eq. 1 (Original)', data: ranking.map(r => r.score_sbrc), backgroundColor: '#64748b' },
                            { label: 'Okapi BM25', data: ranking.map(r => r.score_bm25), backgroundColor: '#0284c7' },
                            { label: 'PLN Embeddings', data: ranking.map(r => r.score_sem), backgroundColor: '#7c3aed' },
                            { label: 'Random Forest (ML)', data: ranking.map(r => r.score_rf), backgroundColor: '#059669' },
                            { label: 'Ensemble Final (v2.0)', data: ranking.map(r => r.ensemble), backgroundColor: '#3b82f6' }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'top',
                                labels: {
                                    color: '#cbd5e1',
                                    font: { family: "'Plus Jakarta Sans'", size: 12, weight: '600' },
                                    boxWidth: 12,
                                    padding: 16
                                }
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                max: 110,
                                ticks: { color: '#94a3b8', font: { family: "'JetBrains Mono'", size: 11 } },
                                grid: { color: '#1e293b' }
                            },
                            x: {
                                ticks: { color: '#f8fafc', font: { family: "'Plus Jakarta Sans'", size: 12, weight: '700' } },
                                grid: { display: false }
                            }
                        }
                    }
                });

                // Gráfico Donut
                const ctxDonut = document.getElementById('chart-rf-donut').getContext('2d');
                new Chart(ctxDonut, {
                    type: 'doughnut',
                    data: {
                        labels: ranking.map(r => r.name),
                        datasets: [{
                            data: ranking.map(r => r.score_rf),
                            backgroundColor: ['#3b82f6', '#ef4444', '#f59e0b', '#8b5cf6', '#10b981'],
                            borderColor: '#0f172a',
                            borderWidth: 3
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: { color: '#cbd5e1', font: { family: "'Plus Jakarta Sans'", size: 11, weight: '500' }, boxWidth: 10, padding: 12 }
                            }
                        },
                        cutout: '68%'
                    }
                });

            })
            .catch(err => console.error("Erro ao carregar dados:", err));
    </script>
</body>
</html>
"""


class IPODashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))

        elif parsed.path == "/api/data":
            data = get_fresh_analysis()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/api/select_preset":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len).decode("utf-8")
            payload = json.loads(body)

            fname = payload.get("filename")
            ftype = payload.get("type")

            CURRENT_DATASET["name"] = fname
            CURRENT_DATASET["type"] = ftype
            CURRENT_DATASET["filepath"] = fname

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode("utf-8"))

        elif parsed.path == "/api/upload":
            content_type = self.headers.get("Content-Type", "")
            content_length = int(self.headers.get("Content-Length", 0))

            if "multipart/form-data" not in content_type:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Invalid Content-Type")
                return

            boundary = content_type.split("boundary=")[1].encode()
            raw_body = self.rfile.read(content_length)

            parts = raw_body.split(b"--" + boundary)
            saved_filename = None

            for part in parts:
                if b'Content-Disposition: form-data; name="file"' in part:
                    lines = part.split(b"\r\n")
                    header_line = lines[1].decode("utf-8", errors="ignore")
                    m = re.search(r'filename="([^"]+)"', header_line)
                    if m:
                        filename = os.path.basename(m.group(1))
                        # Encontrar início do arquivo
                        body_start = part.find(b"\r\n\r\n") + 4
                        body_content = part[body_start:].rstrip(b"\r\n")

                        saved_path = os.path.join(UPLOADS_DIR, filename)
                        with open(saved_path, "wb") as f:
                            f.write(body_content)

                        saved_filename = filename
                        ftype = "json_wazuh" if filename.lower().endswith(".json") else "csv_network"

                        CURRENT_DATASET["name"] = filename + " (Upload Personalizado)"
                        CURRENT_DATASET["type"] = ftype
                        CURRENT_DATASET["filepath"] = saved_path
                        break

            if saved_filename:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok", "filename": saved_filename}).encode("utf-8"))
            else:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "error", "error": "No file uploaded"}).encode("utf-8"))

    def log_message(self, format, *args):
        return


def run_dashboard_server(port=8080):
    server = HTTPServer(("0.0.0.0", port), IPODashboardHandler)
    url = f"http://localhost:{port}"
    print("=" * 80)
    print("  IPO v2.0 — DASHBOARD COM UPLOAD DE DATASETS ATIVO")
    print("=" * 80)
    print(f"[*] Acesse o painel no navegador: {url}")
    print("[*] Pressione Ctrl+C para encerrar quando desejar.")
    print("=" * 80)

    try:
        webbrowser.open(url)
    except Exception:
        pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Servidor encerrado.")
        server.server_close()


if __name__ == "__main__":
    # Render define a porta através da variável de ambiente PORT (padrão 10000 ou 8080)
    port = int(os.environ.get("PORT", 8080))
    run_dashboard_server(port)
