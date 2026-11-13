"""
========================================================================================
MÓDULO 04: EXTRAÇÃO AUTOMÁTICA DE CTI COM PLN / NER E INFERÊNCIA SEMÂNTICA DE TTPs
========================================================================================
Implementa técnicas de Processamento de Linguagem Natural (PLN) sugeridas como evolução
futura por Barros & Gondim (SBRC 2025):
  1. Named Entity Recognition (NER) Híbrido para extrair:
     - Atores de Ameaça (Threat Actors) e Aliases
     - Famílias de Malware / Implantes
     - Vulnerabilidades (CVEs)
     - Indicadores de Comprometimento (IPv4, Domínios, SHA-256)
     - Códigos explícitos do MITRE ATT&CK (Txxxx.xxx)
  2. Inferência Semântica de TTPs (TF-IDF N-Gram + SVD/LSA + Cosine Similarity):
     - Identifica técnicas do MITRE ATT&CK descritas em linguagem natural no texto
       mesmo quando o código Txxxx não é citado explicitamente.
========================================================================================
"""

import json
import os
import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

RAW_REPORTS_FILE = "cti_raw_reports.json"

# Base de Conhecimento Semântica do MITRE ATT&CK (Corpus de Referência para PLN)
MITRE_KNOWLEDGE_BASE = {
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "corpus": (
            "comando e controle C2 via protocolo web HTTP HTTPS tráfego web beaconing "
            "regular pulso periódico intervalo médio baixo jitter callback servidor web "
            "application layer protocol web protocols http https beacon"
        )
    },
    "T1071.004": {
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "corpus": (
            "tunelamento de DNS dns tunneling comando e controle consultas DNS TXT "
            "subdomínios codificados tráfego DNS anômalo túneis DNS"
        )
    },
    "T1102": {
        "name": "Web Service",
        "tactic": "Command and Control",
        "corpus": (
            "serviços web em nuvem bidirecionais APIs externas dead drop resolver "
            "cloud storage C2 comunicação via API pública"
        )
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "corpus": (
            "força bruta brute force adivinhação de senhas password guessing múltiplas "
            "falhas de login autenticação inválida SSH RDP porta 22 3389 tentativas de acesso"
        )
    },
    "T1110.003": {
        "name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "corpus": (
            "password spraying pulverização de senhas única senha contra múltiplos usuários "
            "tentativas distribuídas de login falha de autenticação"
        )
    },
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "corpus": (
            "spearphishing com anexos maliciosos e-mail de phishing documento malicioso "
            "anexo infectado macro vetor inicial de e-mail spearphishing attachment"
        )
    },
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "corpus": (
            "spearphishing com links maliciosos clique em URL de phishing link direcionado "
            "redirecionamento web malicioso credenciais spearphishing link"
        )
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "corpus": (
            "exfiltração massiva de dados sensíveis grandes volumes de pacotes transferência "
            "externa anômala upload para nuvem protocolo alternativo exfiltrar documentos"
        )
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "corpus": (
            "exfiltração direta pelo canal C2 envio de dados roubados na mesma conexão de "
            "comando e controle exfiltration over C2 channel"
        )
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "corpus": (
            "descoberta e varredura de serviços de rede internos port scan varredura de portas "
            "mapeamento de hosts internos network service discovery"
        )
    },
    "T1570": {
        "name": "Lateral Tool Transfer",
        "tactic": "Lateral Movement",
        "corpus": (
            "transferência lateral de ferramentas movimentação lateral cópia de binários SMB "
            "compartilhamento de rede interno lateral tool transfer"
        )
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "corpus": (
            "explorando servidores web públicos vulneráveis exploit public-facing application "
            "vulnerabilidade remota CVE exploração de aplicação exposta na internet"
        )
    },
    "T1090": {
        "name": "Proxy",
        "tactic": "Command and Control",
        "corpus": (
            "proxies multi-hop redirecionamento de tráfego ocultação de origem proxy SOCKS "
            "cadeia de proxies intermediários"
        )
    },
    "T1021.001": {
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "corpus": (
            "conexões de área de trabalho remota RDP porta 3389 acesso remoto interativo "
            "remote desktop protocol"
        )
    }
}

# Expressões Regulares para NER de Segurança Cibernética
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
RE_MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|cc|io|ru|cn|br|gov)\b")

KNOWN_ACTORS = [
    "APT-DarkSerpent", "BlackCat", "ALPHV", "Noberus", "Kimsuky",
    "Velvet Chollima", "Thallium", "Lazarus Group", "HIDDEN COBRA",
    "APT28", "Fancy Bear", "Sofacy", "Strontium", "FinRansom-99", "APT-Python-Group"
]

KNOWN_MALWARES = [
    "ViperRAT", "BlackCat-Rust", "GoldDragon", "BlindingCan", "Zebrocy", "Emotet-Clone"
]


class CTINLPExtractor:
    """
    Pipeline de PLN para extração de Entidades (NER) e Inferência Semântica de TTPs
    a partir de relatórios de inteligência em texto livre.
    """

    def __init__(self, semantic_threshold=0.18):
        self.semantic_threshold = semantic_threshold
        self.tech_ids = list(MITRE_KNOWLEDGE_BASE.keys())
        self.tech_corpus = [MITRE_KNOWLEDGE_BASE[tid]["corpus"] for tid in self.tech_ids]

        # Vetorizador híbrido (unigramas, bigramas e trigramas)
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 3), sublinear_tf=True)
        self.kb_tfidf_matrix = self.vectorizer.fit_transform(self.tech_corpus)

    def extract_entities_ner(self, text):
        """Extrai entidades nomeadas (NER) e IoCs do texto bruto."""
        ips = sorted(list(set(RE_IPV4.findall(text))))
        cves = sorted(list(set(m.upper() for m in RE_CVE.findall(text))))
        explicit_ttps = sorted(list(set(RE_MITRE.findall(text))))
        hashes = sorted(list(set(RE_SHA256.findall(text))))
        domains = sorted(list(set(RE_DOMAIN.findall(text))))

        actors = [a for a in KNOWN_ACTORS if a.lower() in text.lower()]
        malwares = [m for m in KNOWN_MALWARES if m.lower() in text.lower()]

        return {
            "threat_actors": actors,
            "malwares": malwares,
            "cves": cves,
            "iocs": {
                "ipv4": ips,
                "domains": domains,
                "sha256": hashes
            },
            "explicit_ttps": explicit_ttps
        }

    def infer_semantic_ttps(self, text):
        """
        Divide o relatório em sentenças (removendo menções explícitas a Txxxx) e calcula
        a Similaridade de Cosseno contra a base semântica do MITRE ATT&CK.
        """
        clean_text = RE_MITRE.sub("", text)
        sentences = [s.strip() for s in re.split(r"[.!?;]+", clean_text) if len(s.strip()) > 15]

        inferred = {}
        if not sentences:
            return inferred

        sent_vectors = self.vectorizer.transform(sentences)
        sim_matrix = cosine_similarity(sent_vectors, self.kb_tfidf_matrix)

        for s_idx, sentence in enumerate(sentences):
            for t_idx, tech_id in enumerate(self.tech_ids):
                score = float(sim_matrix[s_idx, t_idx])
                if score >= self.semantic_threshold:
                    if tech_id not in inferred or score > inferred[tech_id]["confidence"]:
                        inferred[tech_id] = {
                            "technique_id": tech_id,
                            "name": MITRE_KNOWLEDGE_BASE[tech_id]["name"],
                            "tactic": MITRE_KNOWLEDGE_BASE[tech_id]["tactic"],
                            "confidence": round(score, 3),
                            "matched_sentence": sentence[:90] + ("..." if len(sentence) > 90 else "")
                        }

        return inferred

    def process_reports(self, reports_filepath=RAW_REPORTS_FILE):
        if not os.path.exists(reports_filepath):
            return []

        with open(reports_filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        extracted_profiles = []
        for rpt in data.get("reports", []):
            raw_text = rpt.get("raw_text", "")
            ner = self.extract_entities_ner(raw_text)
            semantic_ttps = self.infer_semantic_ttps(raw_text)

            all_ttps = sorted(list(set(ner["explicit_ttps"]).union(set(semantic_ttps.keys()))))

            extracted_profiles.append({
                "report_id": rpt.get("report_id"),
                "title": rpt.get("title"),
                "primary_actor": ner["threat_actors"][0] if ner["threat_actors"] else "Desconhecido",
                "ner_entities": ner,
                "semantic_inferred_ttps": list(semantic_ttps.values()),
                "consolidated_ttps": all_ttps,
                "raw_text": raw_text
            })

        return extracted_profiles


def run_nlp_demo():
    print("=" * 88)
    print("  MÓDULO 04: PLN / NER E INFERÊNCIA SEMÂNTICA DE TTPs EM RELATÓRIOS BRUTOS")
    print("=" * 88)
    extractor = CTINLPExtractor()
    profiles = extractor.process_reports()

    for p in profiles:
        print(f"\n[*] Relatório [{p['report_id']}]: {p['title']}")
        print(f"    -> Ator(es) Detectado(s) (NER) : {', '.join(p['ner_entities']['threat_actors'])}")
        print(f"    -> Malware(s) (NER)            : {', '.join(p['ner_entities']['malwares']) or 'N/A'}")
        print(f"    -> CVEs (NER)                  : {', '.join(p['ner_entities']['cves']) or 'N/A'}")
        iocs = p["ner_entities"]["iocs"]
        print(f"    -> IoCs Extraídos              : {len(iocs['ipv4'])} IPs, {len(iocs['domains'])} Domínios, {len(iocs['sha256'])} Hashes")
        print(f"    -> TTPs Explícitas (Regex)     : {', '.join(p['ner_entities']['explicit_ttps'])}")
        sem_list = [f"{s['technique_id']} (sim={s['confidence']:.2f})" for s in p["semantic_inferred_ttps"]]
        print(f"    -> TTPs Inferidas por PLN      : {', '.join(sem_list)}")


if __name__ == "__main__":
    run_nlp_demo()

