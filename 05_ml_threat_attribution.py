"""
========================================================================================
MÓDULO 05: CIÊNCIA DE DADOS E MACHINE LEARNING PARA ATRIBUIÇÃO DE AMEAÇAS NO IPO
========================================================================================
Implementa 3 abordagens matemáticas e de aprendizado de máquina para superar as
limitações da Equação 1 original do artigo (Barros & Gondim, SBRC 2025):

  1. Ponderação TF-IDF e Okapi BM25 sobre TTPs:
     - Penaliza técnicas genéricas (ex: T1071.001 presente em todos os grupos) e
       valoriza técnicas raras/discriminativas (alto IDF), evitando falsos empates.
  2. Similaridade Semântica Densa (TF-IDF Subword/N-Gram + TruncatedSVD/LSA + Cosseno):
     - Projeta a descrição textual da telemetria observada e os relatórios CTI em um
       espaço latente (Embeddings LSA) e calcula a Similaridade de Cosseno.
  3. Classificador Supervisionado Ensemble (Random Forest Classifier):
     - Combina indicadores binários de TTPs com features contínuas de tráfego de rede
       (jitter do beacon, intervalo médio C2, megabytes transferidos, falhas de login
       em janela deslizante, hits em domínios de phishing) para prever a probabilidade
       de autoria de cada grupo APT/Ransomware.
========================================================================================
"""

import math
import numpy as np
from sklearn.decomposition import TruncatedSVD
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.preprocessing import normalize


# ======================================================================================
# 1. PONDERAÇÃO TF-IDF E OKAPI BM25 SOBRE CONJUNTOS DE TTPs
# ======================================================================================
class TTPTfIdfScorer:
    """
    Calcula o peso IDF (Inverse Document Frequency) de cada técnica MITRE ATT&CK
    no catálogo de grupos e avalia a afinidade por Cosseno TF-IDF e Okapi BM25.
    """

    def __init__(self, patterns, k1=1.5, b=0.75):
        self.patterns = patterns
        self.k1 = k1
        self.b = b
        self.num_docs = len(patterns)
        self.idf = {}
        self.avg_dl = 0.0
        self._fit()

    def _fit(self):
        df_counts = {}
        total_len = 0
        for pat in self.patterns:
            ttps = set(t["technique_id"] for t in pat.get("network_ttps", []))
            total_len += len(ttps)
            for t in ttps:
                df_counts[t] = df_counts.get(t, 0) + 1

        self.avg_dl = total_len / self.num_docs if self.num_docs > 0 else 1.0

        # Smooth IDF: ln((N + 1) / (df + 1)) + 1.0
        for t, df in df_counts.items():
            self.idf[t] = math.log((self.num_docs + 1.0) / (df + 1.0)) + 1.0

    def score_patterns(self, detected_ttps):
        scores = {}
        if not detected_ttps:
            return {p["name"]: {"tfidf_score": 0.0, "bm25_score": 0.0} for p in self.patterns}

        # Norma do vetor observado ponderado por IDF
        obs_weights = {t: self.idf.get(t, math.log(self.num_docs + 1.0) + 1.0) for t in detected_ttps}
        obs_norm = math.sqrt(sum(w * w for w in obs_weights.values())) or 1.0

        raw_bm25 = {}
        for pat in self.patterns:
            name = pat["name"]
            pat_ttps = set(t["technique_id"] for t in pat.get("network_ttps", []))
            dl = len(pat_ttps)

            pat_weights = {t: self.idf.get(t, 1.0) for t in pat_ttps}
            pat_norm = math.sqrt(sum(w * w for w in pat_weights.values())) or 1.0

            # Produto escalar TF-IDF normalizado (Cosine TF-IDF sobre TTPs)
            intersection = detected_ttps.intersection(pat_ttps)
            dot_product = sum(obs_weights[t] * pat_weights[t] for t in intersection)
            tfidf_cos = (dot_product / (obs_norm * pat_norm)) * 100.0

            # Okapi BM25 adaptado para perfis de TTPs
            bm25_val = 0.0
            for t in intersection:
                idf_t = self.idf.get(t, 1.0)
                tf = 1.0
                denom = tf + self.k1 * (1.0 - self.b + self.b * (dl / self.avg_dl))
                bm25_val += idf_t * ((tf * (self.k1 + 1.0)) / denom)

            raw_bm25[name] = bm25_val
            scores[name] = {
                "tfidf_score": round(tfidf_cos, 2),
                "bm25_raw": bm25_val
            }

        max_bm25 = max(raw_bm25.values()) if raw_bm25 and max(raw_bm25.values()) > 0 else 1.0
        for name in scores:
            scores[name]["bm25_score"] = round((scores[name]["bm25_raw"] / max_bm25) * 100.0, 2)

        return scores


# ======================================================================================
# 2. EMBEDDINGS SEMÂNTICOS (TF-IDF N-GRAM + LSA / SVD + COSINE SIMILARITY)
# ======================================================================================
class SemanticEmbeddingMatcher:
    """
    Constrói Embeddings Densos via Latent Semantic Analysis (TF-IDF + TruncatedSVD)
    a partir das descrições de padrões e relatórios de cada grupo, e mede a similaridade
    semântica contra o resumo narrativo gerado pela telemetria de rede.
    """

    def __init__(self, patterns, raw_reports=None):
        self.patterns = patterns
        self.raw_reports = raw_reports or []
        self.actor_names = []
        self.corpus = []
        self._build_corpus()

        self.vectorizer = TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 2),
            sublinear_tf=True
        )
        tfidf_mat = self.vectorizer.fit_transform(self.corpus)

        # Redução dimensional LSA (TruncatedSVD) para capturar relações semânticas latentes
        n_components = min(4, tfidf_mat.shape[0] - 1, tfidf_mat.shape[1] - 1)
        if n_components >= 2:
            self.svd = TruncatedSVD(n_components=n_components, random_state=42)
            self.actor_embeddings = normalize(self.svd.fit_transform(tfidf_mat))
        else:
            self.svd = None
            self.actor_embeddings = tfidf_mat

        self.actor_tfidf = tfidf_mat

    def _build_corpus(self):
        report_by_actor = {}
        for r in self.raw_reports:
            txt = r.get("raw_text", "")
            for pat in self.patterns:
                if pat["name"].lower() in txt.lower() or any(a.lower() in txt.lower() for a in pat.get("aliases", [])):
                    report_by_actor[pat["name"]] = txt

        for pat in self.patterns:
            name = pat["name"]
            self.actor_names.append(name)
            ttp_texts = " ".join(
                f"{t['technique_id']} {t['tactic']} {t['name']} {' '.join(t.get('detection_rules', []))}"
                for t in pat.get("network_ttps", [])
            )
            doc = f"{name} {' '.join(pat.get('aliases', []))} {pat.get('type', '')} {pat.get('description', '')} {ttp_texts} {report_by_actor.get(name, '')}"
            self.corpus.append(doc)

    def compute_similarity(self, telemetry_narrative):
        query_tfidf = self.vectorizer.transform([telemetry_narrative])
        cos_tfidf = cosine_similarity(query_tfidf, self.actor_tfidf)[0]

        if self.svd is not None:
            query_lsa = normalize(self.svd.transform(query_tfidf))
            cos_lsa = cosine_similarity(query_lsa, self.actor_embeddings)[0]
            # Combinação convexa entre similaridade lexical exata (TF-IDF) e semântica latente (LSA)
            combined = 0.65 * cos_tfidf + 0.35 * np.clip(cos_lsa, 0, 1)
        else:
            combined = cos_tfidf

        return {
            self.actor_names[i]: round(float(combined[i]) * 100.0, 2)
            for i in range(len(self.actor_names))
        }


# ======================================================================================
# 3. CLASSIFICADOR SUPERVISIONADO DE MACHINE LEARNING (RANDOM FOREST)
# ======================================================================================
class ThreatAttributionMLClassifier:
    """
    Treina um modelo RandomForestClassifier sobre perfis comportamentais e métricas
    contínuas de tráfego de rede para realizar a atribuição probabilística de incidentes.
    """

    FEATURE_NAMES = [
        "ttp_T1071_001_web_c2",
        "ttp_T1110_001_bruteforce",
        "ttp_T1110_003_spraying",
        "ttp_T1566_001_phish_attach",
        "ttp_T1566_002_phish_link",
        "ttp_T1048_exfil_alt",
        "ttp_T1046_port_scan",
        "ttp_T1570_lateral_transfer",
        "ttp_T1071_004_dns_tunnel",
        "beacon_mean_interval_sec",
        "beacon_jitter_sec",
        "max_outbound_mb",
        "auth_failures_5m",
        "phishing_domain_hits"
    ]

    CLASSES = [
        "APT-DarkSerpent",
        "BlackCat",
        "Kimsuky",
        "Lazarus Group",
        "APT28"
    ]

    def __init__(self, n_samples_per_class=80, random_state=42):
        self.rng = np.random.default_rng(random_state)
        self.model = RandomForestClassifier(
            n_estimators=150,
            max_depth=8,
            random_state=random_state
        )
        self.cv_accuracy = 0.0
        self._train_synthetic_benchmark(n_samples_per_class)

    def _generate_class_samples(self, actor, n):
        X = np.zeros((n, len(self.FEATURE_NAMES)), dtype=float)
        r = self.rng

        for i in range(n):
            if actor == "APT-DarkSerpent":
                # C2 HTTP com beacon ~60s e jitter baixo + Brute Force SSH/RDP + Phishing Domain Callback, SEM exfiltração massiva
                X[i, 0] = r.choice([1, 0], p=[0.95, 0.05])  # T1071.001
                X[i, 1] = r.choice([1, 0], p=[0.92, 0.08])  # T1110.001
                X[i, 3] = r.choice([1, 0], p=[0.88, 0.12])  # T1566.001
                X[i, 9] = r.normal(60.0, 5.0)               # beacon_mean_interval_sec (~60s)
                X[i, 10] = abs(r.normal(2.0, 1.2))          # beacon_jitter_sec (baixo)
                X[i, 11] = abs(r.normal(0.5, 0.3))          # max_outbound_mb (< 2 MB)
                X[i, 12] = r.integers(15, 65)               # auth_failures_5m
                X[i, 13] = r.integers(2, 18)                # phishing_domain_hits

            elif actor == "BlackCat":
                # Ransomware: Brute Force + C2 + Exfiltração Massiva (>25 MB), sem phishing attachment contínuo
                X[i, 0] = r.choice([1, 0], p=[0.90, 0.10])  # T1071.001
                X[i, 1] = r.choice([1, 0], p=[0.92, 0.08])  # T1110.001
                X[i, 5] = r.choice([1, 0], p=[0.96, 0.04])  # T1048 Exfil
                X[i, 9] = r.normal(120.0, 25.0)             # beacon_mean_interval_sec
                X[i, 10] = abs(r.normal(15.0, 5.0))         # jitter moderado
                X[i, 11] = abs(r.normal(45.0, 15.0))        # max_outbound_mb (Exfiltração alta!)
                X[i, 12] = r.integers(10, 50)               # auth_failures_5m
                X[i, 13] = r.integers(0, 2)                 # phishing_domain_hits baixo

            elif actor == "Kimsuky":
                # Espionagem furtiva: Spearphishing Link + Web C2 + Port Scan + Lateral Transfer
                X[i, 0] = r.choice([1, 0], p=[0.94, 0.06])  # T1071.001
                X[i, 4] = r.choice([1, 0], p=[0.90, 0.10])  # T1566.002
                X[i, 5] = r.choice([1, 0], p=[0.75, 0.25])  # T1048
                X[i, 6] = r.choice([1, 0], p=[0.85, 0.15])  # T1046
                X[i, 7] = r.choice([1, 0], p=[0.80, 0.20])  # T1570
                X[i, 9] = r.normal(180.0, 20.0)             # beacon lento
                X[i, 10] = abs(r.normal(8.0, 3.0))
                X[i, 11] = abs(r.normal(12.0, 4.0))
                X[i, 12] = r.integers(0, 4)                 # quase sem brute force ruidoso
                X[i, 13] = r.integers(3, 12)

            elif actor == "Lazarus Group":
                # Operação ampla: C2 + DNS Tunnel + Lateral + Port Scan + Brute Force + Exfil
                X[i, 0] = r.choice([1, 0], p=[0.92, 0.08])
                X[i, 1] = r.choice([1, 0], p=[0.70, 0.30])
                X[i, 5] = r.choice([1, 0], p=[0.85, 0.15])
                X[i, 6] = r.choice([1, 0], p=[0.88, 0.12])
                X[i, 7] = r.choice([1, 0], p=[0.88, 0.12])
                X[i, 8] = r.choice([1, 0], p=[0.85, 0.15])  # DNS Tunneling
                X[i, 9] = r.normal(90.0, 15.0)
                X[i, 10] = abs(r.normal(6.0, 2.0))
                X[i, 11] = abs(r.normal(25.0, 8.0))
                X[i, 12] = r.integers(5, 20)
                X[i, 13] = r.integers(1, 5)

            elif actor == "APT28":
                # Password Spraying + DNS Tunneling + Port Scan + Lateral
                X[i, 0] = r.choice([1, 0], p=[0.88, 0.12])
                X[i, 2] = r.choice([1, 0], p=[0.95, 0.05])  # T1110.003 Spraying
                X[i, 3] = r.choice([1, 0], p=[0.75, 0.25])
                X[i, 6] = r.choice([1, 0], p=[0.85, 0.15])
                X[i, 7] = r.choice([1, 0], p=[0.80, 0.20])
                X[i, 8] = r.choice([1, 0], p=[0.90, 0.10])  # DNS Tunneling
                X[i, 9] = r.normal(150.0, 30.0)
                X[i, 10] = abs(r.normal(12.0, 4.0))
                X[i, 11] = abs(r.normal(8.0, 3.0))
                X[i, 12] = r.integers(8, 30)
                X[i, 13] = r.integers(1, 6)

        return X

    def _train_synthetic_benchmark(self, n_per_class):
        X_list, y_list = [], []
        for idx, actor in enumerate(self.CLASSES):
            X_actor = self._generate_class_samples(actor, n_per_class)
            X_list.append(X_actor)
            y_list.extend([idx] * n_per_class)

        X_all = np.vstack(X_list)
        y_all = np.array(y_list)

        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = cross_val_score(self.model, X_all, y_all, cv=skf, scoring="accuracy")
        self.cv_accuracy = float(np.mean(cv_scores)) * 100.0

        self.model.fit(X_all, y_all)

    def predict_incident(self, feature_dict):
        x_vec = np.array([[float(feature_dict.get(f, 0.0)) for f in self.FEATURE_NAMES]])
        probs = self.model.predict_proba(x_vec)[0]
        return {
            self.CLASSES[i]: round(float(probs[i]) * 100.0, 2)
            for i in range(len(self.CLASSES))
        }

    def get_top_feature_importances(self, top_k=5):
        importances = self.model.feature_importances_
        pairs = sorted(zip(self.FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
        return [(name, round(float(imp) * 100.0, 2)) for name, imp in pairs[:top_k]]

