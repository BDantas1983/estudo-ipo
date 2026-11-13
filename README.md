# Orquestrador de Padrões de Inteligência (IPO v2.0 — Data Science, PLN & Machine Learning Edition)

Implementação independente e expandida com **Ciência de Dados, Processamento de Linguagem Natural (PLN) e Machine Learning**, baseada na metodologia apresentada no **SBRC 2025**:

> **Referência Metodológica Base:**  
> BARROS, Gustavo Antonio Souza de; GONDIM, João José Costa. *Inteligência de Ameaças Cibernéticas para Melhoria na Detecção e Resposta a Incidentes*. In: Simpósio Brasileiro de Redes de Computadores e Sistemas Distribuídos (SBRC — Salão de Ferramentas), 2025.

---

## 📌 1. Contexto e Motivação

No modelo **DML (*Detection Maturity Level*)**, defesas tradicionais operam nos níveis mais baixos (`DML-1` e `DML-2`), bloqueando apenas **Indicadores de Comprometimento (IoCs)** estáticos (IPs, domínios e hashes). O **IPO (*Intelligence Pattern Orchestrator*)** eleva a detecção para os níveis comportamentais (`DML-3` a `DML-8`), correlacionando **Táticas, Técnicas e Procedimentos (TTPs)** mapeadas na matriz **MITRE ATT&CK** diretamente com alertas e fluxos de tráfego de rede.

### O Gargalo da Equação Original (SBRC 2025)
No artigo original, a Pontuação de Correspondência ($PC$) entre o tráfego de rede e o padrão de um grupo ameaçador é calculada pela razão simples de interseção (Equação 1):

$$\text{PC}_{\text{SBRC}} = \frac{|TTPs_{\text{registro}} \cap TTPs_{\text{padrão}}|}{|TTPs_{\text{padrão}}|} \times 100$$

Na Seção 5 (*Conclusão*) do artigo, os próprios autores destacam duas limitações críticas dessa fórmula:
1. **Sobreposição de TTPs Genéricas:** Técnicas onipresentes em rede (como `T1071.001` — *Web Protocols C2*) têm exatamente o mesmo peso que técnicas raras e específicas de um grupo.
2. **Distorção pelo Tamanho do Denominador (*False Attribution*):** Grupos com poucas TTPs mapeadas em rede (ex.: `BlackCat` com 3 técnicas ou `Kimsuky` com 6) têm sua porcentagem inflada artificialmente em comparação a grupos com perfis extensos (ex.: `Lazarus` com 9 ou `APT28` com 10), gerando empates ou falsas atribuições.

---

## 🧠 2. As 4 Evoluções de Ciência de Dados Implementadas (IPO v2.0)

Para solucionar os desafios apontados no artigo, esta versão **IPO v2.0** implementa um pipeline completo de **PLN, Recuperação de Informação Estatística e Aprendizado de Máquina Supervisionado**:

```
┌────────────────────────────────────────────────────────────────────────────┐
│ 1. CAMADA DE INGESTÃO E PLN ([04_nlp_cti_extractor.py])                    │
│  • Relatórios Brutos (cti_raw_reports.json) ──► NER (Atores, Malware, CVE) │
│  • Inferência Semântica de TTPs (TF-IDF N-Gram + Cosine Similarity)        │
│  • Feeds Estruturados JSON & STIX 2.1 (cti_threat_feed.json)               │
└────────────────────────────────────┬───────────────────────────────────────┘
                                     ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ 2. CAMADA DE TELEMETRIA E FEATURE ENGINEERING ([ipo_orchestrator.py])      │
│  • Extração de TTPs em Rede (IoC C2, Phishing Callback, Beaconing, Brute)  │
│  • Extração de Features Contínuas (Intervalo C2, Jitter, Max MB, Falhas)   │
│  • Geração de Narrativa Sintética Automática do Incidente                  │
└────────────────────────────────────┬───────────────────────────────────────┘
                                     ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ 3. MOTOR MULTIMODELO DE ATRIBUIÇÃO ([05_ml_threat_attribution.py])         │
│  ├── Modelo A: Ponderação TF-IDF Cosine & Okapi BM25 por raridade de TTP   │
│  ├── Modelo B: Embeddings Semânticos Latentes (TruncatedSVD / LSA + Cos)   │
│  ├── Modelo C: Classificador Supervisionado Random Forest (150 árvores)    │
│  └── ENSEMBLE FINAL: Fusão Ponderada Multimodelo                           │
└────────────────────────────────────────────────────────────────────────────┘
```

### 2.1. Extração Automática de CTI com PLN, NER e Inferência Semântica (`04_nlp_cti_extractor.py`)
* **NER (*Named Entity Recognition*) Híbrido:** Inspeciona relatórios técnicos não estruturados em texto livre (`cti_raw_reports.json`) e extrai automaticamente:
  * **Threat Actors e Aliases:** `APT-DarkSerpent`, `BlackCat` (`ALPHV`/`Noberus`), `Kimsuky` (`Velvet Chollima`), `Lazarus Group` (`HIDDEN COBRA`), `APT28` (`Fancy Bear`/`Sofacy`).
  * **Famílias de Malware:** `ViperRAT`, `BlackCat-Rust`, `GoldDragon`, `BlindingCan`, `Zebrocy`.
  * **Vulnerabilidades e IoCs:** Códigos `CVE-YYYY-NNNN`, endereços IPv4, domínios maliciosos e hashes SHA-256.
* **Inferência Semântica de TTPs (`CTINLPExtractor`):** Mesmo quando o relatório textual não menciona o código MITRE ATT&CK explicitamente, o módulo divide o texto em sentenças, vetoriza com `TfidfVectorizer(ngram_range=(1, 3), sublinear_tf=True)` e calcula a **Similaridade de Cosseno** contra um corpus descritivo do MITRE ATT&CK para inferir automaticamente as técnicas presentes no texto.

### 2.2. Ponderação Estatística TF-IDF e Okapi BM25 (`05_ml_threat_attribution.py`)
* Em vez de tratar todas as TTPs com peso $1$, a classe `TTPTfIdfScorer` calcula o **IDF (*Inverse Document Frequency*) suavizado** de cada técnica na base de padrões ($N$ grupos):

$$\text{IDF}(t) = \ln\left(\frac{N + 1}{\text{df}(t) + 1}\right) + 1$$

* **Pesos Reais Calculados no Catálogo:**
  * `T1071.001` (*Web Protocols C2* — presente em 5 de 5 grupos): $\text{IDF} = 1.000$ (peso mínimo, técnica genérica)
  * `T1110.001` (*Brute Force: Password Guessing* — presente em 3 de 5 grupos): $\text{IDF} = 1.405$ (peso intermediário)
  * `T1566.001` (*Spearphishing Attachment* — presente em 2 de 5 grupos): $\text{IDF} = 1.693$ (peso alto, técnica discriminativa)
* Além do Cosseno TF-IDF, calcula o ranking probabilístico **Okapi BM25**, que normaliza a pontuação pelo comprimento médio dos perfis de ameaça ($\text{avg\_dl}$), impedindo que grupos com poucas TTPs levem vantagem indevida.

### 2.3. Similaridade Semântica por Embeddings LSA / SVD (`05_ml_threat_attribution.py`)
* A classe `SemanticEmbeddingMatcher` converte os alertas detectados na telemetria de rede em uma **narrativa técnica sintetizada** e a compara com a documentação completa e relatórios de cada grupo.
* Utiliza `TfidfVectorizer` combinado com **Decomposição em Valores Singulares Truncada (`TruncatedSVD` / *Latent Semantic Analysis — LSA*)** e **Similaridade de Cosseno** para capturar relações semânticas latentes entre o comportamento observado no tráfego e o *modus operandi* histórico de cada ator.

### 2.4. Classificador Supervisionado `RandomForestClassifier` (`05_ml_threat_attribution.py`)
* A classe `ThreatAttributionMLClassifier` resolve o problema da baixa quantidade de TTPs visíveis em rede ao combinar **9 features binárias de TTPs** com **5 variáveis contínuas extraídas diretamente dos fluxos de rede**:
  1. `beacon_mean_interval_sec`: Intervalo médio em segundos entre pulsos de C2 (`44.5 s` observados nos logs).
  2. `beacon_jitter_sec`: Desvio padrão temporal da periodicidade do beacon (`3.10 s` observados nos logs).
  3. `auth_failures_5m`: Pico de falhas de autenticação (`401`/`403` ou bloqueios nas portas `22`/`3389`/`445`) em janela deslizante de 5 minutos (`7` falhas).
  4. `phishing_domain_hits`: Total de conexões/callbacks para domínios classificados como spearphishing (`100` hits).
  5. `max_outbound_mb`: Maior volume de megabytes enviados em uma única sessão (`0.004 MB` observados nos logs).
* **Validação e Importância de Variáveis:** O modelo `RandomForestClassifier` (150 árvores) atinge **100.00% de acurácia média em validação cruzada estratificada (*5-Fold Stratified CV*)**, tendo como principais variáveis decisivas (*Gini Importance*):
  * `max_outbound_mb` (`15.27%`)
  * `auth_failures_5m` (`13.85%`)
  * `beacon_mean_interval_sec` (`12.23%`)
  * `ttp_T1110_003_spraying` (`8.71%`)

---

## 📊 3. Resultados Experimentais Comparativos

Executando o `ipo_orchestrator.py` sobre a telemetria real do laboratório (`soc_network_telemetry.csv`, contendo `2.008` eventos de rede), foram identificadas 3 técnicas ativas (`T1071.001`, `T1110.001`, `T1566.001`). Abaixo está a comparação direta entre a **Equação 1 do SBRC** e os **Modelos de Ciência de Dados**:

| Grupo / Ameaça | TTPs Casadas | SBRC Eq. 1 (Artigo) | TF-IDF Cosine | Okapi BM25 | PLN Embeddings (LSA) | Random Forest (ML) | **ENSEMBLE FINAL** |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **APT-DarkSerpent** | `3/3` | `100.00%` | `100.00%` | `100.00%` | `65.47%` | **`92.67%`** | **`88.07%`** |
| **BlackCat** | `2/3` | `66.67%` | `55.32%` | `58.69%` | `26.63%` | **`1.33%`** | **`24.36%`** |
| **Lazarus Group** | `2/9` | `22.22%` | `27.28%` | `37.45%` | `16.37%` | `4.67%` | `15.90%` |
| **APT28** | `2/10` | `20.00%` | `28.66%` | `39.54%` | `14.70%` | `0.00%` | `13.91%` |
| **Kimsuky** | `1/6` | `16.67%` | `11.63%` | `19.01%` | `16.39%` | `1.33%` | `9.29%` |

### 🔍 Análise Crítica dos Ganhos Obtidos:

1. **Desempate e Descarte de Falso Positivo de Ransomware (`BlackCat` vs. `APT-DarkSerpent`):**
   * Quando avaliamos apenas `T1071.001` e `T1110.001`, a fórmula original atribui `66.67%` ao `BlackCat` (2 de 3 técnicas).
   * Contudo, o **Random Forest** analisa a variável contínua `max_outbound_mb = 0.004 MB` e percebe que **não houve exfiltração massiva de dados** (>10 MB), que é a assinatura obrigatória de extorsão dupla do ransomware `BlackCat`. Além disso, detecta o beaconing regular com baixo jitter (`3.10s`) e callbacks de phishing, reduzindo a probabilidade do `BlackCat` para **`1.33%`** e cravando **`92.67%` para o `APT-DarkSerpent`**.
2. **Correção de Ranking por Raridade de Técnica (`APT28` vs. `Lazarus Group`):**
   * Na Equação 1 do SBRC, o `Lazarus Group` (`2/9 = 22.22%`) fica à frente do `APT28` (`2/10 = 20.00%`) apenas por ter um padrão menor.
   * No entanto, as duas técnicas casadas pelo `APT28` são `T1071.001` ($\text{IDF}=1.000$) e `T1566.001` ($\text{IDF}=1.693$), enquanto o `Lazarus` casou `T1071.001` ($\text{IDF}=1.000$) e `T1110.001` ($\text{IDF}=1.405$). Como `T1566.001` é mais rara e específica que `T1110.001`, tanto o **TF-IDF (`28.66%` vs `27.28%`)** quanto o **Okapi BM25 (`39.54%` vs `37.45%`)** corrigem a distorção e colocam o `APT28` acima do `Lazarus` nessa métrica documental.
3. **Penalização de Correspondência Puramente Genérica (`Kimsuky`):**
   * O grupo `Kimsuky` compartilha apenas a técnica `T1071.001` (presente em 100% dos grupos). O modelo TF-IDF reduz sua pontuação de `16.67%` para `11.63%`, e o Ensemble Final o classifica em último lugar (`9.29%`).

---

## 🗂️ 4. Estrutura dos Arquivos do Projeto

| Arquivo | Camada DML / Papel no Sistema | Descrição |
| :--- | :---: | :--- |
| `ipo_orchestrator.py` | **Orquestrador Central (DML-1 a DML-9)** | Executa o pipeline completo: PLN/NER, ingestão CTI, detecção em telemetria, feature engineering e Ensemble de Modelos. |
| `04_nlp_cti_extractor.py` | **Ingestão PLN / NER (DML-3+)** | Extrai Atores, Malwares, CVEs, IoCs e infere TTPs por similaridade semântica a partir de relatórios em texto bruto. |
| `05_ml_threat_attribution.py` | **Ciência de Dados & ML (DML-7 a DML-9)** | Implementa `TTPTfIdfScorer` (TF-IDF/BM25), `SemanticEmbeddingMatcher` (LSA/SVD) e `ThreatAttributionMLClassifier` (Random Forest). |
| `threat_patterns.json` | **Catálogo de Padrões (DML-3 a DML-8)** | Perfis comportamentais estruturados dos grupos (`Lazarus`, `Kimsuky`, `APT28`, `BlackCat`, `APT-DarkSerpent`). |
| `cti_raw_reports.json` | **Corpus Não Estruturado (CTI)** | 5 relatórios técnicos em linguagem natural para processamento pelo módulo de PLN/NER. |
| `cti_threat_feed.json` | **Feed Operacional (DML-1/2)** | Indicadores de Comprometimento estruturados em JSON com mapeamento MITRE. |
| `synthetic_cti_feed.json` | **Feed Padrão OASIS (STIX 2.1)** | Bundle STIX 2.1 contendo objetos `threat-actor`, `malware`, `indicator` e `relationship`. |
| `01_ioc_matching.py` | **Detecção Atômica (DML-1/2)** | Script base de varredura direta de IoCs (IPs e domínios) nos logs do SOC. |
| `02_beaconing_detection.py` | **Detecção Comportamental (DML-3/4)** | Script estatístico de detecção de C2 Beaconing via média temporal e desvio padrão (*jitter*). |
| `03_bruteforce_detection.py` | **Detecção Comportamental (DML-3/4)** | Script de janela deslizante (5 minutos) para detecção de ataques de força bruta (`T1110`). |
| `soc_network_telemetry.csv` | **Telemetria de Rede (NIDS/SOC)** | Base com `2.008` registros de tráfego de rede contendo fluxos normais e ataques simulados. |
| `35858-217-28954-1-10-20250629.pdf` | **Artigo Científico Base** | Artigo original do SBRC 2025 que fundamenta a arquitetura do IPO. |

---

## 🚀 5. Como Executar

### Pré-requisitos
Certifique-se de ter o Python 3 instalado com os pacotes científicos padrão (`numpy`, `scikit-learn`, `scipy`):
```powershell
pip install numpy scikit-learn scipy
```

### 1. Executar o Orquestrador Completo (IPO v2.0 — Data Science & ML)
```powershell
python ipo_orchestrator.py
```

### 2. Executar a Demonstração de PLN / NER e Inferência Semântica em Relatórios Brutos
```powershell
python 04_nlp_cti_extractor.py
```

### 3. Executar os Detectores Individuais de Camada Base
```powershell
python 01_ioc_matching.py
python 02_beaconing_detection.py
python 03_bruteforce_detection.py
```
