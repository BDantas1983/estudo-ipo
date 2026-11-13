# Orquestrador de Padrões de Inteligência (IPO v2.0)
### Framework de Cyber Threat Intelligence (CTI), Machine Learning, Diagnóstico de Risco e Resposta a Incidentes

Implementação expandida, independente e aplicada à detecção comportamental, inspirada e fundamentada na metodologia apresentada no **SBRC 2025**:

> **Referência Metodológica Base:**  
> BARROS, Gustavo Antonio Souza de; GONDIM, João José Costa. *Inteligência de Ameaças Cibernéticas para Melhoria na Detecção e Resposta a Incidentes*. In: **Simpósio Brasileiro de Redes de Computadores e Sistemas Distribuídos (SBRC — Salão de Ferramentas)**, 2025.

---

## 📌 1. Visão Geral e Motivação Acadêmica

Os Centros de Operações de Segurança (SOC) tradicionais enfrentam uma sobrecarga severa de alertas (*alert fatigue*) e operam predominantemente nos níveis mais baixos do modelo **DML (*Detection Maturity Level*)**:
- **DML-1 e DML-2:** Focados em **Indicadores de Comprometimento (IoCs)** estáticos (endereços IP, domínios e hashes de arquivos), que são trivialmente alterados pelos atacantes a custo computacional e financeiro quase nulo (base da *Pyramid of Pain* de David Bianco).
- **DML-3 a DML-8:** Focados em **Táticas, Técnicas e Procedimentos (TTPs)** mapeadas no framework **MITRE ATT&CK**, correlacionando o comportamento real do tráfego e dos hosts corporativos.
- **DML-9:** Hipóteses de Atribuição, Diagnóstico de Risco e Resposta Orquestrada a Incidentes.

O **IPO v2.0** é uma plataforma que integra **Processamento de Linguagem Natural (PLN)**, **Recuperação de Informação Estatística (Okapi BM25 / TF-IDF)**, **Machine Learning Supervisionado (Random Forest)** e uma **Camada de Aconselhamento e Resposta a Incidentes** com **Health Score Corporativo Dinâmico** e integração nativa com o **Wazuh SIEM/XDR**.

---

## 🔬 2. O Problema da Literatura: Limitações da Equação do SBRC 2025

No artigo original do SBRC 2025, a Pontuação de Correspondência ($PC$) entre a telemetria observada na rede e o catálogo de um grupo de ameaça é calculada pela razão direta de interseção de técnicas (Equação 1):

$$\text{PC}_{\text{SBRC}} = \frac{|TTPs_{\text{registro}} \cap TTPs_{\text{padrão}}|}{|TTPs_{\text{padrão}}|} \times 100$$

Os próprios autores destacam na conclusão do trabalho que essa abordagem puramente combinatória possui duas falhas matemáticas e operacionais severas:

1. **Sobreposição de TTPs Genéricas (Falta de Ponderação Estatística):**  
   Técnicas extremamente comuns na internet — como `T1071.001` (*Web Protocols C2 / HTTP/HTTPS*) ou `T1110` (*Brute Force*) — recebem exatamente o mesmo peso ($1.0$) que técnicas raras, avançadas e altamente discriminativas (como `T1071.004` — *DNS Tunneling* ou `T1566.001` — *Spearphishing Attachment*).
2. **Distorção por Tamanho do Denominador (*Falsa Atribuição Sistêmica*):**  
   Grupos com poucas TTPs catalogadas em rede (ex.: `BlackCat` com 3 técnicas ou `Kimsuky` com 6) têm suas porcentagens infladas artificialmente em relação a grupos com catálogos extensos e detalhados (ex.: `Lazarus Group` com 9 técnicas ou `APT28` com 10).
   * **Caso Prático Reportado no Artigo:** Ao submeter a telemetria de um ataque real do **Lazarus Group**, o orquestrador original atribuiu maior pontuação ao **Kimsuky (66%)** do que ao próprio **Lazarus (56%)**, gerando uma falsa atribuição em ambiente de produção.

---

## 🧠 3. Arquitetura do Sistema (Pipeline em 5 Camadas)

O **IPO v2.0** resolve o problema dividindo o ciclo de CTI e Resposta a Incidentes em 5 camadas coordenadas:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. INGESTÃO DE CTI E PLN ([04_nlp_cti_extractor.py])                                   │
│  • Relatórios em Texto Livre (cti_raw_reports.json) ──► NER Híbrido (Atores, Malwares) │
│  • Inferência Semântica de TTPs (TF-IDF N-Gram + Cosine Similarity contra MITRE)       │
│  • Ingestão de Feeds Estruturados (JSON & OASIS STIX 2.1)                             │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 2. TELEMETRIA E ENGENHARIA DE FEATURES ([ipo_orchestrator.py])                         │
│  • Ingestão de Tráfego de Rede (soc_network_telemetry.csv) & Logs SIEM Wazuh          │
│  • Detecção de TTPs e Extração de 5 Variáveis Contínuas:                               │
│    - Intervalo Médio de Beaconing C2 (s)    - Desvio Padrão Temporal / Jitter (s)      │
│    - Falhas de Autenticação (Janela 5 min)  - Hits em Domínios de Phishing             │
│    - Volume Máximo de Exfiltração (MB)                                                 │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 3. MOTOR MULTIMODELO DE ATRIBUIÇÃO ([05_ml_threat_attribution.py])                    │
│  ├── Modelo A: Ponderação TF-IDF Cosine & Okapi BM25 por Raridade de TTP (IDF)        │
│  ├── Modelo B: Embeddings Semânticos Latentes (TruncatedSVD / LSA + Cosseno)           │
│  ├── Modelo C: Classificador Supervisionado Random Forest (150 árvores, 5-Fold CV)     │
│  └── ENSEMBLE PONDERADO FINAL: Fusão Multimodal com Calibração Probabilística          │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 4. MOTOR DE DIAGNÓSTICO E RISCO CORPORATIVO ([incident_advisory.py])                   │
│  • Abordagem Agnóstica: "O que observar e como responder" (não apenas rotular)         │
│  • Cálculo de Risk Score (0-100): Severidade, Escopo, Confiança e Impacto Operacional   │
│  • Matriz de Superfície Afetada: Estações comprometidas, Portas críticas, Credenciais  │
│  • Runbook Priorizado do Analista do SOC: Ações P1 (Imediato), P2 (Alta), P3 (Forense) │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 5. INTERFACE DO ANALISTA & HEALTH SCORE CORPORATIVO ([ipo_dashboard.py])               │
│  • Dashboard Executivo Glassmorphism (Web responsivo, Dark Theme, Tailwind + SVG)      │
│  • Widget Circular de Health Score: Infraestrutura recupera saúde em tempo real        │
│  • 4 Pilares de Postura de Segurança (NIST/CIS): Endpoints, Perímetro, Identidade, Custódia│
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚙️ 4. Detalhamento dos Módulos Científicos e Algoritmos

### 4.1. Processamento de Linguagem Natural e NER em CTI (`04_nlp_cti_extractor.py`)
* **NER (*Named Entity Recognition*) Híbrido:** Extrai automaticamente threat actors, codinomes (*aliases*), famílias de malware, CVEs e IoCs atômicos a partir de relatórios em linguagem natural não estruturados.
* **Inferência Semântica de TTPs:** Quando o texto do relatório não contém o identificador explícito do MITRE (ex.: `T1071.001`), o módulo segmenta as frases do analista, vetoriza com `TfidfVectorizer(ngram_range=(1, 3), sublinear_tf=True)` e calcula a **Similaridade de Cosseno** contra um corpus de descrições oficiais do MITRE ATT&CK.

### 4.2. Ponderação Estatística de TTPs: TF-IDF e Okapi BM25 (`05_ml_threat_attribution.py`)
Para eliminar a fragilidade de pesos idênticos, a classe `TTPTfIdfScorer` calcula o **IDF (*Inverse Document Frequency*) suavizado**:

$$\text{IDF}(t) = \ln\left(\frac{N + 1}{\text{df}(t) + 1}\right) + 1$$

* **Exemplos de Pesos Calculados na Base de Conhecimento:**
  * `T1071.001` (*Web Protocols C2* — onipresente em todos os grupos): $\text{IDF} = 1.000$ (peso mínimo)
  * `T1110.001` (*Brute Force Password Guessing*): $\text{IDF} = 1.405$ (peso intermediário)
  * `T1566.001` (*Spearphishing Attachment*): $\text{IDF} = 1.693$ (peso alto, técnica discriminativa)
  * `T1071.004` (*DNS Tunneling*): $\text{IDF} = 2.098$ (peso altíssimo, altamente específico)
* **Ranking Probabilístico Okapi BM25:** Normaliza a pontuação considerando o comprimento do perfil da ameaça em relação ao comprimento médio ($\text{avg\_dl}$), eliminando a vantagem indevida de grupos com catálogo curto.

### 4.3. Embeddings Semânticos Latentes via LSA / SVD (`05_ml_threat_attribution.py`)
* Sintetiza os alertas observados no tráfego em uma narrativa técnica textual.
* Utiliza **Decomposição em Valores Singulares Truncada (`TruncatedSVD` / *Latent Semantic Analysis*)** para mapear o comportamento observado no espaço vetorial latente dos perfis históricos dos atacantes.

### 4.4. Machine Learning Supervisionado (`RandomForestClassifier`)
O modelo combina a presença de técnicas com **5 variáveis contínuas comportamentais da rede**:
1. `beacon_mean_interval_sec`: Média de intervalo temporal entre requisições C2.
2. `beacon_jitter_sec`: Desvio padrão temporal das requisições (jitter do malware).
3. `auth_failures_5m`: Volume de falhas de autenticação (`401`/`403`/SSH) em janela de 5 minutos.
4. `phishing_domain_hits`: Quantidade de acessos a domínios de engodo/spearphishing.
5. `max_outbound_mb`: Maior tráfego de saída observado em uma única sessão.

* **Performance:** Com 150 estimadores, o modelo alcança **100% de acurácia em Validação Cruzada Estratificada (*5-Fold Stratified CV*)**.
* **Importância das Variáveis (*Gini Importance*):** `max_outbound_mb` (15.27%), `auth_failures_5m` (13.85%), `beacon_mean_interval_sec` (12.23%).

---

## 📊 5. Resultados Experimentais e Validação Empírica

### Experimento 1: Telemetria de Laboratório do SOC (2.008 Eventos de Rede)
Cenário contendo tráfego real com atividade simultânea de spearphishing callback, força bruta interna e tráfego C2 HTTP.

| Grupo / Ameaça | TTPs Casadas | SBRC Eq. 1 (Artigo Original) | TF-IDF Cosine | Okapi BM25 | LSA Embeddings | Random Forest (ML) | **ENSEMBLE v2.0** | Veredito |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **APT-DarkSerpent** | `3/3` | `100.00%` | `100.00%` | `100.00%` | `65.47%` | **`92.67%`** | **`88.07%`** | **Autor Correto** |
| **BlackCat (Ransomware)**| `2/3` | `66.67%` | `55.32%` | `58.69%` | `26.63%` | **`1.33%`** | **`24.36%`** | **Descartado pelo ML** |
| **Lazarus Group** | `2/9` | `22.22%` | `27.28%` | `37.45%` | `16.37%` | `4.67%` | `15.90%` | Atribuição Secundária |
| **APT28** | `2/10` | `20.00%` | `28.66%` | `39.54%` | `14.70%` | `0.00%` | `13.91%` | Atribuição Secundária |
| **Kimsuky** | `1/6` | `16.67%` | `11.63%` | `19.01%` | `16.39%` | `1.33%` | `9.29%` | Descartado |

* **Ganho Crítico:** O modelo do SBRC indicou 66.67% para o ransomware `BlackCat`. O **Random Forest** avaliou `max_outbound_mb = 0.004 MB` e constatou a ausência de exfiltração massiva (assinatura obrigatória de dupla extorsão), derrubando a probabilidade do BlackCat para **1.33%** e confirmando o ator de espionagem `APT-DarkSerpent` com **92.67%**.

---

### Experimento 2: Ground Truth — O Teste Cego do Caso Lazarus Group (`07_teste_cego_lazarus.py`)
Para auditar a falha de falsa atribuição reportada na literatura (onde o SBRC atribuiu 66% ao Kimsuky e apenas 56% ao Lazarus), foi construído um dataset de teste cego (`teste_cego_lazarus_anonimizado.csv` com 933 fluxos e `.json` com 133 alertas), **100% livre de qualquer rótulo ou nome textual de grupo**, contendo apenas telemetria real (beacon de 90s, jitter de 5.6s, Tunelamento DNS, SMB lateral e 24.5 MB de exfiltração).

| Grupo / Ameaça | TTPs Casadas | SBRC Eq. 1 (Artigo Original) | Okapi BM25 | Random Forest (ML) | **ENSEMBLE v2.0** | Veredito |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Lazarus Group (Autor Real)** | `6/9` | `66.67%` | **`100.00%`** | **`94.67%`** | **`92.00%`** | **CORRETO (Vencedor)** |
| **BlackCat** | `3/3` | **`100.00%`** *(Falso Positivo)* | `71.83%` | `5.33%` | `30.54%` | Descartado pelo ML |
| **Kimsuky** | `4/6` | `66.67%` *(Empate Indevido)* | `76.60%` | `0.00%` | `26.67%` | Descartado pelo ML |
| **APT28** | `4/10` | `40.00%` | `62.43%` | `0.00%` | `20.65%` | Descartado |
| **APT-DarkSerpent** | `2/3` | `66.67%` | `45.34%` | `0.00%` | `16.24%` | Descartado |

* **Como o IPO v2.0 superou a literatura:**
  1. A Equação 1 do SBRC foi enganada pelo denominador pequeno: pontuou **100% para o BlackCat** e empatou **Kimsuky e Lazarus**.
  2. O **Okapi BM25** penalizou BlackCat e Kimsuky por não possuírem técnicas raras identificadas (Tunelamento DNS), concedendo pontuação máxima ao Lazarus.
  3. O **Random Forest** avaliou a periodicidade precisa de rede (`90.2s` de beacon, `5.65s` de jitter e `24.5 MB` de exfiltração), cravando **94.67%** de probabilidade para o Lazarus e **0.00%** para Kimsuky.
  4. O **Ensemble v2.0 atribuiu 92.00% ao Lazarus Group**, revertendo a falha histórica.

---

## 🛡️ 6. Da Detecção à Resposta: Diagnóstico, Aconselhamento e Health Score

A literatura moderna de CTI e Resposta a Incidentes (NIST SP 800-61r2, MITRE D3FEND, CIS Controls v8) salienta que **atribuição de atores estatais é probabilística e não deve atrasar a contenção**. Um analista de SOC precisa saber **o que está acontecendo e o que fazer imediatamente**, independentemente do nome do grupo.

### 6.1. O Módulo `incident_advisory.py`
O sistema calcula:
- **Score de Risco Corporativo (0 a 100):** Combina severidade das técnicas observadas, abrangência na rede (ativos impactados), confiança da telemetria e criticidade de negócios.
- **Mapeamento de Superfície Comprometida:** Identifica IPs de origem, servidores alvos, portas vulneráveis (`22`, `445`, `80/443`) e credenciais expostas.
- **Runbook Dinâmico de Triagem & Contenção:** Gera um checklist estruturado em 3 níveis de prioridade:
  - **P1 - Imediato (Remediação de Alto Impacto):** Isolamento de rede do paciente zero via EDR/switch; auditoria de compartilhamentos e pastas temporárias.
  - **P2 - Alta (Contenção de Perímetro e Identidade):** Bloqueio/Sinkhole de IPs/domínios externos em Firewalls; revogação de tokens de autenticação e reset de senhas comprometidas.
  - **P3 - Investigativo (Cadeia de Custódia e Forense):** Coleta de dumps de memória RAM, preservação de logs de eventos (Sysmon / Event IDs 4624, 4625, 4688).

### 6.2. Health Score Corporativo Dinâmico & 4 Pilares NIST/CIS
Integrado ao dashboard web, o sistema provê um **Health Score** reativo:
* **Baseline Inicial:** Calculado inversamente ao nível de ameaça:
  
  $$\text{Health}_{\text{inicial}} = \max(5, 100 - \text{Risk Score})$$

  Em um incidente crítico (como o caso Lazarus), a saúde da empresa inicia em **12%** (ou 35% no cenário padrão).
* **Recuperação Reativa via Checklist:** Cada ação executada pelo operador possui um peso percentual de remediação (`+25%`, `+20%`, `+20%`, `+20%`, `+15%`). Ao completar as ações, o widget SVG circular transita de cor (Vermelho $\to$ Âmbar $\to$ Teal $\to$ Esmeralda), elevando a saúde corporativa até **100% ("Totalmente Seguro / Incidente Contido")**.
* **4 Pilares de Postura de Segurança:**
  * **Endpoints:** *Exposto* $\to$ *Isolado [✓]*
  * **Perímetro:** *Vazando* $\to$ *Bloqueado [✓]*
  * **Identidade:** *Em Risco* $\to$ *Protegida [✓]*
  * **Custódia Forense:** *Pendente* $\to$ *Preservada [✓]*

---

## 🔌 7. Integração Real SIEM/XDR: Conector Wazuh (`06_wazuh_connector_test.py`)

O sistema não se restringe a dados sintéticos. O script `06_wazuh_connector_test.py` implementa um conector para o **Wazuh SIEM/XDR**:
* Ingestão de alertas em formato JSON (`/var/ossec/logs/alerts/alerts.json` ou exports de laboratório).
* Mapeamento automático dos campos do Wazuh:
  * `rule.mitre.id` $\to$ Extração de TTPs MITRE ATT&CK.
  * `rule.level` $\to$ Severidade ponderada do evento.
  * `data.srcip` e `data.dstip` $\to$ Mapeamento de endpoints e tráfego de C2.
  * `data.srcport` e `data.dstport` $\to$ Serviços atacados (SSH, SMB, RDP, HTTP).
* O arquivo `wazuh_alerts_hf.json` (com mais de 2.9 MB de eventos reais de laboratório) valida a capacidade do IPO de processar telemetria bruta de ambientes corporativos.

---

## 🗂️ 8. Estrutura Completa do Repositório

| Arquivo / Diretório | Papel / Camada Arquitetural | Descrição |
| :--- | :---: | :--- |
| `ipo_dashboard.py` | **Dashboard Executivo & SOC** | Servidor web nativo (sem dependências de frameworks externos) com UI Dark Mode, alternância de cenários, upload de telemetria, checklist interativo e widget de Health Score. |
| `public/index.html` | **Front-end Responsivo** | Template estático HTML5/Tailwind/Lucide Icons sincronizado para visualização cliente e deploy estático/serverless. |
| `incident_advisory.py` | **Motor de Diagnóstico & Risco** | Módulo de aconselhamento, cálculo de Health Score, avaliação de risco (0-100), matriz de superfície afetada e geração do runbook de contenção. |
| `ipo_orchestrator.py` | **Orquestrador Central (DML-1 a DML-9)** | Pipeline completo: ingestão de CTI, detecção comportamental, feature engineering e cálculo do Ensemble Multimodelo. |
| `04_nlp_cti_extractor.py` | **PLN & NER em CTI (DML-3+)** | Extração de entidades nomeadas e inferência de TTPs via Similaridade de Cosseno TF-IDF em relatórios não estruturados. |
| `05_ml_threat_attribution.py` | **Ciência de Dados & ML** | Implementação dos modelos matemáticos: `TTPTfIdfScorer` (TF-IDF/Okapi BM25), `SemanticEmbeddingMatcher` (LSA/SVD) e `ThreatAttributionMLClassifier` (Random Forest). |
| `06_wazuh_connector_test.py` | **Conector SIEM/XDR** | Ingestão e normalização de alertas reais do Wazuh para alimentação do pipeline do IPO. |
| `07_teste_cego_lazarus.py` | **Benchmark Ground Truth** | Script de validação cega com o dataset anonimizado do Lazarus Group, comparando diretamente SBRC 2025 vs IPO v2.0. |
| `01_ioc_matching.py` | **Detecção Atômica (DML-1/2)** | Motor de varredura e correlação direta de IoCs (IPs, domínios, hashes). |
| `02_beaconing_detection.py` | **Detecção Comportamental (DML-3/4)**| Algoritmo estatístico de detecção de C2 Beaconing (média temporal e jitter). |
| `03_bruteforce_detection.py` | **Detecção Comportamental (DML-3/4)**| Algoritmo de janela deslizante temporal (5 min) para detecção de força bruta. |
| `threat_patterns.json` | **Catálogo de Padrões CTI** | Perfis comportamentais estruturados de grupos reais (`Lazarus`, `Kimsuky`, `APT28`, `BlackCat`, `APT-DarkSerpent`). |
| `cti_raw_reports.json` | **Corpus Textual Não Estruturado**| Relatórios técnicos em linguagem natural para teste do módulo de PLN/NER. |
| `soc_network_telemetry.csv` | **Telemetria de Rede (NIDS)** | Base com 2.008 fluxos de rede normais e ataques simulados de laboratório. |
| `teste_cego_lazarus_anonimizado.csv` | **Dataset Cego de Tráfego** | 933 fluxos de rede reais anonimizados sem qualquer menção nominal de grupo. |
| `teste_cego_lazarus_anonimizado.json` | **Dataset Cego de Alertas** | 133 alertas SIEM do caso Lazarus Group para teste cego de atribuição. |
| `wazuh_alerts_hf.json` | **Telemetria Real de SIEM** | Amostra de 2.9 MB de alertas reais do Wazuh SIEM/XDR. |
| `generate_thesis_pdf.py` | **Gerador de Documentação** | Script em ReportLab que gera o documento acadêmico formal do projeto. |
| `generate_layman_pdf.py` | **Gerador de Guia Didático** | Script que gera o guia explicativo para estudo e nivelamento conceitual. |
| `render.yaml` / `Procfile` | **Infraestrutura em Nuvem** | Arquivos de orquestração para deploy contínuo em produção no **Render**. |

---

## 🚀 9. Guia de Instalação e Execução

### Pré-requisitos
- Python 3.10 ou superior.
- Pacotes científicos padrão listados no `requirements.txt`:
```bash
pip install -r requirements.txt
```
*(Conteúdo: `numpy`, `scikit-learn`, `scipy`)*

---

### Passo 1: Executar o Dashboard Web do SOC & Analista (Recomendado)
Inicia o servidor web local com a interface interativa completa:
```bash
python ipo_dashboard.py
```
* Abra no navegador: **`http://localhost:8080`**
* No dashboard, você pode:
  * Visualizar a pontuação de risco e o diagnóstico da infraestrutura.
  * Alternar entre o **Cenário Padrão (Laboratório)** e o **Teste Cego (Lazarus)** no seletor do topo.
  * Interagir com o **Checklist do Analista** e ver o **Health Score** subir em tempo real.
  * Submeter novos arquivos CSV de rede ou JSON do SIEM na área de upload.

---

### Passo 2: Executar o Benchmark Cego do Caso Lazarus Group
Comprova experimentalmente a superação do algoritmo do SBRC 2025:
```bash
python 07_teste_cego_lazarus.py
```

---

### Passo 3: Executar o Orquestrador Central via Terminal (Modo CLI)
Executa todo o pipeline ponta a ponta e exibe as matrizes comparativas no console:
```bash
python ipo_orchestrator.py
```

---

### Passo 4: Executar os Módulos Específicos
* **Demonstração de PLN, NER e Inferência Semântica:**
  ```bash
  python 04_nlp_cti_extractor.py
  ```
* **Teste do Conector com Alertas Reais do Wazuh SIEM/XDR:**
  ```bash
  python 06_wazuh_connector_test.py
  ```
* **Detectores Atômicos e Estatísticos de Base:**
  ```bash
  python 01_ioc_matching.py
  python 02_beaconing_detection.py
  python 03_bruteforce_detection.py
  ```

---

## 🌐 10. Deploy em Produção (Nuvem)

O projeto está totalmente preparado para deploy contínuo na nuvem:
* **Render:** Configurado via `render.yaml` e `Procfile` com `python ipo_dashboard.py`. Qualquer push na branch `main` dispara o build e deploy automático.
* **Vercel:** Configuração serverless disponível em `vercel.json` e `api/index.py`.

---

## 📚 11. Produção Acadêmica e Materiais Complementares

Para suporte pedagógico e apresentação formal à banca ou banca avaliadora, o repositório inclui:
1. `Artigo_Base_SBRC_2025_Barros_Gondim.pdf`: Artigo científico publicado no Simpósio Brasileiro de Redes de Computadores que serviu de inspiração metodológica.
2. `Apresentacao_IPO_v2.pdf`: Apresentação estruturada com gráficos de arquitetura, formulações e conclusões científicas.
3. `Guia_Simples_Para_Estudo_IPO.pdf`: Guia didático passo a passo explicando cada conceito para estudantes e analistas juniores.
4. `comparativo_modelos_banca.png`: Infográfico comparativo de alta resolução entre os modelos estatísticos e o Random Forest.

---

## 👩‍💻 Autoria e Informações Acadêmicas
- **Autora do Projeto:** Brisa Kalene (`kalenebrisa@gmail.com`)
- **Repositório Oficial:** [https://github.com/BDantas1983/estudo-ipo](https://github.com/BDantas1983/estudo-ipo)
- **Licença:** MIT — Livre para fins acadêmicos, pesquisa e aplicação educacional.
