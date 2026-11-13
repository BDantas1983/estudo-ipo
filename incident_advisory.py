"""
========================================================================================
MÓDULO: MOTOR DE LAUDO CLÍNICO E RECOMENDAÇÃO FORENSE (INCIDENT ADVISORY ENGINE)
========================================================================================
Transfere o foco de um classificador fechado de atores ("quem foi") para uma plataforma
profissional de Detecção e Resposta (NDR/XDR), respondendo:
  1. O QUE está acontecendo? (Severidade, status, estágio de intrusão)
  2. ONDE está o foco do ataque? (Paciente zero, alvos internos impactados)
  3. COMO o ataque evoluiu? (Reconstituição da Cyber Kill Chain / MITRE ATT&CK)
  4. QUAIS evidências matemáticas de automação foram detectadas? (Beaconing, Túnel DNS)
  5. O QUE o analista do SOC deve fazer agora? (Checklist de contenção e caça ativa)
  6. QUAL o contexto de inteligência? (Afinidade técnica com perfis conhecidos de CTI)
========================================================================================
"""

def generate_incident_advisory(telemetry_data, ranking, active_dataset_name=""):
    detected_ttps = set(telemetry_data.get("detected_ttps", []))
    beacon_mean = telemetry_data.get("beacon_mean", 0.0)
    beacon_jitter = telemetry_data.get("beacon_jitter", 0.0)
    auth_fails = telemetry_data.get("auth_fails_5m", 0)
    max_mb = telemetry_data.get("max_outbound_mb", 0.0)
    patient_zero = telemetry_data.get("patient_zero", {"ip": "10.0.1.25", "hostname": "WS-FINANCE-04", "user": "a.silva"})
    internal_targets = telemetry_data.get("internal_targets", ["10.0.2.100 (Portas 445 SMB, 22 SSH)"])
    external_destinations = telemetry_data.get("external_destinations", ["198.51.100.77:443 (C2 HTTPS)", "auth-sync-token.com (Porta 53 DNS)", "198.51.100.88 (Exfiltração)"])

    # 1. Cálculo de Risco e Severidade Global (0 a 100)
    risk_score = 15
    if "T1071.001" in detected_ttps:
        risk_score += 20
    if beacon_jitter > 0 and beacon_jitter < 15:
        risk_score += 15  # Automação/Implante comprovado
    if "T1110.001" in detected_ttps or auth_fails >= 5:
        risk_score += 15
    if "T1570" in detected_ttps:
        risk_score += 15  # Movimentação lateral interna
    if "T1071.004" in detected_ttps:
        risk_score += 10  # Tunelamento evasivo
    if "T1048" in detected_ttps or max_mb > 5.0:
        risk_score += 15  # Exfiltração ativa

    risk_score = min(risk_score, 98)

    if risk_score >= 80:
        severity_label = "CRÍTICO"
        severity_color = "red"
        status_label = "Comprometimento Ativo Multi-Estágio com Exfiltração"
    elif risk_score >= 50:
        severity_label = "ALTO"
        severity_color = "amber"
        status_label = "Intrusão em Andamento com Movimentação Lateral"
    else:
        severity_label = "MODERADO"
        severity_color = "blue"
        status_label = "Varredura / Atividade Anômala em Investigação"

    # 2. Reconstituição da Linha do Tempo (Cyber Kill Chain)
    stages = []

    # Estágio 1: Reconhecimento
    if "T1046" in detected_ttps:
        stages.append({
            "phase": "1. Reconhecimento & Descoberta Interna",
            "ttp": "T1046 (Network Service Discovery)",
            "status": "Executado",
            "badge": "Concluído",
            "desc": f"Mapeamento ativo de portas e serviços na rede interna a partir do host {patient_zero.get('ip', '10.0.1.25')}."
        })
    else:
        stages.append({
            "phase": "1. Reconhecimento",
            "ttp": "N/A",
            "status": "Não Detectado",
            "badge": "Sem indícios",
            "desc": "Nenhuma varredura massiva de portas observada na janela de análise."
        })

    # Estágio 2: Acesso a Credenciais / Movimentação Lateral
    if "T1110.001" in detected_ttps or "T1570" in detected_ttps:
        detail_p2 = []
        if "T1110.001" in detected_ttps or auth_fails >= 5:
            detail_p2.append(f"explosão de {auth_fails} falhas de autenticação")
        if "T1570" in detected_ttps:
            detail_p2.append("transferência interna de binários/ferramentas via SMB (porta 445)")

        stages.append({
            "phase": "2. Credenciais & Movimentação Lateral",
            "ttp": "T1110.001 / T1570 (Lateral Tool Transfer)",
            "status": "Em Progresso / Ativo",
            "badge": "Crítico",
            "desc": f"Comprometimento com {', '.join(detail_p2)} em direção aos alvos internos ({', '.join(internal_targets)})."
        })

    # Estágio 3: Canal Oculto de C2
    if "T1071.001" in detected_ttps or "T1071.004" in detected_ttps:
        c2_details = []
        if "T1071.001" in detected_ttps and beacon_mean > 0:
            c2_details.append(f"beaconing HTTPS regular (intervalo {beacon_mean:.1f}s, jitter {beacon_jitter:.2f}s)")
        if "T1071.004" in detected_ttps:
            c2_details.append("tunelamento DNS evasivo na porta 53 para burlar inspeção de tráfego")

        stages.append({
            "phase": "3. Comando e Controle (C2)",
            "ttp": "T1071.001 / T1071.004 (Covert C2 & DNS Tunneling)",
            "status": "Ativo",
            "badge": "Severo",
            "desc": f"Canal de controle estabelecido via {', '.join(c2_details)} comunicando com servidores externos."
        })

    # Estágio 4: Exfiltração de Dados
    if "T1048" in detected_ttps or max_mb > 5.0:
        stages.append({
            "phase": "4. Exfiltração e Impacto",
            "ttp": "T1048 (Exfiltration Over Alternative Protocol)",
            "status": "Concluído",
            "badge": "Crítico",
            "desc": f"Transferência externa anômala de {max_mb:.2f} MB de dados confidenciais para repositório não autorizado."
        })

    # 3. Checklist Prático para o Analista do SOC (Runbook Operacional) com Pesos de Saúde
    checklist = [
        {
            "id": "chk-1",
            "action": f"Isolamento Emergencial da Estação {patient_zero.get('ip', '10.0.1.25')}",
            "description": f"Cortar conectividade de rede do host {patient_zero.get('hostname', 'WS-FINANCE-04')} via EDR ou porta de switch para conter a propagação lateral.",
            "priority": "P1 - Imediato",
            "priority_color": "red",
            "weight": 25,
            "category": "endpoints"
        },
        {
            "id": "chk-2",
            "action": "Auditoria de Arquivos no Servidor Alvo",
            "description": f"Inspecionar compartilhamentos SMB e diretórios temporários em {', '.join(internal_targets)} para localizar binários ou scripts criados nas últimas horas.",
            "priority": "P1 - Imediato",
            "priority_color": "red",
            "weight": 20,
            "category": "audit"
        },
        {
            "id": "chk-3",
            "action": "Bloqueio e Sinkhole de Infraestrutura Externa",
            "description": f"Inserir regras no Firewall corporativo e DNS para bloquear o tráfego externo para: {', '.join(external_destinations)}.",
            "priority": "P2 - Alta",
            "priority_color": "amber",
            "weight": 20,
            "category": "network"
        },
        {
            "id": "chk-4",
            "action": f"Revogação Forçada de Credenciais de '{patient_zero.get('user', 'a.silva')}'",
            "description": "Redefinir senha de domínio no Active Directory/IdP e revogar imediatamente todos os tokens de sessão e conexões VPN ativas.",
            "priority": "P2 - Alta",
            "priority_color": "amber",
            "weight": 20,
            "category": "identity"
        },
        {
            "id": "chk-5",
            "action": "Coleta Forense de Memória e Artefatos (Triage)",
            "description": "Extrair despejo de memória RAM e logs de eventos (Sysmon / Event Viewer IDs 4624, 4625, 4688) do paciente zero para preservação de cadeia de custódia.",
            "priority": "P3 - Investigativo",
            "priority_color": "blue",
            "weight": 15,
            "category": "forensics"
        }
    ]

    # 4. Cálculo do Health Score Inicial da Infraestrutura
    initial_health = max(5, 100 - risk_score)
    health_score_data = {
        "initial": initial_health,
        "max": 100,
        "status_initial": "Crítico / Comprometido" if initial_health < 40 else ("Ameaça em Andamento" if initial_health < 70 else "Atenção Operacional"),
        "postures": {
            "endpoints": "Exposto",
            "network": "Vazando",
            "identity": "Em Risco",
            "forensics": "Pendente"
        }
    }

    # 5. Nota Contextual de CTI (Benchmark de Sofisticação sem rotulação cega)
    top_actor = ranking[0] if ranking else {"name": "Ameaça Avançada", "ensemble": 0.0}
    second_actor = ranking[1] if len(ranking) > 1 else {"name": "Genérica", "ensemble": 0.0}

    cti_note = (
        f"O conjunto de comportamentos e métricas temporais apresenta alta correlação técnica ({top_actor['ensemble']:.1f}%) "
        f"com o modus operandi clássico de agentes de ciberespionagem sofisticados (perfil compatível com {top_actor['name']}), "
        f"enquanto cenários de ransomware genérico ({second_actor['name']}) registraram apenas {second_actor['ensemble']:.1f}% de afinidade. "
        "Ressalva Forense: Esta correlação tem finalidade orientativa e contextual; não se descarta o reuso de ferramentas "
        "por atacantes autônomos ou campanhas oportunistas de commodity malware."
    )

    return {
        "severity": {
            "score": risk_score,
            "label": severity_label,
            "color": severity_color,
            "status": status_label
        },
        "health_score": health_score_data,
        "patient_zero": patient_zero,
        "internal_targets": internal_targets,
        "external_destinations": external_destinations,
        "kill_chain_stages": stages,
        "analyst_checklist": checklist,
        "cti_affinity_note": cti_note
    }
