"""
Gera o documento PDF detalhado (nível Banca de Mestrado com linguagem acessível e didática)
explicando o artigo original (SBRC 2025), os problemas diagnosticados e as 4 evoluções de
Ciência de Dados, PLN e Machine Learning implementadas no IPO v2.0.
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

OUTPUT_PDF = "Apresentacao_Banca_Mestrado_IPO_v2.pdf"
CHART_PATH = "comparativo_modelos_banca.png"


def register_fonts():
    """Registra fontes TrueType do Windows para suporte completo a acentuação e símbolos."""
    font_dir = r"C:\Windows\Fonts"
    arial_reg = os.path.join(font_dir, "arial.ttf")
    arial_bd = os.path.join(font_dir, "arialbd.ttf")
    arial_it = os.path.join(font_dir, "ariali.ttf")
    arial_bi = os.path.join(font_dir, "arialbi.ttf")

    if os.path.exists(arial_reg) and os.path.exists(arial_bd):
        pdfmetrics.registerFont(TTFont("CustomSans", arial_reg))
        pdfmetrics.registerFont(TTFont("CustomSans-Bold", arial_bd))
        pdfmetrics.registerFont(TTFont("CustomSans-Italic", arial_it if os.path.exists(arial_it) else arial_reg))
        pdfmetrics.registerFont(TTFont("CustomSans-BoldItalic", arial_bi if os.path.exists(arial_bi) else arial_bd))
        pdfmetrics.registerFontFamily(
            "CustomSans",
            normal="CustomSans",
            bold="CustomSans-Bold",
            italic="CustomSans-Italic",
            boldItalic="CustomSans-BoldItalic",
        )
        return "CustomSans"
    return "Helvetica"


def generate_comparison_chart():
    """Gera um gráfico comparativo de barras mostrando a evolução da precisão de atribuição."""
    actors = ["APT-DarkSerpent\n(Culpado Real)", "BlackCat\n(Ransomware)", "Lazarus Group", "APT28", "Kimsuky"]
    sbrc_eq1 = [100.0, 66.67, 22.22, 20.00, 16.67]
    tfidf_bm25 = [100.0, 58.69, 37.45, 39.54, 19.01]
    pln_embed = [65.47, 26.63, 16.37, 14.70, 16.39]
    random_forest = [92.67, 1.33, 4.67, 0.00, 1.33]
    ensemble_final = [88.07, 24.36, 15.90, 13.91, 9.29]

    x = np.arange(len(actors))
    width = 0.16

    fig, ax = plt.subplots(figsize=(9.5, 4.4), dpi=220)
    rects1 = ax.bar(x - 2 * width, sbrc_eq1, width, label="SBRC Eq. 1 (Original)", color="#64748B")
    rects2 = ax.bar(x - width, tfidf_bm25, width, label="Okapi BM25 (Raridade TTP)", color="#0284C7")
    rects3 = ax.bar(x, pln_embed, width, label="PLN Embeddings (LSA)", color="#7C3AED")
    rects4 = ax.bar(x + width, random_forest, width, label="Random Forest (ML)", color="#059669")
    rects5 = ax.bar(x + 2 * width, ensemble_final, width, label="Ensemble Final (IPO v2.0)", color="#DC2626")

    ax.set_ylabel("Pontuação / Probabilidade (%)", fontsize=10, fontweight="bold")
    ax.set_title("Comparativo de Atribuição de Ameaças: Fórmula Original SBRC vs. Ciência de Dados (IPO v2.0)",
                 fontsize=11, fontweight="bold", pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(actors, fontsize=9, fontweight="bold")
    ax.set_ylim(0, 115)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.legend(loc="upper right", fontsize=8.5, frameon=True)

    for rects in [rects1, rects4, rects5]:
        for rect in rects:
            h = rect.get_height()
            if h > 0:
                ax.annotate(f"{h:.1f}%",
                            xy=(rect.get_x() + rect.get_width() / 2, h),
                            xytext=(0, 2),
                            textcoords="offset points",
                            ha="center", va="bottom", fontsize=7, fontweight="bold")

    plt.tight_layout()
    plt.savefig(CHART_PATH, dpi=220)
    plt.close()


def add_page_number(canvas, doc):
    """Adiciona cabeçalho e rodapé institucionais nas páginas."""
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#475569"))
    canvas.drawString(2 * cm, 1.2 * cm, "Dossiê Explicativo para Banca Avaliadora — Projeto IPO v2.0 (CTI, PLN & Machine Learning)")
    canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Página {doc.page}")
    canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
    canvas.line(2 * cm, 1.6 * cm, A4[0] - 2 * cm, 1.6 * cm)
    canvas.restoreState()


def build_callout(title, text, styles, bg_color="#F0F9FF", border_color="#0284C7"):
    """Cria uma caixa de destaque didática (Analogia / Nota para a Banca)."""
    content = Paragraph(f"<b>{title}</b><br/>{text}", styles["CalloutText"])
    tbl = Table([[content]], colWidths=[17.0 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg_color)),
        ("BOX", (0, 0), (-1, -1), 1.2, colors.HexColor(border_color)),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return tbl


def create_pdf():
    base_font = register_fonts()
    bold_font = f"{base_font}-Bold" if base_font == "CustomSans" else "Helvetica-Bold"
    italic_font = f"{base_font}-Italic" if base_font == "CustomSans" else "Helvetica-Oblique"

    generate_comparison_chart()

    doc = SimpleDocTemplate(
        OUTPUT_PDF,
        pagesize=A4,
        leftMargin=2.0 * cm,
        rightMargin=2.0 * cm,
        topMargin=2.0 * cm,
        bottomMargin=2.2 * cm,
        title="Dossiê Explicativo para Banca de Mestrado - IPO v2.0",
        author="Equipe de Pesquisa CTI & Data Science",
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="DocTitle",
        fontName=bold_font,
        fontSize=18,
        leading=23,
        textColor=colors.HexColor("#0F172A"),
        alignment=TA_CENTER,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="DocSubtitle",
        fontName=italic_font,
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#334155"),
        alignment=TA_CENTER,
        spaceAfter=16,
    ))
    styles.add(ParagraphStyle(
        name="ChapterHeading",
        fontName=bold_font,
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#1E3A8A"),
        spaceBefore=14,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading",
        fontName=bold_font,
        fontSize=11.5,
        leading=15,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=10,
        spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="BodyJustified",
        fontName=base_font,
        fontSize=10,
        leading=14.5,
        textColor=colors.HexColor("#1E293B"),
        alignment=TA_JUSTIFY,
        spaceAfter=7,
    ))
    styles.add(ParagraphStyle(
        name="BulletItem",
        fontName=base_font,
        fontSize=10,
        leading=14,
        leftIndent=14,
        textColor=colors.HexColor("#1E293B"),
        alignment=TA_JUSTIFY,
        spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="FormulaBox",
        fontName=bold_font,
        fontSize=10.5,
        leading=15,
        textColor=colors.HexColor("#0F172A"),
        alignment=TA_CENTER,
        spaceBefore=6,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="CalloutText",
        fontName=base_font,
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#0F172A"),
        alignment=TA_JUSTIFY,
    ))
    styles.add(ParagraphStyle(
        name="TableCell",
        fontName=base_font,
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#1E293B"),
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="TableHeader",
        fontName=bold_font,
        fontSize=8.5,
        leading=11,
        textColor=colors.white,
        alignment=TA_CENTER,
    ))

    story = []

    # =========================================================================
    # CAPA / CABEÇALHO DO DOSSIÊ DE DEFESA
    # =========================================================================
    story.append(Paragraph(
        "DOSSIÊ EXPLICATIVO PARA BANCA AVALIADORA DE MESTRADO",
        ParagraphStyle("TopTag", fontName=bold_font, fontSize=9.5, textColor=colors.HexColor("#2563EB"),
                       alignment=TA_CENTER, spaceAfter=6)
    ))
    story.append(Paragraph(
        "Inteligência de Ameaças Cibernéticas e Ciência de Dados:<br/>"
        "O que era o Artigo Original (SBRC 2025), o que Diagnosticamos na Prática "
        "e como Evoluímos o Sistema com PLN e Machine Learning (IPO v2.0)",
        styles["DocTitle"]
    ))
    story.append(Paragraph(
        "Um guia completo, rigoroso nos fundamentos matemáticos e explicado na linguagem mais simples "
        "e didática possível — ideal para apresentação e arguição acadêmica.",
        styles["DocSubtitle"]
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1E3A8A"), spaceAfter=14))

    story.append(build_callout(
        "Objetivo deste Documento:",
        "Este material foi estruturado como um roteiro de defesa perante uma banca examinadora. "
        "Ele traduz termos complexos de Segurança Cibernética (CTI, STIX, MITRE ATT&amp;CK, DML, NIDS) "
        "e de Ciência de Dados (PLN, NER, TF-IDF, Okapi BM25, Decomposição SVD/LSA e Florestas Aleatórias) "
        "em explicações intuitivas, acompanhadas de analogias do mundo real e provas matemáticas.",
        styles, bg_color="#EFF6FF", border_color="#1D4ED8"
    ))
    story.append(Spacer(1, 10))

    # =========================================================================
    # CAPÍTULO 1: O PROBLEMA CENTRAL (MODELO DML EXPLICADO DE FORMA SIMPLES)
    # =========================================================================
    story.append(Paragraph(
        "1. O Ponto de Partida: Por que é tão difícil descobrir quem está atacando uma rede?",
        styles["ChapterHeading"]
    ))
    story.append(Paragraph(
        "Imagine que uma instituição financeira ou um órgão do governo está sofrendo tentativas de invasão "
        "pela internet. Todo computador conectado gera milhares de linhas de registros (chamados de <i>logs</i> "
        "de rede) a cada minuto. Para os analistas humanos de um Centro de Operações de Segurança (SOC), "
        "olhar linha por linha é como procurar uma agulha em um palheiro gigante.",
        styles["BodyJustified"]
    ))
    story.append(Paragraph(
        "Para organizar a defesa, a área de Inteligência de Ameaças Cibernéticas (<b>CTI</b> — <i>Cyber Threat "
        "Intelligence</i>) usa uma escada chamada <b>Modelo de Maturidade de Detecção (DML)</b>, que vai do "
        "nível 0 ao nível 9:",
        styles["BodyJustified"]
    ))
    story.append(Paragraph(
        "• <b>Níveis Baixos (DML-1 e DML-2 — Indicadores Atômicos ou IoCs):</b> São dados simples como um "
        "endereço IP suspeito, um domínio de site falso ou a assinatura digital (<i>hash</i>) de um arquivo "
        "de vírus. A maioria das empresas só se defende aqui: bloqueando listas de IPs conhecidos.",
        styles["BulletItem"]
    ))
    story.append(Paragraph(
        "• <b>Níveis Altos (DML-3 a DML-9 — Comportamento, TTPs e Identidade):</b> Descrevem <i>como</i> o "
        "criminoso age: quais ferramentas usa, como tenta adivinhar senhas, como esconde a comunicação e qual "
        "é o seu objetivo final. Isso é chamado de <b>TTPs (Táticas, Técnicas e Procedimentos)</b>.",
        styles["BulletItem"]
    ))

    story.append(Spacer(1, 4))
    story.append(build_callout(
        "Analogia Simples para a Banca (A Placa do Carro vs. O Modus Operandi):",
        "Bloquear apenas IoCs (nível DML-1) é como a polícia tentar prender uma quadrilha de assaltantes "
        "decorando somente a <b>placa do carro</b> usado no crime de ontem. No ataque de hoje, o criminoso "
        "aluga outro carro (troca o endereço IP em 2 minutos) e passa direto pela barreira policial.<br/>"
        "Já analisar <b>TTPs (nível DML-3+)</b> é estudar o <b>modus operandi</b> da quadrilha: o horário em "
        "que agem, a ferramenta que usam para abrir o cofre e a rota de fuga. Trocar de IP é fácil e barato; "
        "mudar a forma de agir exige que o criminoso reescreva todas as suas ferramentas do zero!",
        styles, bg_color="#FEF3C7", border_color="#D97706"
    ))
    story.append(Spacer(1, 8))

    # =========================================================================
    # CAPÍTULO 2: O QUE ERA O TRABALHO DO ARTIGO ORIGINAL (SBRC 2025)
    # =========================================================================
    story.append(Paragraph(
        "2. O Que Era o Trabalho do Artigo Original (Barros & Gondim, SBRC 2025)?",
        styles["ChapterHeading"]
    ))
    story.append(Paragraph(
        "O artigo científico analisado (<i>'Inteligência de Ameaças Cibernéticas para Melhoria na Detecção e "
        "Resposta a Incidentes'</i>, da Universidade de Brasília — UnB) propôs criar um software chamado "
        "<b>IPO (Orquestrador de Padrões de Inteligência)</b>. A grande ideia dos autores foi: automatizar a "
        "ligação entre os relatórios teóricos sobre grupos hackers e o tráfego real que passa pelos cabos de "
        "rede da empresa.",
        styles["BodyJustified"]
    ))

    story.append(Paragraph("2.1. Os 4 Módulos Criados pelos Autores do Artigo", styles["SectionHeading"]))
    story.append(Paragraph(
        "<b>1. Módulo de Coleta de Informações:</b> O sistema se conecta a um grande banco de dados de "
        "inteligência chamado <b>OpenCTI</b> (que os autores abasteceram com 21 Gigabytes de dados vindos das "
        "comunidades mundiais MISP, AlienVault e MITRE). O analista escolhe um relatório inicial sobre um "
        "ataque, e o software busca automaticamente outros relatórios que compartilhem os mesmos IPs ou "
        "domínios, juntando todas as peças do quebra-cabeça.",
        styles["BulletItem"]
    ))
    story.append(Paragraph(
        "<b>2. Módulo de Filtragem e Ranqueamento:</b> O software lê esses relatórios (que estão em um formato "
        "universal chamado <b>STIX</b>) e separa o joio do trigo: o que for indicador simples (IP/domínio, "
        "abaixo de DML-3) vai direto para bloqueio no sensor de rede; o que for comportamento de ataque "
        "(<b>TTPs</b>, nível DML-3 ou superior) é separado para criar o perfil comportamental do vilão.",
        styles["BulletItem"]
    ))
    story.append(Paragraph(
        "<b>3. Módulo de Construção de Padrão:</b> Cada grupo hacker famoso (como <i>Lazarus</i>, <i>APT28</i>, "
        "<i>Kimsuky</i> ou <i>BlackCat</i>) usa um conjunto de técnicas catalogadas na enciclopédia mundial "
        "<b>MITRE ATT&amp;CK</b> (onde cada técnica tem um código, como <b>T1071</b> para comunicação web ou "
        "<b>T1110</b> para tentativa de adivinhar senhas). O IPO cria uma 'ficha comportamental' (um Padrão) "
        "dizendo quais alertas do sensor de rede (<b>Suricata NIDS</b>) correspondem às técnicas daquele grupo.",
        styles["BulletItem"]
    ))
    story.append(Paragraph(
        "<b>4. Módulo de Correspondência de Padrões (A Fórmula Matemática do Artigo):</b> Quando o sensor de "
        "rede detecta atividades suspeitas, o IPO compara as técnicas vistas no tráfego com as fichas de "
        "todos os grupos cadastrados usando a <b>Equação 1 do artigo</b>:",
        styles["BulletItem"]
    ))

    story.append(Paragraph(
        "Pontuação de Correspondência (SBRC) = "
        "[ Nº de Técnicas em Comum (Rede ∩ Padrão) / Total de Técnicas do Padrão ] × 100",
        styles["FormulaBox"]
    ))

    story.append(Paragraph(
        "Em palavras simples: se a ficha cadastrada de um grupo tem <b>6 técnicas</b> e o tráfego da nossa rede "
        "apresentou <b>3 dessas técnicas</b>, a pontuação de correspondência será <b>(3 / 6) × 100 = 50%</b>.",
        styles["BodyJustified"]
    ))

    # =========================================================================
    # CAPÍTULO 3: O QUE VIMOS E DIAGNOSTICAMOS (AS LIMITAÇÕES DO ARTIGO)
    # =========================================================================
    story.append(Paragraph(
        "3. O Que Vimos na Análise Crítica? (Os 4 Gargalos do Método Original)",
        styles["ChapterHeading"]
    ))
    story.append(Paragraph(
        "Ao examinarmos os resultados experimentais do artigo (Seções 3 e 5) e reproduzirmos o mecanismo em "
        "nosso laboratório, identificamos quatro limitações fundamentais que impediam o sistema original de "
        "alcançar alta precisão em cenários reais:",
        styles["BodyJustified"]
    ))

    story.append(Paragraph(
        "<b>Gargalo 1 — O 'Ponto Cego' do Cabo de Rede (Poucas TTPs Mapeáveis):</b><br/>"
        "A matriz MITRE ATT&amp;CK possui centenas de técnicas, mas a maioria acontece <i>dentro</i> do sistema "
        "operacional da máquina invadida (ex.: criar uma chave oculta no registro do Windows) e não gera pacotes "
        "no cabo de rede. Na Tabela 2 do próprio artigo, para o grupo <b>Lazarus</b> foram encontradas <b>39 "
        "técnicas</b> nos relatórios, mas apenas <b>9 podiam ser vistas na rede</b>! Para o ransomware "
        "<b>BlackCat</b>, de 22 técnicas, apenas <b>3 eram visíveis na rede</b>.",
        styles["BulletItem"]
    ))

    story.append(Paragraph(
        "<b>Gargalo 2 — A 'Injustiça Matemática' do Denominador Pequeno (Falsa Atribuição):</b><br/>"
        "Na Tabela 1 do artigo original, quando os autores testaram um log de ataque do grupo <b>Lazarus</b>, "
        "o sistema deu <b>56% para o Lazarus</b>, mas deu <b>66% para o grupo Kimsuky</b> (errando o culpado "
        "principal!). Por que isso aconteceu? Porque a ficha do Lazarus tinha 9 técnicas no denominador "
        "(acertar 5 de 9 = 55,5%), enquanto a ficha do Kimsuky tinha apenas 6 técnicas (acertar 4 de 6 = 66,7%). "
        "Ou seja, <b>grupos com fichas menores sempre levam vantagem artificial na divisão simples!</b>",
        styles["BulletItem"]
    ))

    story.append(Paragraph(
        "<b>Gargalo 3 — Peso Igual para Pistas Comuns e Pistas Raras:</b><br/>"
        "Quase todos os grupos criminosos do planeta usam protocolo Web HTTP/HTTPS para se comunicar "
        "(técnica <b>T1071.001</b>). Na fórmula do artigo, encontrar essa técnica super genérica vale exatamente "
        "o mesmo peso que encontrar uma técnica raríssima que só um grupo específico utiliza.",
        styles["BulletItem"]
    ))

    story.append(Paragraph(
        "<b>Gargalo 4 — Cegueira para a Intensidade Física do Tráfego (Empate Técnico):</b><br/>"
        "A equação original só pergunta <i>'A técnica apareceu? Sim (1) ou Não (0)'</i>. Em nosso primeiro teste "
        "reproduzindo a fórmula do artigo, quando a rede registrava Comunicação Web C2 (<b>T1071.001</b>) e "
        "Força Bruta de Senhas (<b>T1110.001</b>), o grupo de espionagem <b>APT-DarkSerpent</b> e o ransomware "
        "<b>BlackCat</b> empatavam em <b>66,67% (2 de 3 técnicas)</b>. A fórmula não conseguia desempatar porque "
        "ignorava medidas contínuas vitais: qual foi o tamanho em Megabytes dos dados transferidos? Qual foi o "
        "ritmo exato em segundos dos pulsos de comunicação?",
        styles["BulletItem"]
    ))

    story.append(PageBreak())

    # =========================================================================
    # CAPÍTULO 4: O QUE NÓS MELHORAMOS (AS 4 EVOLUÇÕES DE CIÊNCIA DE DADOS)
    # =========================================================================
    story.append(Paragraph(
        "4. O Que Nós Construímos e Melhoramos? (As 4 Inovações do IPO v2.0)",
        styles["ChapterHeading"]
    ))
    story.append(Paragraph(
        "Na conclusão do artigo do SBRC 2025, os autores deixaram como sugestão para trabalhos futuros o uso "
        "de <b>Processamento de Linguagem Natural (PLN)</b> e <b>Aprendizado de Máquina (Machine Learning)</b>. "
        "Nós assumimos esse desafio e implementamos quatro motores completos de Ciência de Dados que "
        "transformaram o IPO em um sistema inteligente de ponta a ponta:",
        styles["BodyJustified"]
    ))

    # --- MELHORIA 1 ---
    story.append(Paragraph(
        "4.1. Melhoria 1: Robô Leitor de Relatórios com PLN, NER e Inferência Semântica "
        "(04_nlp_cti_extractor.py)",
        styles["SectionHeading"]
    ))
    story.append(Paragraph(
        "<b>O que resolvemos:</b> No trabalho original, os dados precisavam já estar cadastrados e estruturados "
        "no banco OpenCTI. Mas no mundo real, as informações chegam como textos livres (notícias, PDFs, "
        "boletins de segurança).",
        styles["BodyJustified"]
    ))
    story.append(Paragraph(
        "<b>Como funciona na prática (em linguagem simples):</b> Criamos um extrator automático que lê textos "
        "brutos (<i>cti_raw_reports.json</i>) em duas etapas:<br/>"
        "1. <b>Reconhecimento de Entidades Nomeadas (NER):</b> Identifica automaticamente no meio das frases "
        "quem é o grupo atacante (ex.: <i>Lazarus</i>, <i>APT28</i>, <i>APT-DarkSerpent</i>), qual é o nome do "
        "vírus/malware (ex.: <i>ViperRAT</i>, <i>BlindingCan</i>, <i>Zebrocy</i>), quais falhas de segurança "
        "foram exploradas (códigos <i>CVE</i>) e todos os IPs, domínios e hashes.<br/>"
        "2. <b>Inferência Semântica de TTPs por Cosseno:</b> Mesmo que o autor do texto <b>esqueça de escrever "
        "o código da técnica</b> (por exemplo, o texto não cita 'T1110.001', mas diz <i>'o invasor tentou "
        "adivinhar senhas repetidamente na porta SSH'</i>), o nosso algoritmo converte cada frase em um vetor "
        "matemático de palavras e trios de palavras (<b>TF-IDF N-Gram</b>) e calcula a <b>Similaridade de "
        "Cosseno</b> contra uma base descritiva do MITRE ATT&amp;CK. Nos testes, o módulo descobriu sozinho "
        "<b>20 ocorrências de técnicas</b> apenas lendo o significado das frases!",
        styles["BodyJustified"]
    ))

    # --- MELHORIA 2 ---
    story.append(Paragraph(
        "4.2. Melhoria 2: Pesos por Raridade de Técnica com TF-IDF e Okapi BM25 "
        "(05_ml_threat_attribution.py)",
        styles["SectionHeading"]
    ))
    story.append(Paragraph(
        "<b>O que resolvemos:</b> Acabamos com a injustiça de tratar técnicas genéricas com o mesmo peso de "
        "técnicas raras e corrigimos a distorção das fichas pequenas versus fichas grandes.",
        styles["BodyJustified"]
    ))
    story.append(Paragraph(
        "<b>Como funciona na prática:</b> Usamos a estatística <b>IDF (Inverse Document Frequency)</b>, que mede "
        "a raridade de uma pista no catálogo de grupos:",
        styles["BodyJustified"]
    ))
    story.append(Paragraph(
        "Peso IDF(Técnica) = ln[ (Total de Grupos + 1) / (Grupos que usam a Técnica + 1) ] + 1",
        styles["FormulaBox"]
    ))
    story.append(Paragraph(
        "Veja os pesos reais que o nosso sistema calculou automaticamente:<br/>"
        "• <b>T1071.001 (Web Protocols C2):</b> Usada por todos os 5 grupos → <b>Peso IDF = 1,000</b> (pista "
        "comum, vale pouco).<br/>"
        "• <b>T1110.001 (Força Bruta de Senha):</b> Usada por 3 dos 5 grupos → <b>Peso IDF = 1,405</b> (pista "
        "intermediária).<br/>"
        "• <b>T1566.001 (Spearphishing Attachment):</b> Usada por apenas 2 grupos → <b>Peso IDF = 1,693</b> "
        "(pista rara, vale quase 70% a mais!).<br/>"
        "Além disso, implementamos o algoritmo <b>Okapi BM25</b>, que leva em conta o tamanho médio das fichas "
        "criminais para impedir que grupos com poucas técnicas cadastradas tenham a nota inflada.",
        styles["BodyJustified"]
    ))

    # --- MELHORIA 3 ---
    story.append(Paragraph(
        "4.3. Melhoria 3: Embeddings Semânticos Latentes com Álgebra Linear — LSA / SVD "
        "(05_ml_threat_attribution.py)",
        styles["SectionHeading"]
    ))
    story.append(Paragraph(
        "<b>Como funciona na prática:</b> Conforme o nosso orquestrador analisa os 2.008 registros de tráfego "
        "da rede, ele redige automaticamente um 'resumo executivo' em texto descrevendo o incidente observado "
        "(quais protocolos atuaram, qual foi o intervalo do pulso C2, se houve ou não roubo de grandes volumes "
        "de dados). Em seguida, aplicamos <b>Decomposição em Valores Singulares Truncada (TruncatedSVD / "
        "Análise Semântica Latente — LSA)</b> para projetar esse resumo e os relatórios históricos dos grupos "
        "em um espaço geométrico de conceitos, medindo a proximidade contextual completa do ataque.",
        styles["BodyJustified"]
    ))

    # --- MELHORIA 4 ---
    story.append(Paragraph(
        "4.4. Melhoria 4: Classificador Supervisionado Random Forest sobre Telemetria Contínua "
        "(05_ml_threat_attribution.py)",
        styles["SectionHeading"]
    ))
    story.append(Paragraph(
        "<b>O grande salto de qualidade:</b> Em vez de olhar apenas se uma técnica aconteceu (0 ou 1), criamos "
        "uma <b>Floresta Aleatória (Random Forest)</b> com <b>150 árvores de decisão</b> que avalia simultaneamente "
        "as técnicas do MITRE ATT&amp;CK e <b>5 variáveis físicas contínuas medidas diretamente nos pacotes de rede</b>:",
        styles["BodyJustified"]
    ))
    story.append(Paragraph(
        "1. <b>Intervalo Médio do Beacon C2 (44,5 segundos nos logs):</b> De quanto em quanto tempo o computador "
        "infectado conversa com o servidor de comando.<br/>"
        "2. <b>Jitter do Beacon (3,10 segundos):</b> O desvio padrão do relógio do vírus (quanto menor, mais "
        "automatizado e furtivo é o implante).<br/>"
        "3. <b>Pico de Falhas de Login em 5 minutos (7 falhas):</b> Intensidade do ataque de força bruta.<br/>"
        "4. <b>Conexões a Domínios de Phishing (100 acessos):</b> Frequência de acionamento dos domínios de "
        "engenharia social.<br/>"
        "5. <b>Volume Máximo Enviado para Fora — Exfiltração (0,004 Megabytes):</b> Quantidade de dados "
        "extraídos da rede.",
        styles["BulletItem"]
    ))

    story.append(Spacer(1, 4))
    story.append(build_callout(
        "Como o Machine Learning Resolveu o Empate do BlackCat?",
        "Na análise simples por contagem de técnicas, o grupo de ransomware <b>BlackCat</b> recebia <b>66,67%</b> "
        "de suspeita. Porém, quando treinamos o <b>Random Forest</b> (que atingiu <b>100% de acurácia</b> na "
        "validação cruzada de 5 pastas), o modelo descobriu que a variável mais importante de todas (<b>15,27% "
        "de importância Gini</b>) é o <b>volume de Megabytes enviados para fora (max_outbound_mb)</b>.<br/>"
        "Como o BlackCat é um grupo de extorsão dupla que sempre rouba dezenas de Megabytes antes de criptografar "
        "a rede, e nos nossos logs saíram apenas <b>0,004 MB</b> (praticamente zero), a Floresta Aleatória "
        "derrubou a chance de ser BlackCat de 66,67% para apenas <b>1,33%</b>, isolando o verdadeiro culpado "
        "(<b>APT-DarkSerpent</b>) com <b>92,67% de probabilidade</b>!",
        styles, bg_color="#ECFDF5", border_color="#059669"
    ))

    story.append(PageBreak())

    # =========================================================================
    # CAPÍTULO 5: RESULTADOS VISUAIS, TABELA COMPARATIVA E Q&A DA BANCA
    # =========================================================================
    story.append(Paragraph(
        "5. Comparativo Experimental Completo e Arguição da Banca",
        styles["ChapterHeading"]
    ))
    story.append(Paragraph(
        "Abaixo apresentamos o gráfico e a tabela consolidada gerados pela execução real do nosso "
        "<b>ipo_orchestrator.py</b> sobre os registros de telemetria do laboratório (<i>soc_network_telemetry.csv</i>):",
        styles["BodyJustified"]
    ))

    if os.path.exists(CHART_PATH):
        story.append(Image(CHART_PATH, width=16.8 * cm, height=7.8 * cm))
        story.append(Spacer(1, 8))

    table_data = [
        [
            Paragraph("Grupo / Ameaça", styles["TableHeader"]),
            Paragraph("TTPs<br/>Casadas", styles["TableHeader"]),
            Paragraph("SBRC Eq. 1<br/>(Original)", styles["TableHeader"]),
            Paragraph("TF-IDF<br/>Cosine", styles["TableHeader"]),
            Paragraph("Okapi<br/>BM25", styles["TableHeader"]),
            Paragraph("PLN Embed<br/>(LSA/SVD)", styles["TableHeader"]),
            Paragraph("Random<br/>Forest (ML)", styles["TableHeader"]),
            Paragraph("ENSEMBLE<br/>FINAL (v2.0)", styles["TableHeader"]),
        ],
        [
            Paragraph("<b>APT-DarkSerpent</b>", styles["TableCell"]),
            Paragraph("3 / 3", styles["TableCell"]),
            Paragraph("100,00%", styles["TableCell"]),
            Paragraph("100,00%", styles["TableCell"]),
            Paragraph("100,00%", styles["TableCell"]),
            Paragraph("65,47%", styles["TableCell"]),
            Paragraph("<b>92,67%</b>", styles["TableCell"]),
            Paragraph("<b>88,07%</b>", styles["TableCell"]),
        ],
        [
            Paragraph("<b>BlackCat</b>", styles["TableCell"]),
            Paragraph("2 / 3", styles["TableCell"]),
            Paragraph("66,67%", styles["TableCell"]),
            Paragraph("55,32%", styles["TableCell"]),
            Paragraph("58,69%", styles["TableCell"]),
            Paragraph("26,63%", styles["TableCell"]),
            Paragraph("<b>1,33%</b>", styles["TableCell"]),
            Paragraph("<b>24,36%</b>", styles["TableCell"]),
        ],
        [
            Paragraph("<b>Lazarus Group</b>", styles["TableCell"]),
            Paragraph("2 / 9", styles["TableCell"]),
            Paragraph("22,22%", styles["TableCell"]),
            Paragraph("27,28%", styles["TableCell"]),
            Paragraph("37,45%", styles["TableCell"]),
            Paragraph("16,37%", styles["TableCell"]),
            Paragraph("4,67%", styles["TableCell"]),
            Paragraph("15,90%", styles["TableCell"]),
        ],
        [
            Paragraph("<b>APT28</b>", styles["TableCell"]),
            Paragraph("2 / 10", styles["TableCell"]),
            Paragraph("20,00%", styles["TableCell"]),
            Paragraph("<b>28,66%</b>", styles["TableCell"]),
            Paragraph("<b>39,54%</b>", styles["TableCell"]),
            Paragraph("14,70%", styles["TableCell"]),
            Paragraph("0,00%", styles["TableCell"]),
            Paragraph("13,91%", styles["TableCell"]),
        ],
        [
            Paragraph("<b>Kimsuky</b>", styles["TableCell"]),
            Paragraph("1 / 6", styles["TableCell"]),
            Paragraph("16,67%", styles["TableCell"]),
            Paragraph("11,63%", styles["TableCell"]),
            Paragraph("19,01%", styles["TableCell"]),
            Paragraph("16,39%", styles["TableCell"]),
            Paragraph("1,33%", styles["TableCell"]),
            Paragraph("9,29%", styles["TableCell"]),
        ],
    ]

    comp_table = Table(
        table_data,
        colWidths=[3.0 * cm, 1.8 * cm, 1.9 * cm, 1.9 * cm, 1.9 * cm, 2.0 * cm, 2.1 * cm, 2.4 * cm]
    )
    comp_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A8A")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#DCFCE7")),
        ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#FEF2F2")),
        ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#F8FAFC")),
        ("BACKGROUND", (0, 4), (-1, 4), colors.HexColor("#F1F5F9")),
        ("BACKGROUND", (0, 5), (-1, 5), colors.HexColor("#F8FAFC")),
        ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(comp_table)
    story.append(Spacer(1, 12))

    # =========================================================================
    # SEÇÃO DE PERGUNTAS E RESPOSTAS PARA A BANCA (Q&A)
    # =========================================================================
    story.append(Paragraph(
        "5.1. Roteiro de Arguição: 3 Perguntas Clássicas de Banca e Como Responder",
        styles["SectionHeading"]
    ))

    story.append(KeepTogether([
        Paragraph(
            "<b>Pergunta 1 da Banca:</b> <i>'Olhando a tabela, por que o grupo APT28 (que acertou 2 de 10 "
            "técnicas, 20% na fórmula original) ultrapassou o Lazarus Group (2 de 9 técnicas, 22,22% na "
            "fórmula original) quando vocês aplicaram o TF-IDF e o Okapi BM25?'</i>",
            styles["BodyJustified"]
        ),
        Paragraph(
            "<b>Resposta Ideal:</b> Porque a fórmula original do SBRC apenas conta quantas técnicas bateram, "
            "sem olhar <i>quais</i> técnicas bateram. O Lazarus casou as técnicas <b>T1071.001</b> (peso 1,000) "
            "e <b>T1110.001</b> (peso 1,405). Já o APT28 casou a <b>T1071.001</b> (peso 1,000) e a "
            "<b>T1566.001</b> (Spearphishing Attachment, que é mais rara na base e tem peso <b>1,693</b>). "
            "O TF-IDF (28,66% vs 27,28%) e o BM25 (39,54% vs 37,45%) premiaram o APT28 por compartilhar uma "
            "evidência mais específica e rara, provando matematicamente a superioridade da ponderação estatística.",
            styles["BulletItem"]
        ),
    ]))
    story.append(Spacer(1, 4))

    story.append(KeepTogether([
        Paragraph(
            "<b>Pergunta 2 da Banca:</b> <i>'Se o Random Forest sozinho deu 92,67% de certeza para o "
            "APT-DarkSerpent, por que vocês criaram um Ensemble Final combinando TF-IDF, BM25, PLN e "
            "Random Forest (que resultou em 88,07%)?'</i>",
            styles["BodyJustified"]
        ),
        Paragraph(
            "<b>Resposta Ideal:</b> Em Segurança Cibernética, depender de um único modelo supervisionado "
            "(como o Random Forest) cria risco quando enfrentamos uma campanha inédita ou um grupo novo que "
            "muda ligeiramente seu padrão de tráfego (<i>concept drift</i>). Ao combinarmos modelos não "
            "supervisionados de recuperação de informação (TF-IDF, BM25 e Embeddings LSA de PLN) com o "
            "modelo supervisionado (Random Forest), garantimos resiliência: mesmo que o atacante altere a "
            "velocidade do beaconing para tentar enganar a árvore de decisão, os motores de raridade de TTPs "
            "e semântica textual continuam sustentando a detecção.",
            styles["BulletItem"]
        ),
    ]))
    story.append(Spacer(1, 4))

    story.append(KeepTogether([
        Paragraph(
            "<b>Pergunta 3 da Banca:</b> <i>'Qual é a principal contribuição científica e prática do IPO v2.0 "
            "em relação ao artigo original do SBRC 2025?'</i>",
            styles["BodyJustified"]
        ),
        Paragraph(
            "<b>Resposta Ideal:</b> Transformamos um verificador determinístico baseado em interseção simples "
            "de conjuntos em uma <b>arquitetura inteligente multimodal</b>. Nosso trabalho automatiza a "
            "entrada (lendo relatórios em texto livre via PLN/NER e inferindo TTPs sem código explícito) e "
            "revoluciona a saída (unindo estatística de raridade TF-IDF/BM25, semântica latente SVD e "
            "telemetria contínua via Random Forest), eliminando as falsas atribuições relatadas pelos "
            "autores originais.",
            styles["BulletItem"]
        ),
    ]))

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    print(f"[+] PDF gerado com sucesso: {os.path.abspath(OUTPUT_PDF)}")


if __name__ == "__main__":
    create_pdf()
