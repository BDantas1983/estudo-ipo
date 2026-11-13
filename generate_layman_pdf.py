"""
Gera o PDF explicativo voltado para pessoas TOTALMENTE LEIGAS.
Explica tudo o que nosso estudo e sistema fazem usando metáforas do dia a dia
(detetives, polícia, impressões digitais, assalto a banco), sem termos difíceis
ou explicando cada termo técnico na hora com comparações simples.
"""

import os
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

OUTPUT_PDF = "Guia_Simples_Para_Leigos_Nosso_Estudo_IPO.pdf"


def register_fonts():
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


def add_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.drawString(2 * cm, 1.2 * cm, "Como Descobrir Quem é o Hacker? — Um Guia em Linguagem Simples para Qualquer Pessoa")
    canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Página {doc.page}")
    canvas.setStrokeColor(colors.HexColor("#E2E8F0"))
    canvas.line(2 * cm, 1.6 * cm, A4[0] - 2 * cm, 1.6 * cm)
    canvas.restoreState()


def build_box(title, text, styles, bg_color="#F8FAFC", border_color="#3B82F6"):
    content = Paragraph(f"<b>{title}</b><br/>{text}", styles["BoxText"])
    tbl = Table([[content]], colWidths=[17.0 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg_color)),
        ("BOX", (0, 0), (-1, -1), 1.2, colors.HexColor(border_color)),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    return tbl


def create_pdf():
    base_font = register_fonts()
    bold_font = f"{base_font}-Bold" if base_font == "CustomSans" else "Helvetica-Bold"
    italic_font = f"{base_font}-Italic" if base_font == "CustomSans" else "Helvetica-Oblique"

    doc = SimpleDocTemplate(
        OUTPUT_PDF,
        pagesize=A4,
        leftMargin=2.0 * cm,
        rightMargin=2.0 * cm,
        topMargin=2.0 * cm,
        bottomMargin=2.2 * cm,
        title="O Que Faz o Nosso Estudo? — Guia para Leigos",
        author="Equipe de Pesquisa CTI",
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="MainTitle",
        fontName=bold_font,
        fontSize=18,
        leading=23,
        textColor=colors.HexColor("#0F172A"),
        alignment=TA_CENTER,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="MainSubtitle",
        fontName=italic_font,
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#475569"),
        alignment=TA_CENTER,
        spaceAfter=14,
    ))
    styles.add(ParagraphStyle(
        name="TopicTitle",
        fontName=bold_font,
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1E3A8A"),
        spaceBefore=14,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="SubTopicTitle",
        fontName=bold_font,
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=10,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="SimpleBody",
        fontName=base_font,
        fontSize=10,
        leading=15,
        textColor=colors.HexColor("#1E293B"),
        alignment=TA_JUSTIFY,
        spaceAfter=7,
    ))
    styles.add(ParagraphStyle(
        name="SimpleBullet",
        fontName=base_font,
        fontSize=10,
        leading=14.5,
        leftIndent=14,
        textColor=colors.HexColor("#1E293B"),
        alignment=TA_JUSTIFY,
        spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="BoxText",
        fontName=base_font,
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#0F172A"),
        alignment=TA_JUSTIFY,
    ))
    styles.add(ParagraphStyle(
        name="TableHead",
        fontName=bold_font,
        fontSize=9,
        leading=12,
        textColor=colors.white,
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="TableCellText",
        fontName=base_font,
        fontSize=9,
        leading=12.5,
        textColor=colors.HexColor("#1E293B"),
        alignment=TA_CENTER,
    ))

    story = []

    # =========================================================================
    # CAPA / INTRODUÇÃO
    # =========================================================================
    story.append(Paragraph(
        "COMO DESCOBRIR QUEM É O HACKER?",
        ParagraphStyle("SuperTag", fontName=bold_font, fontSize=10, textColor=colors.HexColor("#2563EB"),
                       alignment=TA_CENTER, spaceAfter=4)
    ))
    story.append(Paragraph(
        "O que o Nosso Sistema Faz e por que Ele é Revolucionário:<br/>"
        "Uma Explicação em Linguagem Simples para Qualquer Pessoa",
        styles["MainTitle"]
    ))
    story.append(Paragraph(
        "Sem jargões complicados, sem termos difíceis. Entenda como usamos Inteligência Artificial "
        "e técnicas de detetive para descobrir quem está tentando invadir computadores.",
        styles["MainSubtitle"]
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1E3A8A"), spaceAfter=12))

    story.append(build_box(
        "Resumo em Uma Frase:",
        "Nosso sistema funciona como um <b>detetive digital superinteligente</b>: em vez de apenas avisar que "
        "alguém tentou forçar a porta da empresa, ele analisa as pistas deixadas, lê notícias do mundo todo "
        "sobre criminosos e diz com alta precisão: <i>'Com 88% de certeza, esse ataque foi feito pelo grupo hacker "
        "X, e o plano deles é fazer isso a seguir'</i>.",
        styles, bg_color="#EFF6FF", border_color="#3B82F6"
    ))
    story.append(Spacer(1, 10))

    # =========================================================================
    # PARTE 1: A HISTÓRIA DO DETETIVE (O PROBLEMA DO MUNDO REAL)
    # =========================================================================
    story.append(Paragraph("1. O Problema: Como a Maioria das Empresas se Defende Hoje?", styles["TopicTitle"]))
    story.append(Paragraph(
        "Pense na internet como uma cidade enorme. Todos os dias, empresas, bancos e hospitais sofrem milhares "
        "de tentativas de invasão feitas por criminosos profissionais espalhados pelo mundo. Para tentar se "
        "proteger, a maioria das empresas usa um método muito antigo e frágil: <b>as listas de bloqueio</b>.",
        styles["SimpleBody"]
    ))

    story.append(build_box(
        "A Metáfora da Placa do Carro (Por que o método antigo falha?):",
        "Imagine que a polícia descobre que um assalto a banco foi feito usando um carro branco com placa <b>ABC-1234</b>.<br/>"
        "O que a polícia comum faz? Ela anota essa placa e diz para todas as viaturas: <i>'Se virem a placa ABC-1234, prendam!'</i>.<br/>"
        "O que o criminoso faz no dia seguinte? Ele simplesmente <b>aluga outro carro com outra placa</b> por 50 reais e comete "
        "um novo assalto sem que ninguém o reconheça.<br/><br/>"
        "No mundo da internet é exatamente igual! As empresas ficam decorando o 'número do computador' do invasor "
        "(o famoso endereço IP). Mas o criminoso troca de IP em dois cliques! Ou seja, tentar se defender decorando "
        "apenas números é uma corrida perdida.",
        styles, bg_color="#FEF3C7", border_color="#D97706"
    ))
    story.append(Spacer(1, 8))

    story.append(Paragraph("2. A Nossa Solução: O Que o Detetive Inteligente Faz?", styles["TopicTitle"]))
    story.append(Paragraph(
        "Em vez de olhar só para a placa do carro (o IP), o nosso sistema estuda o <b>Modus Operandi</b> — ou seja, "
        "o jeito de agir do criminoso:",
        styles["SimpleBody"]
    ))
    story.append(Paragraph("• Qual ferramenta ele usa para arrombar a fechadura?", styles["SimpleBullet"]))
    story.append(Paragraph("• Ele prefere agir de madrugada ou no meio do expediente?", styles["SimpleBullet"]))
    story.append(Paragraph("• Ele rouba dinheiro ou está interessado em segredos e documentos confidenciais?", styles["SimpleBullet"]))
    story.append(Paragraph("• Como ele foge depois que entra na casa?", styles["SimpleBullet"]))
    story.append(Paragraph(
        "Trocar o número da placa (IP) é muito fácil. Mas <b>mudar o jeito de pensar, a rotina e as ferramentas que o "
        "criminoso passou anos desenvolvendo é quase impossível!</b> Quando olhamos para o comportamento, o invasor "
        "não consegue se esconder.",
        styles["SimpleBody"]
    ))

    # =========================================================================
    # PARTE 2: O ARTIGO DA UNB E O QUE DESCOBRIMOS
    # =========================================================================
    story.append(Paragraph("3. O Ponto de Partida: O Que os Pesquisadores da UnB Fizeram?", styles["TopicTitle"]))
    story.append(Paragraph(
        "Nós nos baseamos em uma pesquisa científica publicada por pesquisadores da Universidade de Brasília (UnB) "
        "em um dos maiores congressos de computação do Brasil (o SBRC 2025). Eles criaram um programa chamado <b>IPO</b> "
        "(Orquestrador de Padrões de Inteligência).",
        styles["SimpleBody"]
    ))
    story.append(Paragraph(
        "A ideia deles era fantástica: pegar as 'fichas criminais' dos grupos de hackers mais perigosos do planeta "
        "(grupos com nomes famosos como <i>Lazarus</i>, <i>APT28</i>, <i>BlackCat</i> e <i>Kimsuky</i>) e comparar com o que "
        "estava acontecendo na rede da empresa.",
        styles["SimpleBody"]
    ))
    story.append(Paragraph(
        "<b>Mas como eles calculavam quem era o culpado?</b><br/>"
        "Eles usavam uma continha muito simples de divisão: contavam quantas manobras suspeitas apareceram e dividiam "
        "pelo total de manobras que o grupo costuma fazer. Se batesse metade, davam 50% de suspeita.",
        styles["SimpleBody"]
    ))

    story.append(Paragraph("4. O Que Vimos na Prática? (Por que a conta simples dava errado?)", styles["TopicTitle"]))
    story.append(Paragraph(
        "Quando colocamos essa conta simples para rodar, descobrimos que ela cometia erros que nenhum bom detetive "
        "cometeria:",
        styles["SimpleBody"]
    ))

    story.append(Paragraph(
        "<b>1. O Erro do Falso Culpado:</b> Em um dos testes do artigo, o ataque foi feito pelo grupo <i>Lazarus</i>. "
        "Mas o sistema acusou o grupo <i>Kimsuky</i> com nota mais alta! Por quê? Porque o Kimsuky tinha uma ficha criminal "
        "mais curta. Dividir por um número menor faz a porcentagem parecer gigante, mesmo que a culpa não seja dele.",
        styles["SimpleBullet"]
    ))
    story.append(Paragraph(
        "<b>2. O Erro da Pista Comum:</b> Quase todos os vírus usam a internet comum (sites normais) para se comunicar. "
        "Na continha simples do artigo, ver um vírus usando a internet comum valia a mesma pontuação que achar uma impressão "
        "digital rara que só um grupo específico tem.",
        styles["SimpleBullet"]
    ))
    story.append(Paragraph(
        "<b>3. O Empate Sem Saída:</b> Se dois grupos diferentes costumam tentar adivinhar senhas, o sistema original dizia "
        "que os dois tinham 66% de chance de ser o culpado e travava aí, sem saber quem realmente era.",
        styles["SimpleBullet"]
    ))

    story.append(PageBreak())

    # =========================================================================
    # PARTE 3: O QUE NÓS MELHORAMOS COM CIÊNCIA DE DADOS
    # =========================================================================
    story.append(Paragraph("5. O Que Nós Fizemos de Diferente? (As 4 Grandes Melhorias)", styles["TopicTitle"]))
    story.append(Paragraph(
        "Nós pegamos essa ideia inicial e a transformamos usando <b>Ciência de Dados, Leitura de Textos por "
        "Computador (Processamento de Linguagem Natural) e Aprendizado de Máquina (Machine Learning)</b>. "
        "Criamos um sistema que pensa de verdade:",
        styles["SimpleBody"]
    ))

    story.append(Paragraph("A. Demos Peso Diferente para Pistas Raras e Pistas Comuns", styles["SubTopicTitle"]))
    story.append(Paragraph(
        "Se um detetive encontra uma bituca de cigarro comum no chão da cena do crime, isso não ajuda muito, porque "
        "milhões de pessoas fumam. Mas se ele encontra uma caneta de ouro feita sob encomenda com as iniciais do suspeito, "
        "aquela pista vale ouro!<br/>"
        "O nosso programa agora calcula matematicamente a <b>raridade de cada pista</b>: pistas banais ganham peso baixo (1,0) "
        "e pistas raras ganham peso muito maior (1,7). Isso acabou com as acusações injustas!",
        styles["SimpleBody"]
    ))

    story.append(Paragraph("B. Ensinamos o Computador a Ler Relatórios como um Humano", styles["SubTopicTitle"]))
    story.append(Paragraph(
        "Todos os dias saem notícias e relatórios policiais em inglês e português dizendo como os novos vírus agem. "
        "Criamos um robô leitor que lê esses textos, entende o significado das frases e descobre sozinho quais técnicas "
        "estão sendo usadas, mesmo que o texto não use os códigos técnicos formais!",
        styles["SimpleBody"]
    ))

    story.append(Paragraph("C. Colocamos uma Floresta de 150 'Cérebros Artificiais' (Machine Learning)", styles["SubTopicTitle"]))
    story.append(Paragraph(
        "Em vez de apenas perguntar <i>'houve ataque de senha? Sim ou Não'</i>, nosso sistema mede detalhes físicos do tráfego:<br/>"
        "• Qual foi a velocidade dos pulsos de comunicação?<br/>"
        "• O computador do vírus 'bate o ponto' a cada 45 segundos certinhos?<br/>"
        "• Quantos Megabytes de fotos ou documentos foram roubados?<br/>"
        "Treinamos um modelo de Inteligência Artificial chamado <b>Floresta Aleatória (Random Forest)</b>, que junta 150 "
        "pequenas inteligências votando juntas. Elas aprenderam que, por exemplo, grupos de sequestro de dados (ransomware) "
        "sempre roubam dezenas de Megabytes. Se o ataque que estamos vendo roubou quase zero, o computador sabe na hora que "
        "NÃO é aquele grupo!",
        styles["SimpleBody"]
    ))

    story.append(Paragraph("D. Combinamos Todas as Respostas (O 'Conselho de Detetives' / Ensemble)", styles["SubTopicTitle"]))
    story.append(Paragraph(
        "Nenhum detetive decide sozinho. O nosso sistema ouve a matemática da raridade, ouve a leitura dos relatórios "
        "e ouve a Inteligência Artificial. Juntando todas as opiniões em um <b>consenso seguro (Ensemble)</b>, ele dá o "
        "veredito final com altíssima confiança.",
        styles["SimpleBody"]
    ))

    # =========================================================================
    # PARTE 4: TESTES COM DADOS REAIS DO MUNDO E A TELA VISUAL
    # =========================================================================
    story.append(Paragraph("6. Como Provamos que Funciona no Mundo Real?", styles["TopicTitle"]))
    story.append(Paragraph(
        "Para ter certeza de que nosso estudo não era apenas teoria no papel, nós fizemos dois testes práticos pesados:",
        styles["SimpleBody"]
    ))

    story.append(Paragraph(
        "• <b>Teste 1: Mais de 2.000 Eventos de Rede:</b> O sistema analisou mais de 2.000 conexões de internet simuladas "
        "e conseguiu desempatar um ataque complexo, apontando com <b>88% de precisão</b> o grupo correto (APT-DarkSerpent), "
        "enquanto a fórmula antiga ficava confusa entre dois suspeitos totalmente diferentes.",
        styles["SimpleBullet"]
    ))
    story.append(Paragraph(
        "• <b>Teste 2: 738 Alertas Reais de um Sistema de Segurança Famoso (Wazuh):</b> Baixamos um banco de dados real "
        "usado por empresas do mundo todo. O nosso sistema filtrou quase 500 avisos inúteis de rotina (lixo operacional) "
        "e encontrou exatamente 202 ataques reais de tentativa de invasão, identificando o padrão de ataque na mesma hora!",
        styles["SimpleBullet"]
    ))

    story.append(Spacer(1, 4))
    story.append(build_box(
        "E Criamos um Painel Visual de Cinema (Dashboard):",
        "Para que qualquer pessoa (mesmo quem não entende nada de programação) consiga ver tudo acontecendo em tempo real, "
        "construímos um painel visual lindo que abre no navegador da internet, em tela cheia, com gráficos coloridos, "
        "letras grandes e fáceis de ler, e alertas claros mostrando exatamente o que está acontecendo na empresa agora.",
        styles, bg_color="#ECFDF5", border_color="#10B981"
    ))
    story.append(Spacer(1, 10))

    # =========================================================================
    # TABELA COMPARATIVA PARA LEIGOS
    # =========================================================================
    story.append(Paragraph("7. Resumo Rápido: O Jeito Antigo vs. O Nosso Jeito", styles["TopicTitle"]))

    comp_data = [
        [
            Paragraph("Situação / Pergunta", styles["TableHead"]),
            Paragraph("Como as Empresas Fazem Hoje", styles["TableHead"]),
            Paragraph("Como o Nosso Sistema Faz (IPO v2.0)", styles["TableHead"]),
        ],
        [
            Paragraph("<b>O que olham?</b>", styles["TableCellText"]),
            Paragraph("Apenas a placa do carro (IP/número).", styles["TableCellText"]),
            Paragraph("O comportamento completo e as ferramentas (TTPs).", styles["TableCellText"]),
        ],
        [
            Paragraph("<b>Se o criminoso trocar de IP?</b>", styles["TableCellText"]),
            Paragraph("Passa direto sem ninguém ver.", styles["TableCellText"]),
            Paragraph("É reconhecido imediatamente pelo jeito de agir.", styles["TableCellText"]),
        ],
        [
            Paragraph("<b>Leitura de notícias e relatórios?</b>", styles["TableCellText"]),
            Paragraph("Analistas humanos têm que ler tudo na mão.", styles["TableCellText"]),
            Paragraph("O robô de Inteligência Artificial lê e entende sozinho.", styles["TableCellText"]),
        ],
        [
            Paragraph("<b>Precisão da culpa?</b>", styles["TableCellText"]),
            Paragraph("Gera empates e acusa o grupo errado.", styles["TableCellText"]),
            Paragraph("Usa 150 cérebros de IA e desempatou com 88% de certeza.", styles["TableCellText"]),
        ],
        [
            Paragraph("<b>Facilidade de uso?</b>", styles["TableCellText"]),
            Paragraph("Telas pretas com códigos complicados.", styles["TableCellText"]),
            Paragraph("Painel visual moderno, colorido e em português.", styles["TableCellText"]),
        ],
    ]

    table_widget = Table(comp_data, colWidths=[4.2 * cm, 6.4 * cm, 6.4 * cm])
    table_widget.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A8A")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#F8FAFC")),
        ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#F1F5F9")),
        ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#F8FAFC")),
        ("BACKGROUND", (0, 4), (-1, 4), colors.HexColor("#F1F5F9")),
        ("BACKGROUND", (0, 5), (-1, 5), colors.HexColor("#F8FAFC")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(table_widget)
    story.append(Spacer(1, 12))

    story.append(build_box(
        "Conclusão:",
        "O nosso estudo pegou uma ideia muito promissora da Universidade de Brasília e a levou para o estado da arte. "
        "Mostramos que a união de Segurança da Informação com Inteligência Artificial moderna não serve apenas para "
        "escrever artigos difíceis, mas para proteger empresas, hospitais e governos de forma prática, rápida e compreensível.",
        styles, bg_color="#EFF6FF", border_color="#1E3A8A"
    ))

    doc.build(story, onFirstPage=add_footer, onLaterPages=add_footer)
    print(f"[+] PDF para leigos gerado: {os.path.abspath(OUTPUT_PDF)}")


if __name__ == "__main__":
    create_pdf()
