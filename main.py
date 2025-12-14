# Arquivo: anhanga/main.py
import typer
import sys
import os
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Setup de Path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# Imports dos Módulos
from modules.fincrime.pix_decoder import PixForensics
from modules.infra.hunter import InfraHunter, ShodanIntel
from modules.infra.analyzer import ContractAnalyzer
from modules.fincrime.validator import LaranjaHunter
from modules.graph.builder import GraphBrain
from core.database import CaseManager

# Inicialização ÚNICA
app = typer.Typer(help="Anhangá - Framework de Inteligência SWAT & FinCrime")
console = Console()

try:
    db = CaseManager()
except Exception as e:
    console.print(f"[bold red][!] Erro Crítico:[/bold red] Banco de dados não iniciado.")
    console.print(f"Erro: {e}")
    sys.exit(1)

@app.command()
def intro():
    """Exibe o banner e status do sistema."""
    banner = """
    [bold green]
                                                                          █
                                                                         █   
       ▄▄▄       ███▄    █  ██░ ██  ▄▄▄       ███▄    █   ▄████  ▄▄▄    █  
      ▒████▄     ██ ▀█   █ ▓██░ ██▒▒████▄     ██ ▀█   █  ██▒ ▀█▒▒████▄    
      ▒██  ▀█▄  ▓██  ▀█ ██▒▒██▀▀██░▒██  ▀█▄  ▓██  ▀█ ██▒▒██░▄▄▄░▒██  ▀█▄  
      ░██▄▄▄▄██ ▓██▒  ▐▌██▒░▓█ ░██ ░██▄▄▄▄██ ▓██▒  ▐▌██▒░▓█  ██▓░██▄▄▄▄██ 
       ▓█   ▓██▒▒██░   ▓██░░▓█▒░██▓ ▓█   ▓██▒▒██░   ▓██░░▒▓███▀▒ ▓█   ▓██▒
       ▒▒   ▓▒█░░ ▒░   ▒ ▒  ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒░   ▒ ▒  ░▒   ▒  ▒▒   ▓▒█░
    [/bold green]
    [bold yellow]   SWAT INTELLIGENCE FRAMEWORK v1.0[/bold yellow]
    """
    console.print(banner)
    console.print(Panel.fit("Módulos ativos: FinCrime, Infra, GraphCore.", title="Status do Sistema", border_style="green"))

@app.command()
def start():
    """Limpa a memória e inicia uma NOVA investigação."""
    db.nuke()
    console.print(Panel.fit("[bold green]Nova Investigação Iniciada![/bold green]\nO banco de dados 'investigation_current.json' foi resetado.", title="Sessão Limpa"))

@app.command()
def status():
    """Mostra o resumo do caso atual."""
    case = db.get_full_case()
    
    table = Table(title="Status da Investigação Atual")
    table.add_column("Categoria", style="cyan")
    table.add_column("Quantidade", style="magenta")
    
    table.add_row("Pessoas/Empresas (Laranjas)", str(len(case['entities'])))
    table.add_row("Infraestrutura (Sites/IPs)", str(len(case['infra'])))
    table.add_row("Conexões Mapeadas", str(len(case['relations'])))
    
    console.print(table)

@app.command()
def add_pix(
    pix: str = typer.Option(..., "--pix", "-p", help="Código Copia e Cola Pix")
):
    """1. Decodifica Pix e ADICIONA ao caso."""
    console.print("[blue][*] Processando Pix...[/blue]")
    decoder = PixForensics(pix)
    data = decoder.analyze()
    
    # Salva no Banco de Dados
    nome = data['merchant_name']
    cidade = data['merchant_city']
    chave = data['pix_key']
    
    # Tenta extrair documento da chave se for CPF/CNPJ
    doc = chave if len(chave) in [11, 14] and chave.isdigit() else "Desconhecido"
    
    db.add_entity(nome, doc, role="Laranja Pix")
    
    console.print(f"[green][+] Entidade Adicionada:[/green] {nome} ({doc})")

@app.command()
def add_url(
    url: str = typer.Option(..., "--url", "-u", help="URL do site alvo"),
    shodan_key: str = typer.Option(None, "--shodan-key", "-k", help="API Key do Shodan para enriquecimento automático")
):
    """2. Analisa URL, pega Favicon e (opcional) usa IA para varrer o Shodan."""
    console.print(f"[blue][*] Investigando Infra: {url}...[/blue]")
    
    # 1. Pega o Hash do Favicon
    hunter = InfraHunter(url)
    hash_val, link_visual = hunter.get_favicon_hash()
    
    extra_info = link_visual
    ai_analysis = "Nenhuma análise de IA realizada."
    
    if hash_val:
        console.print(f"[green][+] Hash Capturado:[/green] {hash_val}")
        
        # 2. SE tiver a chave, faz a mágica completa
        if shodan_key:
            with console.status("[bold purple]Consultando API Shodan + Análise Neural (Ollama)...[/bold purple]"):
                # Busca no Shodan
                shodan_tool = ShodanIntel(shodan_key)
                shodan_data = shodan_tool.search_by_hash(hash_val)
                
                if "erro" not in shodan_data:
                    # Manda pro Ollama analisar o JSON técnico do Shodan
                    analyst = ContractAnalyzer(url)
                    ai_analysis = analyst.analyze_shodan_data(str(shodan_data))
                    
                    # Formata para o banco de dados
                    extra_info = f"SHODAN DATA: {len(shodan_data)} IPs encontrados.\n\nANÁLISE IA:\n{ai_analysis}"
                else:
                    ai_analysis = f"Erro no Shodan: {shodan_data.get('erro')}"
                    extra_info = ai_analysis

        # Salva no Banco de Dados
        db.add_infra(url, ip=f"Hash: {hash_val}", extra_info=extra_info)
        
        # Mostra o resultado na tela
        if shodan_key:
            if "Erro" in ai_analysis:
                console.print(f"[red][!] {ai_analysis}[/red]")
            else:
                console.print(Panel(ai_analysis, title="🤖 Relatório de Infraestrutura (IA)", border_style="purple"))
        else:
            console.print(f"[yellow][!] Hash salvo. Para análise automática, use --shodan-key[/yellow]")
            
    else:
        db.add_infra(url, ip="Protegido/Falha")
        console.print(f"[red][!] Favicon não encontrado ou site inacessível.[/red]")

@app.command()
def enrich():
    """3. (Automático) Varre o banco e valida CNPJs na BrasilAPI."""
    case = db.get_full_case()
    validator = LaranjaHunter()
    
    console.print("[bold purple][*] Iniciando Enriquecimento em Massa...[/bold purple]")
    
    if not case['entities']:
        console.print("[yellow][!] Nenhuma entidade para enriquecer. Use 'add-pix' primeiro.[/yellow]")
        return

    for ent in case['entities']:
        doc = ent['document']
        # Se parece um CNPJ (14 dígitos), consulta na Receita
        if len(doc) == 14 and doc.isdigit():
            console.print(f"    -> Consultando BrasilAPI para: {doc}...")
            res = validator.consultar_cnpj(doc)
            if "erro" not in res:
                ent['info_extra'] = f"CNAE: {res['cnae_principal']} | Sócio: {res['socio_admin']}"
                # Atualiza risco
                if "ALTO" in res.get('risco', ''):
                    ent['role'] = "LARANJA CONFIRMADO"
    
    console.print("[green][V] Enriquecimento concluído.[/green]")

@app.command()
def graph():
    """4. Plota o Grafo FINAL usando os dados acumulados no Caso."""
    console.print("[bold blue][*] Gerando Visualização Tática do Caso...[/bold blue]")
    
    brain = GraphBrain()
    case = db.get_full_case()
    
    if not case['entities'] and not case['infra']:
        console.print("[red][!] O caso está vazio. Adicione Pix ou URLs antes de gerar o gráfico.[/red]")
        return

    # 1. Adiciona Pessoas do Banco de Dados
    for ent in case['entities']:
        brain.add_fincrime_data(ent['name'], ent['document'])
    
    # 2. Adiciona Infra do Banco de Dados
    for inf in case['infra']:
        brain.add_infra_data(inf['domain'], inf['ip'])
        
    # 3. Cria Conexões (Associação por Caso)
    for ent in case['entities']:
        for inf in case['infra']:
            brain.connect_entities(ent['name'], inf['domain'], relation_type="investigado_em")
    
    console.print("[bold green][V] Abrindo Janela Gráfica com Dados Reais...[/bold green]")
    brain.plot_investigation()

if __name__ == "__main__":
    app()