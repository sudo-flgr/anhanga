# Arquivo: anhanga.py
import typer
import sys
import os
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.markdown import Markdown

# Setup de Path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# --- IMPORTS v2.0 (ENGINE) ---
from core.engine import InvestigationEngine
from core.config import ConfigManager
from core.database import CaseManager

# --- IMPORTS LEGADOS (Ainda necessários até portarmos tudo) ---
# Note que REMOVEMOS o PixForensics daqui, pois ele já é v2.0
from modules.infra.hunter import InfraHunter, ShodanIntel, IPGeo, VirusTotalIntel, WhoisIntel
from modules.graph.builder import GraphBrain
from modules.reporter.writer import AIReporter 

app = typer.Typer(help="Anhangá - Cyber Defense Framework")
console = Console()
db = CaseManager()
cfg = ConfigManager()

# Inicializa a Engine v2.0 Global
engine = InvestigationEngine()

@app.command()
def print_banner():
    banner = """
    [bold green]
       ▄▄▄       ███▄    █  ██░ ██  ▄▄▄       ███▄    █   ▄████  ▄▄▄      
      ▒████▄     ██ ▀█   █ ▓██░ ██▒▒████▄     ██ ▀█   █  ██▒ ▀█▒▒████▄    
      ▒██  ▀█▄  ▓██  ▀█ ██▒▒██▀▀██░▒██  ▀█▄  ▓██  ▀█ ██▒▒██░▄▄▄░▒██  ▀█▄  
      ░██▄▄▄▄██ ▓██▒  ▐▌██▒░▓█ ░██ ░██▄▄▄▄██ ▓██▒  ▐▌██▒░▓█  ██▓░██▄▄▄▄██ 
       ▓█   ▓██▒▒██░   ▓██░░▓█▒░██▓ ▓█   ▓██▒▒██░   ▓██░░▒▓███▀▒ ▓█   ▓██▒
       ▒▒   ▓▒█░░ ▒░   ▒ ▒  ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒░   ▒ ▒  ░▒   ▒  ▒▒   ▓▒█░
    [/bold green]
    [bold yellow]   SWAT INTELLIGENCE FRAMEWORK v2.0[/bold yellow]
    """
    console.print(banner)

@app.command()
def investigate():
    """Modo Guiado v2.0: Pipeline Modular (Pix -> Infra -> Crypto)."""
    print_banner()
    
    if Confirm.ask("[bold yellow]1. Deseja iniciar uma NOVA operação?[/bold yellow]"):
        db.nuke()
        console.print("[green][*] Memória limpa.[/green]")
    
    # --- FASE 1: ARSENAL ---
    pipeline_pix = ['fincrime.pix_decoder']
    pipeline_crypto = ['crypto.hunter']

    # --- FASE 2: COLETA ---
    
    # A. Financeiro (Híbrido Pix/Crypto)
    console.print("\n[bold cyan]--- RASTREIO FINANCEIRO ---[/bold cyan]")
    input_fin = Prompt.ask("Cole o [bold]Pix[/bold] ou uma [bold]Carteira Crypto[/bold] (ou Enter p/ pular)")
    
    if input_fin:
        # Tenta detectar se é Pix ou Crypto
        if "br.gov.bcb.pix" in input_fin:
             results = engine.run_pipeline(input_fin, pipeline_pix)
             # Salva no banco legado para compatibilidade com o Grafo
             for res in results:
                 if res['title'] == 'Nome Recebedor':
                     db.add_entity(res['content'], "Pix Detectado", role="Recebedor")
        else:
             # Assume que é Crypto/Texto Geral
             results = engine.run_pipeline(input_fin, pipeline_crypto)
             # Exibe resultados Crypto
             for res in results:
                 console.print(Panel(res['content'], title=res['title'], border_style="yellow"))

    # B. Infraestrutura (Ainda Legado)
    console.print("\n[bold cyan]--- INTELIGÊNCIA DE INFRA ---[/bold cyan]")
    url = Prompt.ask("Digite a [bold]URL[/bold] do alvo (ex: tigrinho.io) ou Enter p/ pular")
    
    if url:
        with console.status("[bold blue]Rodando InfraHunter (Legado)...[/bold blue]"):
             hunter = InfraHunter(url)
             ip = hunter.resolve_ip()
             
             # Whois
             whois_tool = WhoisIntel()
             w_data = whois_tool.get_whois(hunter.domain)
             whois_txt = f"Registrar: {w_data.get('registrar')}\nData: {w_data.get('creation_date')}"

             # VT
             vt_intel = VirusTotalIntel(cfg.get_key("virustotal"))
             vt_res = "N/A"
             if ip and vt_intel.key:
                 vt_data = vt_intel.analyze_ip(ip)
                 if vt_data: vt_res = f"{vt_data.get('verdict')} - {vt_data.get('owner')}"

             report_tec = f"IP: {ip}\nWHOIS: {whois_txt}\nVT: {vt_res}"
             db.add_infra(url, ip=str(ip), extra_info=report_tec)
             console.print(Panel(report_tec, title="Infraestrutura Mapeada", border_style="green"))

    # --- FASE 3: RELATÓRIO ---
    console.print("\n[bold cyan]--- ANÁLISE COGNITIVA (OLLAMA) ---[/bold cyan]")
    if Confirm.ask("Gerar relatório com IA?"):
        with console.status("[bold purple]Escrevendo dossiê...[/bold purple]"):
            reporter = AIReporter()
            case_data = db.get_full_case()
            dossie = reporter.generate_dossier(case_data)
            filename = reporter.save_report(dossie)
        console.print(f"[bold green]Arquivo salvo: {filename}[/bold green]")

@app.command()
def add_pix(pix: str = typer.Option(..., "--pix", "-p")):
    """Comando individual atualizado para usar a Engine v2.0."""
    # Pipeline de um passo só
    results = engine.run_pipeline(pix, ['fincrime.pix_decoder'])
    
    if not results:
        console.print("[red]Falha ao decodificar Pix.[/red]")
        return

    # Exibe bonito
    for res in results:
        console.print(f"[green]{res['title']}:[/green] {res['content']}")
        # Salva no banco para persistência
        if res['title'] == 'Nome Recebedor':
             db.add_entity(res['content'], "Pix Manual", role="Recebedor")

@app.command()
def config(shodan: str = typer.Option(None), vt: str = typer.Option(None)):
    if shodan: cfg.set_key("shodan", shodan)
    if vt: cfg.set_key("virustotal", vt)

@app.command()
def start(): 
    db.nuke()
    console.print("[green]Resetado.[/green]")

if __name__ == "__main__":
    app()