# Arquivo: anhanga.py
import typer
import sys
import os
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.markdown import Markdown

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from core.config import ConfigManager
from core.orchestrator import Orchestrator

app = typer.Typer(help="Anhangá - Cyber Defense Framework")
console = Console()
cfg = ConfigManager()

# Orchestrator handles engine, db, and reporter
orchestrator = Orchestrator()

@app.command()
def print_banner():
    banner = r"""
    [bold green]
                                  # #### ####
                                ### \/#|### |/####
                               ##\/#/ \||/##/_/##/_#
                             ###  \/###|/ \/ # ###
                           ##_\_#\_\## | #/###_/_####
                          ## #### # \ #| /  #### ##/##
                           __#_--###`  |{,###---###-~
                                     \ }{
                                      }}{
                                      }}{
                                      {{}
                                , -=-~{ .-^- _
                                      `}
                                       {
       ▄▄▄       ███▄    █  ██░ ██  ▄▄▄       ███▄    █   ▄████  ▄▄▄       █
      ▒████▄     ██ ▀█   █ ▓██░ ██▒▒████▄     ██ ▀█   █  ██▒ ▀█▒▒████▄    █
      ▒██  ▀█▄  ▓██  ▀█ ██▒▒██▀▀██░▒██  ▀█▄  ▓██  ▀█ ██▒▒██░▄▄▄░▒██  ▀█▄  
      ░██▄▄▄▄██ ▓██▒  ▐▌██▒░▓█ ░██ ░██▄▄▄▄██ ▓██▒  ▐▌██▒░▓█  ██▓░██▄▄▄▄██ 
       ▓█   ▓██▒▒██░   ▓██░░▓█▒░██▓ ▓█   ▓██▒▒██░   ▓██░░▒▓███▀▒ ▓█   ▓██▒
       ▒▒   ▓▒█░░ ▒░   ▒ ▒  ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒░   ▒ ▒  ░▒   ▒  ▒▒   ▓▒█░     
    [/bold green]
            [bold white]Financial Crime & Cyber Threat Intelligence[/bold white] [bold cyan]v2.1[/bold cyan]
   """
    console.print(banner)

@app.command()
def investigate():
    print_banner()
    
    if Confirm.ask("[bold yellow]1. Deseja iniciar uma NOVA operação?[/bold yellow]"):
        orchestrator.nuke_database()
        console.print("[green][*] Memória limpa.[/green]")
    
    # --- FASE 1: DEFINIÇÃO DE PIPELINES ---
    # Moved to Orchestrator

    # --- FASE 2: COLETA FINANCEIRA ---
    console.print("\n[bold cyan]--- RASTREIO FINANCEIRO ---[/bold cyan]")
    input_fin = Prompt.ask("Cole o [bold]Pix[/bold] ou [bold]Carteira Crypto[/bold] (ou Enter p/ pular)")
    
    if input_fin:
        fin_data = orchestrator.run_financial_pipeline(input_fin)
        if fin_data['type'] == 'crypto':
             for res in fin_data['results']:
                 console.print(Panel(res['content'], title=res['title'], border_style="yellow"))

    # --- FASE 3: INFRA & SCRAPING ---
    console.print("\n[bold cyan]--- INTELIGÊNCIA DE INFRA & SCRAPING ---[/bold cyan]")
    url = Prompt.ask("Digite a [bold]URL[/bold] do alvo (ex: tigrinho.io) ou Enter p/ pular")
    
    if url:
        results = orchestrator.run_infra_pipeline(url)
        
        for res in results:
            icon = "🔍" if "Scraping" in res['title'] else "🌐"
            console.print(f"[{res['confidence']}]{icon} {res['title']}: {res['content']}")

    console.print("\n[bold cyan]--- VALIDAÇÃO DE IDENTIDADE ---[/bold cyan]")
    email_alvo = Prompt.ask("Digite um [bold]E-mail[/bold] suspeito (ex: achado no Whois/Scraping) ou Enter p/ pular")
        
    if email_alvo:
            results = orchestrator.run_identity_pipeline(email_alvo)
            
            for res in results:
                icon = "👤"
                if res['title'] == "Gravatar Encontrado": icon = "📸"
                if res['title'] == "Spotify": icon = "🎵"
                
                console.print(Panel(f"{icon} {res['content']}", title=res['title'], border_style="blue"))
                
    # --- FASE 5: RELATÓRIO ---
    console.print("\n[bold cyan]--- ANÁLISE COGNITIVA (OLLAMA) ---[/bold cyan]")
    if Confirm.ask("Gerar relatório com IA?"):
        with console.status("[bold purple]Escrevendo dossiê...[/bold purple]"):
            filename = orchestrator.generate_report()
        console.print(f"[bold green]Arquivo salvo: {filename}[/bold green]")

@app.command()
def config(vt: str = typer.Option(None, "--set-vt")):
    """Configura chaves de API (Opcional)."""
    if vt: 
        cfg.set_key("virustotal", vt)
        console.print("[green]Chave VT Salva![/green]")

if __name__ == "__main__":
    app()
