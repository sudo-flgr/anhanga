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
from core.engine import InvestigationEngine
from core.config import ConfigManager
from core.database import CaseManager
from modules.reporter.writer import AIReporter 

app = typer.Typer(help="Anhangá - Cyber Defense Framework")
console = Console()
db = CaseManager()
cfg = ConfigManager()

engine = InvestigationEngine()

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
        db.nuke()
        console.print("[green][*] Memória limpa.[/green]")
    
    # --- FASE 1: DEFINIÇÃO DE PIPELINES ---
    pipeline_pix = ['fincrime.pix_decoder']
    pipeline_crypto = ['crypto.hunter']
    pipeline_infra = ['infra.hunter'] # Agora chama o novo v2.0!

    # --- FASE 2: COLETA FINANCEIRA ---
    console.print("\n[bold cyan]--- RASTREIO FINANCEIRO ---[/bold cyan]")
    input_fin = Prompt.ask("Cole o [bold]Pix[/bold] ou [bold]Carteira Crypto[/bold] (ou Enter p/ pular)")
    
    if input_fin:
        if "br.gov.bcb.pix" in input_fin:
             results = engine.run_pipeline(input_fin, pipeline_pix)
             for res in results:
                 if res['title'] == 'Nome Recebedor':
                     db.add_entity(res['content'], "Pix Detectado", role="Recebedor")
        else:
             results = engine.run_pipeline(input_fin, pipeline_crypto)
             for res in results:
                 console.print(Panel(res['content'], title=res['title'], border_style="yellow"))

    # --- FASE 3: INFRA & SCRAPING ---
    console.print("\n[bold cyan]--- INTELIGÊNCIA DE INFRA & SCRAPING ---[/bold cyan]")
    url = Prompt.ask("Digite a [bold]URL[/bold] do alvo (ex: tigrinho.io) ou Enter p/ pular")
    
    if url:
        results = engine.run_pipeline(url, pipeline_infra)
        
        info_buffer = ""
        ip_alvo = "N/A"
        
        for res in results:
            icon = "🔍" if "Scraping" in res['title'] else "🌐"
            console.print(f"[{res['confidence']}]{icon} {res['title']}: {res['content']}")
            
            info_buffer += f"{res['title']}: {res['content']}\n"
            
            if res['title'] == "Endereço IP":
                ip_alvo = res['content']

        db.add_infra(url, ip=ip_alvo, extra_info=info_buffer)

    console.print("\n[bold cyan]--- VALIDAÇÃO DE IDENTIDADE ---[/bold cyan]")
    email_alvo = Prompt.ask("Digite um [bold]E-mail[/bold] suspeito (ex: achado no Whois/Scraping) ou Enter p/ pular")
        
    if email_alvo:
            pipeline_identity = ['identity.checker']
            results = engine.run_pipeline(email_alvo, pipeline_identity)
            
            for res in results:
                icon = "👤"
                if res['title'] == "Gravatar Encontrado": icon = "📸"
                if res['title'] == "Spotify": icon = "🎵"
                
                console.print(Panel(f"{icon} {res['content']}", title=res['title'], border_style="blue"))
                
                db.add_entity(res['content'], "Identidade Digital", role=f"Vínculo: {email_alvo}")
    if email_alvo:
            pipeline_identity = ['identity.checker', 'identity.leaks'] 
            results = engine.run_pipeline(email_alvo, pipeline_identity)

    # --- FASE 5: RELATÓRIO ---
    console.print("\n[bold cyan]--- ANÁLISE COGNITIVA (OLLAMA) ---[/bold cyan]")
    if Confirm.ask("Gerar relatório com IA?"):
        with console.status("[bold purple]Escrevendo dossiê...[/bold purple]"):
            reporter = AIReporter()
            case_data = db.get_full_case()
            dossie = reporter.generate_dossier(case_data)
            filename = reporter.save_report(dossie)
        console.print(f"[bold green]Arquivo salvo: {filename}[/bold green]")

@app.command()
def config(vt: str = typer.Option(None, "--set-vt")):
    """Configura chaves de API (Opcional)."""
    if vt: 
        cfg.set_key("virustotal", vt)
        console.print("[green]Chave VT Salva![/green]")

if __name__ == "__main__":
    app()