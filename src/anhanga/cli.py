import typer
import sys
import os
import time
import urllib3
import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.layout import Layout
from typing import Optional

# Disable SSL Warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Core Imports
from anhanga.core.engine import run_investigation
from anhanga.core.config import ConfigManager

# Module Imports (Try/Except for robustness)
try:
    from anhanga.modules.identity.checker import IdentityModule
except ImportError:
    IdentityModule = None

try:
    from anhanga.modules.fincrime.pix_decoder import PixIntelligence
except ImportError:
    PixIntelligence = None

try:
    from anhanga.modules.reporter.writer import AIReporter
except ImportError:
    AIReporter = None

app = typer.Typer(help="Anhangá - Framework de Defesa Cibernética e Inteligência Financeira")
console = Console()
cfg = ConfigManager()

def print_banner():
    # Helper for ASCII Banner
    banner = r"""
    [bold green]
       ___      _                            
      / _ \    | |                           
     / /_\ \ __| |_   _  __ _ _ __   ___ ___ 
     |  _  |/ _` | | | |/ _` | '_ \ / __/ _ \
     | | | | (_| | |_| | (_| | | | | (_|  __/
     \_| |_/\__,_|\__, |\__,_|_| |_|\___\___|
                   __/ |                     
                  |___/                      
    [/bold green]
            [bold white]Financial Crime & Cyber Threat Intelligence[/bold white] [bold cyan]v3.0[/bold cyan]
   """
    console.print(banner)

@app.command()
def version():
    """Exibe a versão e banner do sistema."""
    print_banner()

@app.command()
def config(
    vt: str = typer.Option(None, "--set-vt", help="Configurar chave API VirusTotal"),
    shodan: str = typer.Option(None, "--set-shodan", help="Configurar chave API Shodan")
):
    """Gerencia configurações e chaves de API."""
    if vt: 
        cfg.set_key("virustotal", vt)
        console.print("[green]Chave VT Salva![/green]")
    if shodan:
        cfg.set_key("shodan", shodan)
        console.print("[green]Chave Shodan Salva![/green]")
        
    if not vt and not shodan:
        console.print("[yellow]Use --set-vt ou --set-shodan para configurar.[/yellow]")

@app.command()
def scan(
    url: str, 
    report: bool = typer.Option(False, "--report", "-r", help="Gerar relatório de inteligência com IA")
):
    """
    Inicia uma investigação completa contra um alvo (URL).
    Executa InfraHunter, StealthScraper e Análise Financeira.
    Opcionalmente gera um relatório final com IA.
    """
    print_banner()
    
    if not url.startswith("http"):
        url = "https://" + url
        
    console.print(f"\n[bold white][Target] Alvo:[/bold white] [cyan]{url}[/cyan]\n")
    
    with console.status("[bold blue]Executando Anhangá Engine v3.0...[/bold blue]", spinner="dots"):
        try:
            state = run_investigation(url)
        except Exception as e:
            console.print(f"[bold red]Erro crítico na execução do motor:[/bold red] {e}")
            return

    # --- VISUALIZAÇÃO DOS RESULTADOS ---
    
    # 1. Painel de Infraestrutura
    protection = state.get("protection_type", "Desconhecido")
    status = state.get("status", "N/A")
    screenshot = state.get("screenshot_path", "Nenhum")
    
    infra_text = Text()
    infra_text.append(f"Proteção Detectada: {protection}\n", style="bold yellow" if protection != "None" else "green")
    infra_text.append(f"Status da Coleta: {status}\n", style="white")
    if screenshot:
        infra_text.append(f"Evidência Visual: {screenshot}", style="blue underline")
    else:
        infra_text.append("Evidência Visual: Nenhuma captura disponível", style="dim")
        
    console.print(Panel(infra_text, title="[Search] Infraestrutura & Acesso", border_style="cyan"))

    # 2. Painel de Compliance
    comp_res = state.get("compliance_result") or {}
    if comp_res.get("status"):
        comp_status = comp_res.get("status", "UNKNOWN")
        operator = comp_res.get("operator", "N/A")
        auth_type = comp_res.get("auth_type", "N/A")
        brand = comp_res.get("brand", "")
        
        comp_style = "green" if comp_status == "AUTHORIZED" else "red"
        
        comp_text = Text()
        comp_text.append(f"Status Legal: {comp_status.upper()}\n", style=f"bold {comp_style}")
        comp_text.append(f"Operador Autorizado: {operator}\n")
        comp_text.append(f"Tipo de Autorização: {auth_type}\n")
        if brand:
             comp_text.append(f"Marca Detectada: {brand}")
        
        console.print(Panel(comp_text, title="[Scale] Compliance & Regulação", border_style=comp_style))
    else:
        console.print(Panel("Sem dados de compliance disponíveis.", title="[Scale] Compliance", border_style="dim"))

    # 3. Painel de Inteligência Financeira
    fin_intel = state.get("financial_intel", {})
    if fin_intel:
        risk_score = fin_intel.get("risk_score", 0)
        flags = fin_intel.get("flags", [])
        pix_data = fin_intel.get("pix_data", [])
        crypto_data = fin_intel.get("crypto_data", [])
        
        if risk_score >= 50:
            alert_text = Text("[!] ALERTA DE LAVAGEM DE DINHEIRO DETECTADO\n", style="bold white on red", justify="center")
            alert_text.append("Indícios de inconsistência entre Operador e Beneficiário Financeiro (Laranja).", style="bold white")
            console.print(Panel(alert_text, border_style="red"))
        elif risk_score == 0 and (pix_data or crypto_data):
            console.print(Panel("[OK] Fluxo Financeiro Coerente", style="bold green", border_style="green"))

        if pix_data or crypto_data:
            table = Table(title="Rastreio Financeiro (Money Trail)")
            table.add_column("Tipo", style="cyan")
            table.add_column("Identificador / Chave", style="white")
            table.add_column("Detalhes (Beneficiário/Rede)", style="yellow")
            
            for pix in pix_data:
                ben = pix.get("beneficiary_name", "Desconhecido")
                city = pix.get("city", "")
                key = pix.get("pix_key") or "Chave Dinâmica"
                details = f"Beneficiário: {ben}"
                if city: details += f" ({city})"
                table.add_row("PIX", key, details)
                
            for crypto in crypto_data:
                table.add_row(f"Crypto [{crypto['coin']}]", crypto['address'], "Alta Confiança")
                
            console.print(table)
            
            if flags:
                console.print("\n[bold red]Alertas Específicos:[/bold red]")
                for flag in flags:
                    console.print(f"- {flag}")
        else:
            console.print(Panel("Nenhum vetor financeiro (PIX/Crypto) identificado.", title="[$] Rastreio Financeiro", border_style="white"))
    else:
         console.print(Panel("Módulo de Inteligência Financeira vazio.", title="[$] Rastreio Financeiro", border_style="dim"))

    # --- REPORTING (IA) ---
    if report:
        if AIReporter:
            console.print("\n[bold cyan]--- GERAÇÃO DE RELATÓRIO (IA) ---[/bold cyan]")
            with console.status("[bold purple]Escrevendo dossiê investigativo...[/bold purple]"):
                reporter = AIReporter()
                # Prepare data for AI
                case_data = {
                    "target": url,
                    "date": time.strftime("%Y-%m-%d"),
                    "infra": {
                        "protection": protection,
                        "status": status
                    },
                    "compliance": comp_res,
                    "financial": fin_intel
                }
                dossier_text = reporter.generate_dossier(case_data)
                filename = reporter.save_report(dossier_text)
            console.print(f"[bold green]Relatório IA salvo em: {filename}[/bold green]")
        else:
            console.print("[bold red]Erro: Módulo AIReporter não encontrado.[/bold red]")


# --- SUBCOMANDO OSINT (IDENTITY) ---

osint_app = typer.Typer(help="Ferramentas de Inteligência de Fontes Abertas (OSINT)")
app.add_typer(osint_app, name="osint")

@osint_app.command("email")
def osint_email(address: str):
    """
    Realiza varredura passiva em um e-mail (Gravatar, Spotify, Skype, etc).
    """
    if not IdentityModule:
        console.print("[bold red]Módulo Identity não encontrado.[/bold red]")
        return
        
    print_banner()
    console.print(f"\n[bold white]Investigando Identidade Digital:[/bold white] [cyan]{address}[/cyan]\n")
    
    with console.status("[bold blue]Consultando bases de dados...[/bold blue]"):
        module = IdentityModule()
        module.run(address)
        results = module.get_results()
        
    if results:
        for res in results:
            title = res.get("title", "Evidência")
            content = res.get("content", "")
            confidence = res.get("confidence", "low")
            
            icon = "[?]"
            border = "white"
            
            if "Spotify" in title: icon = "[Music]"; border="green"
            elif "Gravatar" in title: icon = "[Photo]"; border="blue"
            elif "Skype" in title: icon = "[Call]"; border="cyan"
            
            console.print(Panel(f"{icon} {content}", title=f"🕵️ {title} ({confidence})", border_style=border))
    else:
        console.print("[bold yellow]Nenhuma pegada digital encontrada para este e-mail.[/bold yellow]")


# --- SUBCOMANDO DECODE (UTILS) ---

decode_app = typer.Typer(help="Ferramentas de Decodificação")
app.add_typer(decode_app, name="decode")

@decode_app.command("pix")
def decode_pix_cmd(code: str):
    """
    Decodifica strings PIX Copia-e-Cola (EMV QRCPS).
    Extrai Beneficiário, Cidade, TXID e Valor.
    """
    if not PixIntelligence:
         console.print("[bold red]Módulo PixIntelligence não encontrado.[/bold red]")
         return

    print_banner()
    console.print(f"\n[bold white]Decodificando PIX...[/bold white]\n")
    
    module = PixIntelligence()
    # Determine input type. If pure hex, convert? Usually input is raw string "000201..."
    decoded = module.decode_emv(code)
    
    if decoded:
        table = Table(title="Dados do PIX Decodificados")
        table.add_column("Campo", style="cyan")
        table.add_column("Valor", style="white")
        
        table.add_row("Beneficiário", decoded.get("beneficiary_name", "N/A"))
        table.add_row("Cidade", decoded.get("city", "N/A"))
        table.add_row("Chave PIX", decoded.get("pix_key", "N/A"))
        table.add_row("Valor", decoded.get("amount", "R$ 0,00"))
        table.add_row("TxID", decoded.get("txid", "N/A"))
        
        console.print(table)
    else:
        console.print("[bold red]Falha ao decodificar PIX. Payload inválido ou CRC incorreto.[/bold red]")


if __name__ == "__main__":
    app()