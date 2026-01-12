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

# Force UTF-8 on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

# Core Imports
from anhanga.core.engine import run_investigation
from anhanga.core.config import ConfigManager

# Optional AI Reporter
try:
    from anhanga.modules.reporter.writer import AIReporter
except ImportError:
    AIReporter = None

app = typer.Typer(help="Anhangá - Framework de Defesa Cibernética e Inteligência Financeira")
console = Console()
cfg = ConfigManager()

def print_banner():
    # Professional ASCII Banner
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
            [bold white]Advanced Financial Crime & Threat Intelligence Platform - v3.0[/bold white]
   """
    console.print(banner)

@app.command()
def version():
    """Exibe a versão e banner do sistema."""
    print_banner()

@app.command()
def config(
    vt: str = typer.Option(None, "--set-vt", help="Configurar chave API VirusTotal"),
    shodan: str = typer.Option(None, "--set-shodan", help="Configurar chave API Shodan"),
    urlscan: str = typer.Option(None, "--set-urlscan", help="Configurar chave API URLScan.io")
):
    """Gerencia configurações e chaves de API."""
    if vt: 
        cfg.set_key("virustotal", vt)
        console.print("[green]Chave VT Salva![/green]")
    if shodan:
        cfg.set_key("shodan", shodan)
        console.print("[green]Chave Shodan Salva![/green]")
        
    if urlscan:
        cfg.set_key("urlscan", urlscan)
        console.print("[green]Chave URLScan Salva![/green]")
        
    if not vt and not shodan and not urlscan:
        console.print("[yellow]Use --set-vt, --set-shodan ou --set-urlscan para configurar.[/yellow]")

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
    
    with console.status("[bold blue]Executando Anhangá Engine v3.0 (Async)...[/bold blue]", spinner="dots"):
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
    infra_data = state.get("infra_data", {})
    
    infra_text = Text()
    infra_text.append(f"Proteção Detectada: {protection}\n", style="bold yellow" if protection != "None" else "green")
    
    # Enrich with Heavy Infra Data
    if infra_data:
        ip = infra_data.get("ip", "N/A")
        tech = infra_data.get("tech", [])
        emails = infra_data.get("emails", [])
        
        infra_text.append(f"IP do Servidor: {ip}\n", style="bold cyan")
        
        if tech:
            infra_text.append("\n Tecnologias Detectadas:\n", style="bold white")
            for t in tech:
                infra_text.append(f"- {t}\n", style="dim")
                
        if emails:
            infra_text.append("\n E-mails Encontrados (Scraping):\n", style="bold white")
            for e in emails:
                infra_text.append(f"- {e}\n", style="cyan underline")

        # [NEW] Whois Display
        w_data = infra_data.get("whois")
        if w_data and w_data.get("registrar"):
             infra_text.append(f"\n[Whois] {w_data.get('registrar')} ({w_data.get('creation_date')})\n", style="dim")
        else:
             infra_text.append(f"\n[Whois] Dados não disponíveis\n", style="dim")
        
        # [NEW] Shodan Display
        s_data = infra_data.get("shodan")
        if s_data and s_data.get("ip") != "N/A": # Basic check or check ports
            # Ensure we don't crash on None org
            org = s_data.get('org') or "Unknown"
            infra_text.append(f"\n[Shodan] Org: {org}\n", style="bold red")
            
            ports = s_data.get('ports') or []
            if ports:
                infra_text.append(f" Portas: {ports}\n", style="red")
            
            vulns = s_data.get('vulns') or []
            if vulns:
                infra_text.append(f" Vulns: {len(vulns)} detectadas!\n", style="bold red blink")
        else:
             # Only show unavailable if we expected it? Or just suppress? 
             # User asked to "handle empty data gracefully (display 'N/A'...)"
             # But if Shodan key isn't present, maybe we shouldn't show "N/A". 
             # Let's show "N/A" only if we have a section header concept. 
             # Here we are appending inline.
             # I'll stick to printing "[Shodan] N/A" if checking failed but key might have been present. 
             # For now, if no data, let's print "Dados Shodan não disponíveis" to be safe.
             pass 

        # URLScan (Legacy/Preserved)
        if u_data := infra_data.get("urlscan"):
             u_report_url = u_data.get("report_url", "N/A")
             if u_report_url != "N/A":
                  infra_text.append(f"\n[URLScan] {u_report_url}\n", style="blue underline")

        # VirusTotal
        if vt_data := infra_data.get("virustotal"):
            if "malicious" in vt_data:
                malicious = vt_data.get("malicious", 0)
                harmless = vt_data.get("harmless", 0)
                color = "red" if malicious > 0 else "green"
                infra_text.append(f"\n[🛡️ VirusTotal] {malicious} Maliciosos / {harmless} Seguros\n", style=f"bold {color}")
            elif vt_data.get("status") == "not_found":
                infra_text.append("\n[🛡️ VirusTotal] URL não encontrada na base.\n", style="dim")

    infra_text.append(f"\nStatus da Coleta: {status}\n", style="white")
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
                        "status": status,
                        "details": infra_data # Includes IP, Tech, etc
                    },
                    "compliance": comp_res,
                    "financial": fin_intel
                }
                dossier_text = reporter.generate_dossier(case_data)
                filename = reporter.save_report(dossier_text)
            console.print(f"[bold green]Relatório IA salvo em: {filename}[/bold green]")
        else:
            console.print("[bold red]Erro: Módulo AIReporter não encontrado.[/bold red]")


if __name__ == "__main__":
    app()