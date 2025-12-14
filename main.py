# Arquivo: anhanga/main.py
import typer
import sys
import os
from rich.console import Console
from rich.panel import Panel

# Setup de Path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# Imports
from modules.fincrime.pix_decoder import PixForensics
from modules.infra.hunter import InfraHunter, ShodanIntel, CertificateHunter, CertificateHunter, IPGeo, VirusTotalIntel, WhoisIntel
from modules.infra.analyzer import ContractAnalyzer
from modules.fincrime.validator import LaranjaHunter
from modules.graph.builder import GraphBrain
from core.database import CaseManager
from core.config import ConfigManager # <--- NOVO GERENCIADOR

app = typer.Typer(help="Anhangá - Cyber Defense Framework")
console = Console()
db = CaseManager()
cfg = ConfigManager()

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
def config(
    shodan: str = typer.Option(None, "--set-shodan", help="Define API Key do Shodan"),
    vt: str = typer.Option(None, "--set-vt", help="Define API Key do VirusTotal")
):
    """Configurações Globais."""
    if shodan:
        cfg.set_key("shodan", shodan)
        console.print("[green][V] Shodan Key salva![/green]")
    if vt:
        cfg.set_key("virustotal", vt)
        console.print("[green][V] VirusTotal Key salva![/green]")

@app.command()
def start():
    db.nuke()
    console.print("[bold green][*] Operação Limpa Iniciada.[/bold green]")

@app.command()
def add_pix(
    pix: str = typer.Option(..., "--pix", "-p"),
    link_url: str = typer.Option(None, "--link", "-l")
):
    decoder = PixForensics(pix)
    data = decoder.analyze()
    db.add_entity(data['merchant_name'], data['pix_key'], role="Recebedor Pix")
    console.print(f"[green][+] Alvo:[/green] {data['merchant_name']}")
    
    if link_url:
        db.add_infra(link_url, ip="Desconhecido")
        db.add_relation(data['merchant_name'], link_url, "recebeu_pagamento_de")
        console.print(f"[cyan][LINK] Vínculo criado com {link_url}[/cyan]")

@app.command()
def add_url(url: str = typer.Option(..., "--url", "-u")):
    """Analisa Infra Completa (Whois, IP, VirusTotal, Shodan)."""
    console.print(f"[blue][*] Investigando: {url}[/blue]")
    
    hunter = InfraHunter(url)
    ip_geo = IPGeo()
    vt_intel = VirusTotalIntel(cfg.get_key("virustotal"))
    whois_tool = WhoisIntel()
    
    # 1. Resolução e Favicon
    target_ip = hunter.resolve_ip()
    hash_val, _ = hunter.get_favicon_hash()
    
    report = f"IP: {target_ip}\n"
    report += f"Hash: {hash_val}\n" if hash_val else "Hash: N/A\n"

    # 2. WHOIS (Dados de Registro)
    with console.status("[bold yellow]Consultando Whois (Registrar)...[/bold yellow]"):
        w_data = whois_tool.get_whois(hunter.domain)
        if w_data["status"] == "Sucesso":
            report += f"\n[WHOIS]\nRegistrar: {w_data['registrar']}\nOrg: {w_data['org']}\nCriado em: {w_data['creation_date']}\nE-mails: {w_data['emails']}\n"
        else:
            report += f"\n[WHOIS]: Falha ({w_data['error']})\n"

    # 3. Enriquecimento de Rede
    if target_ip:
        geo_info = ip_geo.get_data(target_ip)
        report += f"\n[REDE]: {geo_info}\n"
    
    # 4. VirusTotal
    if target_ip and vt_intel.key:
        with console.status("[bold red]Consultando VirusTotal...[/bold red]"):
            vt_data = vt_intel.analyze_ip(target_ip)
            if vt_data and "error" not in vt_data:
                report += f"\n[VIRUSTOTAL]\nStatus: {vt_data['verdict']}\nDono: {vt_data['owner']}\n"

    # 5. Shodan
    shodan_key = cfg.get_key("shodan")
    if shodan_key:
        shodan_tool = ShodanIntel(shodan_key)
        intel = shodan_tool.enrich_target(target_ip, hash_val)
        if not intel.get("error"):
            report += f"\n[SHODAN]: {intel['strategy']} - Dados coletados."

    db.add_infra(url, ip=str(target_ip), extra_info=report)
    console.print(Panel(report, title="Dossiê de Infraestrutura", border_style="cyan"))

@app.command()
def graph():
    brain = GraphBrain()
    case = db.get_full_case()
    
    for ent in case['entities']: brain.add_fincrime_data(ent['name'], ent['document'])
    for inf in case['infra']: brain.add_infra_data(inf['domain'], inf['ip'])
        
    for rel in case['relations']:
        brain.connect_entities(rel['source'], rel['target'], relation_type=rel['type'])
        
    brain.plot_investigation()

if __name__ == "__main__":
    app()