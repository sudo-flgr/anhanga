import logging
import asyncio
import os
import requests
import urllib3
from datetime import datetime
from typing import TypedDict, Annotated, List, Dict, Any, Optional
import operator

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver
from rich.console import Console
from anhanga.modules.fincrime.compliance.validator import BetCompliance

# Suprime avisos de SSL (comum em sites de phishing)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

console = Console()

class AgentState(TypedDict):
    url: str
    html: Optional[str]
    headers: Dict[str, Any]
    protection_type: str  # 'Cloudflare', 'None', etc.
    screenshot_path: Optional[str]
    status: str  # 'success', 'failed', 'pending'
    retry_count: int
    errors: List[str]
    compliance_result: Optional[Dict[str, Any]]

# Initialize Compliance Validator
compliance_validator = BetCompliance()

def infra_hunter_node(state: AgentState) -> AgentState:
    """
    First node: Checks for infrastructure and protection mechanisms (like Cloudflare).
    """
    url = state["url"]
    console.print(f"[bold blue][InfraHunter][/bold blue] Analisando: {url}")
    
    state.setdefault("retry_count", 0)
    state.setdefault("errors", [])
    state.setdefault("screenshot_path", None)
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        server_header = response.headers.get("Server", "").lower()
        cf_ray = response.headers.get("CF-RAY")
        status_code = response.status_code
        
        state["headers"] = dict(response.headers)
        
        is_cloudflare = "cloudflare" in server_header or cf_ray is not None
        is_challenge = status_code in [403, 503]
        
        if is_cloudflare or (is_challenge and is_cloudflare):
            console.print(f"[bold yellow][InfraHunter][/bold yellow] [!] Proteção Cloudflare detectada! (Server: {server_header})")
            state["protection_type"] = "Cloudflare"
        else:
            console.print("[bold green][InfraHunter][/bold green] Nenhuma proteção pesada detectada.")
            state["protection_type"] = "None"
            
    except Exception as e:
        console.print(f"[bold red][InfraHunter] Erro: {e}[/bold red]")
        state["errors"].append(f"Erro no InfraHunter: {str(e)}")
        state["protection_type"] = "None" 
        
    return state

async def stealth_scraper_node(state: AgentState) -> AgentState:
    """
    Stealth Scraper: Uses AsyncCamoufox to bypass protections and take screenshots.
    """
    url = state["url"]
    console.print(f"[bold magenta][StealthScraper][/bold magenta] [~] Iniciando modo Stealth (Camoufox) para {url}...")
    
    try:
        from camoufox.async_api import AsyncCamoufox
    except ImportError:
        msg = "Biblioteca Camoufox não encontrada. Instale-a para usar o StealthScraper."
        console.print(f"[bold red]{msg}[/bold red]")
        state["errors"].append(msg)
        state["status"] = "failed"
        return state

    try:
        async with AsyncCamoufox(headless=True) as browser:
            page = await browser.new_page()
            
            await page.goto(url, timeout=60000, wait_until="domcontentloaded")
            await page.wait_for_load_state("networkidle", timeout=10000)
            
            screenshots_dir = "screenshots"
            if not os.path.exists(screenshots_dir):
                os.makedirs(screenshots_dir)
                
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_url = "".join(c if c.isalnum() else "_" for c in url)[:50]
            screenshot_path = os.path.join(screenshots_dir, f"{safe_url}_{timestamp}.png")
            
            await page.screenshot(path=screenshot_path)
            state["screenshot_path"] = screenshot_path
            console.print(f"[bold magenta][StealthScraper][/bold magenta] Screenshot salvo em {screenshot_path}")

            content = await page.content()
            state["html"] = content
            state["status"] = "success"
            console.print(f"[bold magenta][StealthScraper][/bold magenta] [+] Sucesso. Tamanho do conteúdo: {len(content)}")
            
    except Exception as e:
        console.print(f"[bold red][StealthScraper] Erro: {e}[/bold red]")
        state["errors"].append(f"Erro no StealthScraper: {str(e)}")
        state["status"] = "failed"
        state["retry_count"] += 1
        
    return state

def standard_scraper_node(state: AgentState) -> AgentState:
    """
    Standard Scraper: Uses standard Requests.
    """
    url = state["url"]
    console.print(f"[bold cyan][StandardScraper][/bold cyan] Buscando {url} com requests...")
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=15, verify=False)
        response.raise_for_status()
        
        state["html"] = response.text
        state["status"] = "success"
        console.print(f"[bold cyan][StandardScraper][/bold cyan] [+] Sucesso. Tamanho do conteúdo: {len(response.text)}")
        
    except Exception as e:
        console.print(f"[bold red][StandardScraper] Erro: {e}[/bold red]")
        state["errors"].append(f"Erro no StandardScraper: {str(e)}")
        state["status"] = "failed"
        state["retry_count"] += 1
        
    return state

def compliance_check_node(state: AgentState) -> AgentState:
    """
    Compliance Check: Verifies if the domain is authorized.
    """
    url = state["url"]
    console.print(f"[bold blue][ComplianceCheck][/bold blue] Verificando conformidade para {url}...")

    try:
        result = compliance_validator.check_compliance(url)
        state["compliance_result"] = result

        status = result["status"]

        # Translation map for status
        status_map = {
            "AUTHORIZED": "AUTORIZADO",
            "UNLICENSED_SOVEREIGN": "NAO_LICENCIADO_SOBERANO",
            "ILLEGAL_FOREIGN": "ILEGAL_ESTRANGEIRO"
        }
        status_display = status_map.get(status, status)

        color = "green" if status == "AUTHORIZED" else "red"
        console.print(f"[{color}][ComplianceCheck] Status: {status_display}[/{color}]")
        if status == "AUTHORIZED":
            console.print(f"[{color}]Operador: {result.get('operator')}[/{color}]")
        else:
            console.print(f"[{color}]Motivo: {result.get('reason')}[/{color}]")

    except Exception as e:
        console.print(f"[bold red][ComplianceCheck] Erro: {e}[/bold red]")
        state["errors"].append(f"Erro no ComplianceCheck: {str(e)}")

    return state

def route_protection(state: AgentState) -> str:
    """
    Router: Decides next step based on protection detection.
    """
    protection_type = state.get("protection_type", "None")
    
    if protection_type == "Cloudflare":
        return "stealth_scraper"
    
    return "standard_scraper"

workflow = StateGraph(AgentState)

workflow.add_node("infra_hunter", infra_hunter_node)
workflow.add_node("stealth_scraper", stealth_scraper_node)
workflow.add_node("standard_scraper", standard_scraper_node)
workflow.add_node("compliance_check", compliance_check_node)

workflow.add_edge(START, "infra_hunter")

workflow.add_conditional_edges(
    "infra_hunter",
    route_protection,
    {
        "stealth_scraper": "stealth_scraper",
        "standard_scraper": "standard_scraper"
    }
)

workflow.add_edge("stealth_scraper", "compliance_check")
workflow.add_edge("standard_scraper", "compliance_check")
workflow.add_edge("compliance_check", END)

memory = MemorySaver()

investigation_graph = workflow.compile(checkpointer=memory)

async def run_investigation_async(url: str, thread_id: str = "1") -> Dict[str, Any]:
    """
    Async entry point for running the investigation graph.
    """
    initial_state = {
        "url": url,
        "html": None,
        "headers": {},
        "protection_type": None,
        "screenshot_path": None,
        "status": "pending",
        "retry_count": 0,
        "errors": [],
        "compliance_result": None
    }
    
    config = {"configurable": {"thread_id": thread_id}}
    
    result_state = await investigation_graph.ainvoke(initial_state, config=config)
    return result_state

def run_investigation(url: str, thread_id: str = "1") -> Dict[str, Any]:
    """
    Sync wrapper for convenience (runs asyncio loop).
    """
    return asyncio.run(run_investigation_async(url, thread_id))