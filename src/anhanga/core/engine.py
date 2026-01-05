import logging
import asyncio
import os
import requests
from datetime import datetime
from typing import TypedDict, Annotated, List, Dict, Any, Optional
import operator

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver
from rich.console import Console

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

console = Console()

# --- DEFINITIONS ---

class AgentState(TypedDict):
    url: str
    html: Optional[str]
    headers: Dict[str, Any]
    protection_type: str  # 'Cloudflare', 'None', etc.
    screenshot_path: Optional[str]
    status: str  # 'success', 'failed', 'pending'
    retry_count: int
    errors: List[str]

# --- NODES ---

def infra_hunter_node(state: AgentState) -> AgentState:
    """
    First node: Checks for infrastructure and protection mechanisms (like Cloudflare).
    """
    url = state["url"]
    console.print(f"[bold blue][InfraHunter][/bold blue] Analyzing: {url}")
    
    # Initialize defaults
    state.setdefault("retry_count", 0)
    state.setdefault("errors", [])
    state.setdefault("screenshot_path", None)
    
    try:
        # Lightweight request to detect WAF/CDN
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        # Verify=False to avoid SSL issues on target
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        server_header = response.headers.get("Server", "").lower()
        cf_ray = response.headers.get("CF-RAY")
        status_code = response.status_code
        
        state["headers"] = dict(response.headers)
        
        # Detection logic
        is_cloudflare = "cloudflare" in server_header or cf_ray is not None
        
        # Check for challenge pages (403/503 often used by WAFs)
        is_challenge = status_code in [403, 503]
        
        if is_cloudflare or (is_challenge and is_cloudflare):
            console.print(f"[bold yellow][InfraHunter][/bold yellow] Cloudflare detected! (Server: {server_header})")
            state["protection_type"] = "Cloudflare"
        else:
            console.print("[bold green][InfraHunter][/bold green] No heavy protection detected.")
            state["protection_type"] = "None"
            
    except Exception as e:
        console.print(f"[bold red][InfraHunter] Error: {e}[/bold red]")
        state["errors"].append(f"InfraHunter Error: {str(e)}")
        # Default to None to try standard scraper or fail gracefully
        state["protection_type"] = "None" 
        
    return state

async def stealth_scraper_node(state: AgentState) -> AgentState:
    """
    Stealth Scraper: Uses AsyncCamoufox to bypass protections and take screenshots.
    """
    url = state["url"]
    console.print(f"[bold magenta][StealthScraper][/bold magenta] Engaging Camoufox for {url}...")
    
    try:
        from camoufox.async_api import AsyncCamoufox
    except ImportError:
        msg = "Camoufox library not found. Install it to use StealthScraper."
        console.print(f"[bold red]{msg}[/bold red]")
        state["errors"].append(msg)
        state["status"] = "failed"
        return state

    try:
        async with AsyncCamoufox(headless=True) as browser:
            page = await browser.new_page()
            
            # Stealth navigation
            await page.goto(url, timeout=60000, wait_until="domcontentloaded")
            
            # Simple wait for hydration/challenges
            await page.wait_for_load_state("networkidle", timeout=10000)
            
            # Screenshot Logic
            screenshots_dir = "screenshots"
            if not os.path.exists(screenshots_dir):
                os.makedirs(screenshots_dir)
                
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Sanitize URL for filename
            safe_url = "".join(c if c.isalnum() else "_" for c in url)[:50]
            screenshot_path = os.path.join(screenshots_dir, f"{safe_url}_{timestamp}.png")
            
            await page.screenshot(path=screenshot_path)
            state["screenshot_path"] = screenshot_path
            console.print(f"[bold magenta][StealthScraper][/bold magenta] Screenshot saved to {screenshot_path}")

            content = await page.content()
            state["html"] = content
            state["status"] = "success"
            console.print(f"[bold magenta][StealthScraper][/bold magenta] Success. Content length: {len(content)}")
            
    except Exception as e:
        console.print(f"[bold red][StealthScraper] Error: {e}[/bold red]")
        state["errors"].append(f"StealthScraper Error: {str(e)}")
        state["status"] = "failed"
        state["retry_count"] += 1
        
    return state

def standard_scraper_node(state: AgentState) -> AgentState:
    """
    Standard Scraper: Uses standard Requests.
    """
    url = state["url"]
    console.print(f"[bold cyan][StandardScraper][/bold cyan] Fetching {url} with requests...")
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=15, verify=False)
        response.raise_for_status()
        
        state["html"] = response.text
        state["status"] = "success"
        # Requests cannot take screenshots
        console.print(f"[bold cyan][StandardScraper][/bold cyan] Success. Content length: {len(response.text)}")
        
    except Exception as e:
        console.print(f"[bold red][StandardScraper] Error: {e}[/bold red]")
        state["errors"].append(f"StandardScraper Error: {str(e)}")
        state["status"] = "failed"
        state["retry_count"] += 1
        
    return state

# --- ROUTING ---

def route_protection(state: AgentState) -> str:
    """
    Router: Decides next step based on protection detection.
    """
    protection_type = state.get("protection_type", "None")
    
    if protection_type == "Cloudflare":
        return "stealth_scraper"
    
    return "standard_scraper"

# --- GRAPH CONSTRUCTION ---

workflow = StateGraph(AgentState)

# Add Nodes
workflow.add_node("infra_hunter", infra_hunter_node)
workflow.add_node("stealth_scraper", stealth_scraper_node)
workflow.add_node("standard_scraper", standard_scraper_node)

# Add Edges
workflow.add_edge(START, "infra_hunter")

workflow.add_conditional_edges(
    "infra_hunter",
    route_protection,
    {
        "stealth_scraper": "stealth_scraper",
        "standard_scraper": "standard_scraper"
    }
)

workflow.add_edge("stealth_scraper", END)
workflow.add_edge("standard_scraper", END)

# Persistence
memory = MemorySaver()

# Compilation
investigation_graph = workflow.compile(checkpointer=memory)

# --- EXECUTION HELPERS ---

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
        "errors": []
    }
    
    config = {"configurable": {"thread_id": thread_id}}
    
    # Run the graph
    result_state = await investigation_graph.ainvoke(initial_state, config=config)
    return result_state

def run_investigation(url: str, thread_id: str = "1") -> Dict[str, Any]:
    """
    Sync wrapper for convenience (runs asyncio loop).
    """
    return asyncio.run(run_investigation_async(url, thread_id))