import logging
from typing import TypedDict, Annotated, List, Dict, Any, Optional
import requests
import operator

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from rich.console import Console

# Import Camoufox for Stealth Scraper
# Note: Assuming camoufox is installed in the environment
try:
    from camoufox.sync_api import Camoufox
except ImportError:
    # Fallback or mock if camoufox is not available, though user requested it.
    Camoufox = None

console = Console()

class AgentState(TypedDict):
    url: str
    html: Optional[str]
    headers: Dict[str, Any]
    protection_detected: bool
    protection_type: Optional[str]
    screenshot_path: Optional[str]
    retry_count: int
    status: str
    errors: List[str]

def infra_hunter_node(state: AgentState) -> AgentState:
    """
    First node: Checks for infrastructure and protection mechanisms (like Cloudflare).
    """
    url = state["url"]
    
    # Initialize defaults if missing
    if "retry_count" not in state:
        state["retry_count"] = 0
    if "screenshot_path" not in state:
        state["screenshot_path"] = None
        
    console.print(f"[bold blue][InfraHunter][/bold blue] Analyzing: {url}")
    
    try:
        # Initial lightweight request to detect WAF/CDN
        # Using a standard user-agent to see how the server reacts
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        server_header = response.headers.get("Server", "").lower()
        cf_ray = response.headers.get("CF-RAY")
        status_code = response.status_code
        
        state["headers"] = dict(response.headers)
        
        # Detection logic
        is_cloudflare = "cloudflare" in server_header or cf_ray is not None
        
        # Sometimes Cloudflare returns 403 or 503 when challenging
        is_challenge = status_code in [403, 503] and is_cloudflare
        
        if is_cloudflare:
            console.print(f"[bold yellow][InfraHunter][/bold yellow] Cloudflare detected! (Server: {server_header})")
            state["protection_detected"] = True
            state["protection_type"] = "Cloudflare"
        else:
            console.print("[bold green][InfraHunter][/bold green] No heavy protection detected.")
            state["protection_detected"] = False
            state["protection_type"] = None
            
    except Exception as e:
        console.print(f"[bold red][InfraHunter] Error: {e}[/bold red]")
        state["errors"].append(str(e))
        # If we can't connect, let's assume no specific protection type detected yet, or connection error.
        
    return state

def stealth_scraper_node(state: AgentState) -> AgentState:
    """
    Stealth Scraper: Uses Camoufox to bypass protections.
    """
    url = state["url"]
    console.print(f"[bold magenta][StealthScraper][/bold magenta] Engaging Camoufox for {url}...")
    
    if Camoufox is None:
        msg = "Camoufox library not found. Cannot perform stealth scraping."
        console.print(f"[bold red]{msg}[/bold red]")
        state["errors"].append(msg)
        state["status"] = "failed"
        return state

    try:
        with Camoufox(headless=True) as browser:
            page = browser.new_page()
            page.goto(url, timeout=30000)
            # Find a way to wait for cloudflare challenge if needed? 
            # Camoufox usually handles this.
            page.wait_for_load_state("networkidle")
            
            # Take screenshot
            import os
            from datetime import datetime
            
            # Ensure screenshots dir exists
            # Ideally this path should be configurable, using temp or specific dir
            screenshots_dir = "screenshots"
            if not os.path.exists(screenshots_dir):
                os.makedirs(screenshots_dir)
                
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_url = url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "")[:50]
            screenshot_filename = f"{screenshots_dir}/{safe_url}_{timestamp}.png"
            
            page.screenshot(path=screenshot_filename)
            state["screenshot_path"] = screenshot_filename
            console.print(f"[bold magenta][StealthScraper][/bold magenta] Screenshot saved to {screenshot_filename}")

            content = page.content()
            
            state["html"] = content
            state["status"] = "success"
            console.print(f"[bold magenta][StealthScraper][/bold magenta] Automatically bypassed protection. Content length: {len(content)}")
            
    except Exception as e:
        console.print(f"[bold red][StealthScraper] Error: {e}[/bold red]")
        state["errors"].append(str(e))
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
        # Re-using the logic from Hunter or just simple get
        response = requests.get(url, headers=headers, timeout=15, verify=False)
        response.raise_for_status()
        
        state["html"] = response.text
        state["status"] = "success"
        state["screenshot_path"] = None # No screenshot capability in requests
        console.print(f"[bold cyan][StandardScraper][/bold cyan] Success. Content length: {len(response.text)}")
        
    except Exception as e:
        console.print(f"[bold red][StandardScraper] Error: {e}[/bold red]")
        state["errors"].append(str(e))
        state["status"] = "failed"
        state["retry_count"] += 1
        
    return state

def route_protection(state: AgentState) -> str:
    """
    Router: Decides next step based on protection detection.
    """
    if state.get("protection_detected"):
        return "stealth_scraper"
    return "standard_scraper"

# Graph Construction
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

# Helper function to run the graph easily
def run_investigation(url: str, thread_id: str = "1") -> Dict[str, Any]:
    initial_state = {
        "url": url,
        "html": None,
        "headers": {},
        "protection_detected": False,
        "protection_type": None,
        "screenshot_path": None,
        "retry_count": 0,
        "status": "pending",
        "errors": []
    }
    
    config = {"configurable": {"thread_id": thread_id}}
    
    # Run the graph
    # LangGraph returns the final state
    result_state = investigation_graph.invoke(initial_state, config=config)
    return result_state