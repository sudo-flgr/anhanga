import logging
import asyncio
import os
import requests
import difflib
import base64
from datetime import datetime
from typing import TypedDict, Annotated, List, Dict, Any, Optional
import operator

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver
from rich.console import Console

# Import Modules
from anhanga.modules.fincrime.pix_decoder import PixIntelligence
from anhanga.modules.crypto.wallet_hunter import WalletHunter
from anhanga.modules.fincrime.compliance.validator import BetCompliance
from anhanga.modules.infra.hunter import InfraModule
from anhanga.core.config import ConfigManager
try:
    import whois
except ImportError:
    whois = None
try:
    import shodan
except ImportError:
    shodan = None

# Configure Logging
logging.basicConfig(level=logging.ERROR) 
logger = logging.getLogger(__name__)

# --- DEFINITIONS ---

class AgentState(TypedDict):
    url: str
    html: Optional[str]
    headers: Dict[str, Any]
    protection_type: str 
    screenshot_path: Optional[str]
    status: str 
    retry_count: int
    errors: List[str]
    financial_intel: Dict[str, Any] 
    compliance_result: Optional[Dict[str, Any]]
    infra_data: Optional[Dict[str, Any]] # New Field for Rich Infra Data

# --- NODES ---

def infra_hunter_node(state: AgentState) -> AgentState:
    """
    Checks infrastructure using Heavy Infra logic (Ported from v2).
    """
    url = state["url"]
    
    # Initialize defaults
    state.setdefault("retry_count", 0)
    state.setdefault("errors", [])
    state.setdefault("screenshot_path", None)
    state.setdefault("financial_intel", {"risk_score": 0, "flags": [], "pix_data": [], "crypto_data": []})
    state.setdefault("compliance_result", None)
    state.setdefault("infra_data", {})
    
    try:
        # 1. Run Heavy Infra Module
        infra_module = InfraModule()
        infra_module.run(url)
        results = infra_module.get_results()
        
        # 2. Parse Results into structured infra_data
        infra_data = {
            "ip": "N/A",
            "tech": [],
            "emails": [],
            "favicon_hash": None,
            "virustotal": None,
            "virustotal": None,
            "whois": {"registrar": "N/A", "creation_date": "N/A"},
            "shodan": {"ports": [], "tags": []},
            "urlscan": {"report_url": "N/A"}
        }
        
        for res in results:
            title = res.get("title")
            content = res.get("content")
            
            if title == "Endereço IP":
                infra_data["ip"] = content
            elif "Scraping:" in title:
                tech_name = title.replace("Scraping: ", "")
                if "E-mails" in tech_name:
                    infra_data["emails"].extend(content.split(", "))
                else:
                    infra_data["tech"].append(f"{tech_name}: {content}")
            elif title == "Favicon Hash":
                infra_data["favicon_hash"] = content
            elif title == "VirusTotal":
                infra_data["virustotal"] = content
        
        state["infra_data"] = infra_data

        # --- EXTERNAL ENRICHMENT ---
        cfg = ConfigManager()
        target_ip = infra_data.get("ip")
        
        # 1. Whois Lookup (Native)
        try:
            # Robust extraction: remove protocol and path
            domain = url.split("//")[-1].split("/")[0]
            w = whois.whois(domain)
            state["infra_data"]["whois"] = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
                "org": w.org
            }
        except Exception as e:
            # Capturing generic exception including PywhoisError if generic
            state["errors"].append(f"Whois Error: {e}")
            
        # 2. Shodan Lookup (API)
        if target_ip and target_ip != "N/A":
            if shodan_key := cfg.get_key("shodan"):
                try:
                    api = shodan.Shodan(shodan_key)
                    # Use timeout or safe call if possible, but Shodan lib handles most
                    host = api.host(target_ip)
                    state["infra_data"]["shodan"] = {
                        "ports": host.get("ports", []),
                        "org": host.get("org", "Unknown"),
                        "tags": host.get("tags", []),
                        "vulns": list(host.get("vulns", []))
                    }
                except Exception as e:
                    state["errors"].append(f"Shodan Error: {e}")

        # 3. VirusTotal Integration
        if vt_key := cfg.get_key("virustotal"):
            try:
                # VT requires base64 URL ID (urlsafe, no padding)
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                headers = {"x-apikey": vt_key}
                
                vt_res = requests.get(vt_url, headers=headers, timeout=15)
                if vt_res.status_code == 200:
                    vt_json = vt_res.json()
                    stats = vt_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    state["infra_data"]["virustotal"] = stats
                elif vt_res.status_code == 404:
                    # URL not found in VT
                    state["infra_data"]["virustotal"] = {"status": "not_found"}
            except Exception as e:
                state["errors"].append(f"VirusTotal Error: {e}")

        # 4. URLScan.io Submission
        urlscan_key = cfg.get_key("urlscan")
        if urlscan_key:
            try:
                # Check previous implementation compatibility
                headers = {'API-Key': urlscan_key,'Content-Type': 'application/json'}
                data = {"url": url, "visibility": "public"}
                u_res = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data, timeout=15)
                if u_res.status_code == 200:
                    u_data = u_res.json()
                    if "urlscan" not in state["infra_data"]:
                         state["infra_data"]["urlscan"] = {}
                    state["infra_data"]["urlscan"]["report_url"] = u_data.get("result", "N/A")
            except Exception as e:
                state["errors"].append(f"URLScan Error: {str(e)}")

        state["protection_type"] = "Unknown"
            
    except Exception as e:
        state["errors"].append(f"InfraHunter Error: {str(e)}")
        state["protection_type"] = "Unknown" 
        
    return state

async def stealth_scraper_node(state: AgentState) -> AgentState:
    """
    Stealth Scraper: Uses AsyncCamoufox for ALL targets.
    Ensures screenshots are always taken.
    """
    url = state["url"]
    
    try:
        from camoufox.async_api import AsyncCamoufox
    except ImportError:
        msg = "Camoufox library not found."
        state["errors"].append(msg)
        state["status"] = "failed"
        return state

    try:
        async with AsyncCamoufox(headless=True) as browser:
            page = await browser.new_page()
            
            # Stealth navigation
            await page.goto(url, timeout=60000, wait_until="domcontentloaded")
            await page.wait_for_load_state("networkidle", timeout=15000)
            
            # Screenshot Logic
            screenshots_dir = "screenshots"
            if not os.path.exists(screenshots_dir):
                os.makedirs(screenshots_dir)
                
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_url = "".join(c if c.isalnum() else "_" for c in url)[:50]
            screenshot_path = os.path.join(screenshots_dir, f"{safe_url}_{timestamp}.png")
            
            await page.screenshot(path=screenshot_path)
            state["screenshot_path"] = screenshot_path

            content = await page.content()
            state["html"] = content
            state["status"] = "success"
            
    except Exception as e:
        state["errors"].append(f"StealthScraper Error: {str(e)}")
        state["status"] = "failed"
        state["retry_count"] += 1
        
    return state

def compliance_check_node(state: AgentState) -> AgentState:
    """
    Checks if the site is Authorized/Illegal using BetCompliance.
    """
    url = state["url"]
    
    try:
        # Initialize Compliance Checker (loads bets_db.json)
        checker = BetCompliance()
        result = checker.check_compliance(url)
        
        state["compliance_result"] = {
            "status": result.get("status", "UNKNOWN"),
            "operator": result.get("operator"),
            "auth_type": result.get("auth_type"),
            "brand": result.get("brand")
        }
        
    except Exception as e:
        state["errors"].append(f"Compliance Error: {str(e)}")
        
    return state

def financial_analysis_node(state: AgentState) -> AgentState:
    """
    Extracts PIX/Crypto and performs 'Orange Check'.
    """
    html = state.get("html", "")
    if not html:
        state["errors"].append("No HTML content to analyze.")
        return state
        
    # Initialize Modules
    pix_module = PixIntelligence()
    wallet_module = WalletHunter()
    
    # Run Extraction
    pix_results = pix_module.run(html)
    crypto_results = wallet_module.run(html)
    
    # Store Raw Data
    state["financial_intel"]["pix_data"] = pix_results["decoded"]
    state["financial_intel"]["crypto_data"] = crypto_results
    
    # --- ORANGE CHECK (LARANJA DETECTION) ---
    risk_score = 0
    flags = []
    
    # Get Authorized Operator from AgentSate
    compliance_result = state.get("compliance_result") or {}
    operator_name = compliance_result.get("operator") 
    
    match_score = 1.0 
    
    if operator_name:
        for pix in pix_results["decoded"]:
            pix_name = pix.get("beneficiary_name")
            if pix_name:
                # Fuzzy Match
                similarity = difflib.SequenceMatcher(None, operator_name.lower(), pix_name.lower()).ratio()
                
                if similarity < 0.6:
                    flags.append(f"Mismatch: Operator '{operator_name}' vs PIX '{pix_name}' (Score: {similarity:.2f})")
                    risk_score += 50 
                    match_score = min(match_score, similarity) 
                else:
                    flags.append(f"Verified: Operator '{operator_name}' matches PIX '{pix_name}' (Score: {similarity:.2f})")

    state["financial_intel"]["risk_score"] = risk_score
    state["financial_intel"]["flags"] = flags
    
    return state


# --- GRAPH CONSTRUCTION ---

workflow = StateGraph(AgentState)

# Add Nodes
workflow.add_node("infra_hunter", infra_hunter_node)
workflow.add_node("stealth_scraper", stealth_scraper_node)
workflow.add_node("compliance_check", compliance_check_node)
workflow.add_node("financial_analysis", financial_analysis_node)

# Add Edges: Simple Linear Flow
workflow.add_edge(START, "infra_hunter")
workflow.add_edge("infra_hunter", "stealth_scraper") # FORCE STEALTH
workflow.add_edge("stealth_scraper", "compliance_check")
workflow.add_edge("compliance_check", "financial_analysis")
workflow.add_edge("financial_analysis", END)

# Persistence
memory = MemorySaver()

# Compilation
investigation_graph = workflow.compile(checkpointer=memory)

# --- EXECUTION HELPERS ---

async def run_investigation_async(url: str, thread_id: str = "1") -> Dict[str, Any]:
    initial_state = {
        "url": url,
        "html": None,
        "headers": {},
        "protection_type": None,
        "screenshot_path": None,
        "status": "pending",
        "retry_count": 0,
        "errors": [],
        "financial_intel": {"risk_score": 0, "flags": [], "pix_data": [], "crypto_data": []},
        "compliance_result": None,
        "infra_data": None
    }
    
    config = {"configurable": {"thread_id": thread_id}}
    
    try:
        result_state = await investigation_graph.ainvoke(initial_state, config=config)
        return result_state
    except Exception as e:
        # Fallback to prevent crash
        initial_state["status"] = "failed"
        initial_state["errors"].append(str(e))
        return initial_state

def run_investigation(url: str, thread_id: str = "1") -> Dict[str, Any]:
    return asyncio.run(run_investigation_async(url, thread_id))