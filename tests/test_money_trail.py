import sys
import os
import asyncio
from rich.console import Console

# Ensure src is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from anhanga.core.engine import financial_analysis_node, AgentState

console = Console()

def test_orange_check_mismatch():
    console.print("[bold blue]Test 1: Mismatch 'Orange Check' (Laranja Detection)[/bold blue]")
    
    # 1. Simulate HTML with a PIX code
    # This PIX string has Beneficiary: "JOAO DA SILVA SAUROI" (ID 59)
    # Generated for testing purposes (fake CRC but structure is valid enough for parsing if we skip strict CRC or use a valid one)
    # Let's use a "valid-looking" string. 
    # To bypass CRC check in test, we might see "CRC Invalid" but data should still be extracted.
    # Payload below roughly mimics: Name=JOAO SILVA, City=BRASILIA
    pix_payload = "00020126580014BR.GOV.BCB.PIX0136123e4567-e89b-12d3-a456-4266554400005204000053039865406100.005802BR5910JOAO SILVA6008BRASILIA62070503***6304ABCD"
    
    html_content = f"""
    <html>
        <body>
            <h1>Betting Site</h1>
            <p>Pay with PIX:</p>
            <p>{pix_payload}</p>
        </body>
    </html>
    """
    
    # 2. Simulate State
    state: AgentState = {
        "url": "https://fake-bet.com",
        "html": html_content,
        "headers": {},
        "protection_type": "None",
        "screenshot_path": None,
        "status": "success",
        "retry_count": 0,
        "errors": [],
        "financial_intel": {"risk_score": 0, "flags": [], "pix_data": [], "crypto_data": []},
        # THE OFFICIAL OPERATOR IS "BETANO"
        "compliance_result": {"status": "authorized", "operator": "BETANO INTERNACIONAL"}
    }
    
    # 3. Run Node
    result_state = financial_analysis_node(state)
    
    # 4. Verify
    intel = result_state["financial_intel"]
    risk_score = intel["risk_score"]
    flags = intel["flags"]
    
    console.print(f"\n[bold]Risk Score:[/bold] {risk_score}")
    console.print(f"[bold]Flags:[/bold] {flags}")
    
    if risk_score >= 50 and any("Mismatch" in f for f in flags):
        console.print("[bold green]PASS: High Risk detected for Name Mismatch![/bold green]")
    else:
        console.print("[bold red]FAIL: Did not detect mismatch properly.[/bold red]")

def test_orange_check_match():
    console.print("\n[bold blue]Test 2: Match (Legitimate Flow)[/bold blue]")
    
    # Payload with Name=BETANO TECH (SIMILAR TO BETANO INTERNACIONAL)
    pix_payload = "00020126580014BR.GOV.BCB.PIX0136123e4567-e89b-12d3-a456-4266554400005204000053039865406100.005802BR5911BETANO TECH6008BRASILIA62070503***6304ABCD"
    
    html_content = f"<p>{pix_payload}</p>"
    
    state: AgentState = {
        "url": "https://fake-bet.com",
        "html": html_content,
        "headers": {},
        "protection_type": "None",
        "screenshot_path": None,
        "status": "success",
        "retry_count": 0,
        "errors": [],
        "financial_intel": {"risk_score": 0, "flags": [], "pix_data": [], "crypto_data": []},
        "compliance_result": {"status": "authorized", "operator": "BETANO INTERNACIONAL"}
    }
    
    result_state = financial_analysis_node(state)
    intel = result_state["financial_intel"]
    
    console.print(f"[bold]Risk Score:[/bold] {intel['risk_score']}")
    console.print(f"[bold]Flags:[/bold] {intel['flags']}")
    
    # Assuming "BETANO TECH" matches "BETANO INTERNACIONAL" with > 0.6 similarity
    # Difflib: SequenceMatcher(None, "betano internacional", "betano tech").ratio()
    # verify logic
    
    if intel["risk_score"] < 50:
         console.print("[bold green]PASS: Low Risk for Consistent Name![/bold green]")
    else:
         console.print("[bold red]FAIL: False Positive on match.[/bold red]")


if __name__ == "__main__":
    test_orange_check_mismatch()
    test_orange_check_match()
