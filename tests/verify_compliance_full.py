from anhanga.core.engine import run_investigation
from rich.console import Console
from rich.pretty import pprint

console = Console()

def main():
    targets = [
        ("https://betano.bet.br", "Should be AUTHORIZED / ADMINISTRATIVE"),
        ("https://zeroum.bet", "Should be AUTHORIZED / JUDICIAL - Critical Check"),
        ("https://stake.com", "Should be ILLEGAL_FOREIGN")
    ]
    
    for url, expected in targets:
        console.print(f"\n[bold blue]Running investigation for:[/bold blue] {url}")
        console.print(f"[italic yellow]Expected: {expected}[/italic yellow]")
        
        try:
            # Generate a unique thread_id or just use default since running sequentially
            result = run_investigation(url)
            
            console.print(f"[bold green]Compliance Result for {url}:[/bold green]")
            if result and "compliance_result" in result:
                pprint(result["compliance_result"])
            else:
                console.print("[red]No compliance result found in output state.[/red]")
                pprint(result)
                
        except Exception as e:
            console.print(f"[bold red]Error running investigation for {url}:[/bold red] {e}")
        
        console.print("-" * 50)

if __name__ == "__main__":
    main()
