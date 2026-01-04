# Arquivo: anhanga/core/engine.py
import importlib
from rich.console import Console
from anhanga.core.base import AnhangáModule # <--- Import Corrigido

console = Console()

class InvestigationEngine:
    def __init__(self):
        self.loaded_modules = {}

    def load_module(self, category: str, module_name: str) -> AnhangáModule:
        """
        Carrega dinamicamente um módulo (ex: 'fincrime', 'pix_decoder').
        """
        try:
            module_path = f"anhanga.modules.{category}.{module_name}"
            
            mod = importlib.import_module(module_path)
            
            target_class = None
            for attribute_name in dir(mod):
                attribute = getattr(mod, attribute_name)
                if (isinstance(attribute, type) and 
                    issubclass(attribute, AnhangáModule) and 
                    attribute is not AnhangáModule):
                    target_class = attribute
                    break
            
            if not target_class:
                raise ImportError(f"Nenhuma classe AnhangáModule encontrada em {module_path}")

            instance = target_class()
            self.loaded_modules[f"{category}.{module_name}"] = instance
            return instance

        except Exception as e:
            console.print(f"[bold red][!] Erro ao carregar módulo '{module_name}': {e}[/bold red]")
            return None

    def run_pipeline(self, target: str, pipeline_steps: list):
        """Executa a sequência de módulos."""
        results_aggregated = []
        
        for step in pipeline_steps:
            category, name = step.split('.')
            module = self.load_module(category, name)
            
            if module:
                with console.status(f"[bold blue]Executando {module.meta['name']}...[/bold blue]"):
                    try:
                        module.run(target)
                        results_aggregated.extend(module.get_results())
                        console.print(f"[green]✓ {module.meta['name']} finalizado.[/green]")
                    except Exception as e:
                        console.print(f"[red]✗ Erro em {module.meta['name']}: {e}[/red]")
        
        return results_aggregated