# Arquivo: anhanga/core/base.py
from abc import ABC, abstractmethod
from typing import Any, Dict, List
from datetime import datetime

class AnhangáModule(ABC):
    """
    Classe base para todos os módulos do Anhangá v2.0.
    """
    def __init__(self):
        self.meta = {
            "name": self.__class__.__name__,
            "description": "Módulo genérico",
            "author": "Anhangá Core",
            "version": "1.0"
        }
        self.results: List[Dict[str, Any]] = []

    @abstractmethod
    def run(self, target: str) -> bool:
        """
        Método obrigatório. Recebe o alvo e processa.
        """
        pass

    def add_evidence(self, title: str, content: Any, confidence: str = "medium"):
        """Padroniza a saída de evidências."""
        self.results.append({
            "module": self.meta["name"],
            "title": title,
            "content": content,
            "confidence": confidence,
            "timestamp": str(datetime.now())
        })

    def get_results(self):
        return self.results