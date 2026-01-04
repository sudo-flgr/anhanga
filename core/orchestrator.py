from typing import List, Dict, Any
import sys
import os

from core.engine import InvestigationEngine
from core.database import CaseManager
from modules.reporter.writer import AIReporter

class Orchestrator:
    def __init__(self):
        self.engine = InvestigationEngine()
        self.db = CaseManager()
        self.reporter = AIReporter()

        # Pipelines definition
        self.pipeline_pix = ['fincrime.pix_decoder']
        self.pipeline_crypto = ['crypto.hunter']
        self.pipeline_infra = ['infra.hunter']
        # Combined identity pipeline to avoid re-running checks
        self.pipeline_identity = ['identity.checker', 'identity.leaks']

    def nuke_database(self):
        """Clears the database."""
        self.db.nuke()

    def run_financial_pipeline(self, input_fin: str) -> Dict[str, Any]:
        """
        Runs financial pipeline based on input type (Pix or Crypto).
        Returns a dict with 'type' ('pix' or 'crypto') and 'results'.
        """
        results = []
        if not input_fin:
            return {"type": "none", "results": results}

        if "br.gov.bcb.pix" in input_fin:
             results = self.engine.run_pipeline(input_fin, self.pipeline_pix)
             for res in results:
                 if res['title'] == 'Nome Recebedor':
                     self.db.add_entity(res['content'], "Pix Detectado", role="Recebedor")
             return {"type": "pix", "results": results}
        else:
             results = self.engine.run_pipeline(input_fin, self.pipeline_crypto)
             # No DB update for crypto in original code
             return {"type": "crypto", "results": results}

    def run_infra_pipeline(self, url: str) -> List[Dict[str, Any]]:
        """Runs the infrastructure analysis pipeline."""
        results = []
        if not url:
            return results

        results = self.engine.run_pipeline(url, self.pipeline_infra)

        info_buffer = ""
        ip_alvo = "N/A"

        for res in results:
            info_buffer += f"{res['title']}: {res['content']}\n"
            if res['title'] == "Endereço IP":
                ip_alvo = res['content']

        self.db.add_infra(url, ip=ip_alvo, extra_info=info_buffer)
        return results

    def run_identity_pipeline(self, email: str) -> List[Dict[str, Any]]:
        """Runs the identity verification pipeline."""
        results = []
        if not email:
            return results

        results = self.engine.run_pipeline(email, self.pipeline_identity)

        for res in results:
             self.db.add_entity(res['content'], "Identidade Digital", role=f"Vínculo: {email}")

        return results

    def generate_report(self) -> str:
        """Generates the AI dossier."""
        case_data = self.db.get_full_case()
        dossie = self.reporter.generate_dossier(case_data)
        filename = self.reporter.save_report(dossie)
        return filename
