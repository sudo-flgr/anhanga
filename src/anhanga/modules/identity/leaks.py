# Arquivo: anhanga/modules/identity/leaks.py
import requests
from anhanga.core.base import AnhangáModule
from anhanga.core.config import ConfigManager

class LeakModule(AnhangáModule):
    def __init__(self):
        super().__init__()
        self.meta = {
            "name": "LeakHunter",
            "description": "Verificação de exposição de credenciais e vazamentos",
            "version": "2.1"
        }
        self.cfg = ConfigManager()

    def run(self, email: str) -> bool:
        self.add_evidence("Alvo Analisado", email, "high")
        
        self._run_google_dorks(email)
        
        # 2. Busca de CNPJ via Domínio 
        if self._is_corporate_email(email):
            domain = email.split("@")[1]
            self._check_corporate_link(domain)
            
        return True

    def _is_corporate_email(self, email):
        """Filtra provedores gratuitos comuns."""
        free_providers = ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "uol.com.br", "bol.com.br", "icloud.com"]
        domain = email.split("@")[1].lower()
        return domain not in free_providers

    def _run_google_dorks(self, email):
        """Gera links de inteligência para busca manual em bases indexadas."""
        dorks = {
            "Vazamento Pastebin": f'site:pastebin.com "{email}"',
            "Exposição de Arquivos": f'filetype:txt OR filetype:csv "{email}"',
            "Vínculo com CPF": f'"{email}" CPF',
            "Listas de Combo": f'"{email}" combo list'
        }
        
        report_content = "Links para verificação manual (Google Hacking):\n"
        for title, query in dorks.items():
            url = f"https://www.google.com/search?q={requests.utils.quote(query)}"
            report_content += f"- {title}: {url}\n"
            
        self.add_evidence("Google Dorking (Leaks)", report_content, "medium")

    def _check_corporate_link(self, domain):
        try:
            import whois
            w = whois.whois(domain)
            
            info = []
            if w.org: info.append(f"Organização: {w.org}")
            if w.emails: info.append(f"Emails de Registro: {w.emails}")
            if w.creation_date: info.append(f"Criação: {w.creation_date}")
            
            if info:
                self.add_evidence("Domínio Corporativo", "\n".join(info), "high")
            else:
                self.add_evidence("Domínio Corporativo", "Whois protegido ou sem dados claros.", "low")

        except Exception as e:
            pass