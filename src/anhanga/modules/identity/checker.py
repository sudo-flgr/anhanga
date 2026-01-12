import requests
import hashlib
from anhanga.core.base import AnhangáModule

class IdentityModule(AnhangáModule):
    def __init__(self):
        super().__init__()
        self.meta = {
            "name": "IdentityHunter",
            "description": "Validação de E-mail em Plataformas (Gravatar, Spotify, Skype)",
            "version": "2.0"
        }

    def run(self, email: str) -> bool:
        """
        Verifica a presença digital de um e-mail (OSINT Passivo).
        """
        self.add_evidence("Alvo", email, "high")
        
        self._check_gravatar(email)

        self._check_spotify(email)
        
        self._check_skype(email)

        return True

    def _check_gravatar(self, email):
        """Verifica se existe avatar global associado."""
        try:
            email_hash = hashlib.md5(email.lower().strip().encode('utf-8')).hexdigest()
            url = f"https://en.gravatar.com/{email_hash}.json"
            
            r = requests.get(url, headers={'User-Agent': 'Anhangá-OSINT'}, timeout=5)
            if r.status_code == 200:
                data = r.json()
                entry = data['entry'][0]
                
                username = entry.get('preferredUsername', 'N/A')
                name = entry.get('displayName', 'N/A')
                location = entry.get('currentLocation', 'N/A')
                photos = entry.get('photos', [])
                
                evidence = f"Usuário: {username}\nNome: {name}\nLocal: {location}"
                if photos:
                    evidence += f"\nFoto URL: {photos[0]['value']}"
                
                self.add_evidence("Gravatar Encontrado", evidence, "high")
            elif r.status_code == 404:
                self.add_evidence("Gravatar", "Sem perfil público.", "low")
        except:
            pass

    def _check_spotify(self, email):
        """Verifica se o e-mail está registrado no Spotify."""
        try:
            url = f"https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={email}"
            headers = {'User-Agent': 'Mozilla/5.0'}
            r = requests.get(url, headers=headers, timeout=5)
            
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == 20: 
                    self.add_evidence("Spotify", "Conta existente vinculada a este e-mail.", "medium")
        except:
            pass

    def _check_skype(self, email):
        """Tenta resolver o e-mail para um usuário Skype."""
        try:
            url = f"https://login.skype.com/json/validator?new_username={email}"
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == 406:
                    self.add_evidence("Microsoft/Skype", "E-mail vinculado a conta Microsoft.", "medium")
        except:
            pass