# Arquivo: anhanga/modules/infra/hunter.py
import re
import socket
import requests
import mmh3
import codecs
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from core.base import AnhangáModule
from core.config import ConfigManager

# Suprime avisos de SSL (comum em sites de phishing)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class InfraModule(AnhangáModule):
    def __init__(self):
        super().__init__()
        self.meta = {
            "name": "InfraHunter v2",
            "description": "Análise de Infra + Dirty Scraping (Analytics, Contatos, Tech)",
            "version": "2.0"
        }
        self.cfg = ConfigManager()

    def run(self, url: str) -> bool:
        """
        Executa o pipeline completo de infraestrutura.
        """
        # 1. Normalização de URL
        if not url.startswith("http"):
            target_url = f"https://{url}"
        else:
            target_url = url
        
        domain = urlparse(target_url).netloc
        
        try:
            # 2. Resolução de IP (DNS)
            ip = self._resolve_ip(domain)
            self.add_evidence("Endereço IP", ip, "high")

            # 3. Dirty Scraping (A Mágica do STRX)
            # Baixa o HTML para procurar segredos
            html_content = self._fetch_html(target_url)
            if html_content:
                self._dirty_scrape(html_content)
                self._get_favicon_hash(target_url, html_content)
            
            # 4. Integrações Externas (Se tiver chave)
            # VirusTotal
            vt_key = self.cfg.get_key("virustotal")
            if vt_key and ip != "N/A":
                self._check_virustotal(ip, vt_key)

            return True

        except Exception as e:
            self.add_evidence("Erro de Execução", str(e), "low")
            return False

    def _resolve_ip(self, domain):
        try:
            return socket.gethostbyname(domain)
        except:
            return "N/A"

    def _fetch_html(self, url):
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            r = requests.get(url, headers=headers, verify=False, timeout=10)
            return r.text
        except Exception as e:
            self.add_evidence("Erro de Conexão", f"Site inacessível: {str(e)}", "medium")
            return None

    def _dirty_scrape(self, html):
        """
        O 'Dirty Scraper': Usa Regex para achar agulha no palheiro.
        Inspirado no STRX.
        """
        # Padrões de Regex
        patterns = {
            "Google Analytics (UA)": r"UA-[0-9]+-[0-9]+",
            "Google Tag (G-)": r"G-[A-Z0-9]{10,}",
            "Meta Pixel": r"fbq\('init',\s*'([0-9]+)'\)",
            "E-mails": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}",
            "Telefones (BR)": r"(?:(?:\+|00)?(55)\s?)?(?:\(?([1-9][0-9])\)?\s?)?(?:((?:9\d|[2-9])\d{3})\-?(\d{4}))"
        }

        found_tech = []

        for label, pattern in patterns.items():
            matches = list(set(re.findall(pattern, html))) # Remove duplicatas
            if matches:
                # Limpa resultados de telefone para ficar legível
                if "Telefone" in label:
                    matches = [f"{m[1]} {m[2]}-{m[3]}" for m in matches if m[1]] # Filtra vazios

                if matches:
                    self.add_evidence(f"Scraping: {label}", ", ".join(matches[:5]), "high")
                    found_tech.append(label)

        if not found_tech:
            self.add_evidence("Scraping", "Nenhum identificador oculto encontrado.", "low")

    def _get_favicon_hash(self, url, html):
        """Calcula o Hash do ícone para buscar servidores reais no Shodan."""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            icon_link = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
            
            favicon_url = f"{url}/favicon.ico" # Fallback
            if icon_link and icon_link.get('href'):
                href = icon_link.get('href')
                if href.startswith("http"): favicon_url = href
                else: favicon_url = f"{url.rstrip('/')}/{href.lstrip('/')}"

            r = requests.get(favicon_url, verify=False, timeout=5)
            if r.status_code == 200:
                favicon_base64 = codecs.encode(r.content, 'base64')
                hash_val = mmh3.hash(favicon_base64)
                self.add_evidence("Favicon Hash", str(hash_val), "high")
                # Link útil para o analista
                self.add_evidence("Shodan Dork", f"http.favicon.hash:{hash_val}", "high")
        except:
            pass

    def _check_virustotal(self, ip, key):
        """Consulta rápida de reputação (Free API)."""
        try:
            headers = {"x-apikey": key}
            r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=5)
            if r.status_code == 200:
                stats = r.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                if malicious > 0:
                    self.add_evidence("VirusTotal", f"⚠️ DETECTADO como malicioso por {malicious} motores.", "high")
                else:
                    self.add_evidence("VirusTotal", "✅ IP Limpo (0 detecções).", "medium")
        except:
            pass