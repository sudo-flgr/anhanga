# Arquivo: anhanga/modules/infra/hunter.py
import mmh3
import requests
import codecs
import urllib3
import shodan
import socket
from bs4 import BeautifulSoup
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class InfraHunter:
    def __init__(self, url):
        self.raw_url = url
        # Tratamento para garantir domínio limpo e URL completa
        if "://" in url:
            self.domain = url.split("://")[1].split("/")[0]
            self.url = url
        else:
            self.domain = url.split("/")[0]
            self.url = f"https://{url}"

    def resolve_ip(self):
        """Resolve o IP atual do domínio."""
        try:
            ip = socket.gethostbyname(self.domain)
            return ip
        except:
            return None

    def get_favicon_hash(self):
        """Baixa favicon e calcula hash."""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Referer': 'https://www.google.com/'
        }
        
        icon_url = None
        try:
            # Tenta extrair do HTML
            try:
                response = requests.get(self.url, headers=headers, verify=False, timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.content, 'html.parser')
                    icon_link = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
                    if icon_link and icon_link.get('href'):
                        icon_url = urljoin(self.url, icon_link.get('href'))
            except:
                pass
            
            if not icon_url:
                icon_url = f"{self.url.rstrip('/')}/favicon.ico"

            # Baixa e calcula
            r = requests.get(icon_url, headers=headers, verify=False, timeout=10)
            if r.status_code == 200:
                favicon_base64 = codecs.encode(r.content, 'base64')
                hash_val = mmh3.hash(favicon_base64)
                return hash_val, f"https://www.shodan.io/search?query=http.favicon.hash%3A{hash_val}"
            return None, None
        except:
            return None, None

class CertificateHunter:
    """Busca subdomínios usando Certificate Transparency (CRT.sh) - Gratuito"""
    def get_subdomains(self, domain):
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            # print(f"[DEBUG] Consultando CRT.sh para {domain}...") 
            r = requests.get(url, timeout=20)
            if r.status_code == 200:
                data = r.json()
                # Filtra duplicatas e limpa os nomes
                subs = set()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    # Separa múltiplas entradas por linha
                    for sub in name_value.split('\n'):
                        if sub and '*' not in sub:
                            subs.add(sub.lower())
                return list(subs)
            return []
        except Exception as e:
            return [f"Erro CRT: {str(e)}"]

class ShodanIntel:
    def __init__(self, api_key):
        self.api = shodan.Shodan(api_key)

    def enrich_target(self, ip, favicon_hash=None):
        """
        Estratégia Híbrida:
        1. Tenta buscar pelo Hash (Ideal).
        2. Se der 403 (Plano Free), consulta o HOST IP direto (Permitido).
        """
        intel = {
            "strategy": "Unknown",
            "data": [],
            "error": None
        }

        # TENTATIVA 1: Busca Global por Hash (Melhor cenário: Bypass)
        if favicon_hash:
            try:
                query = f"http.favicon.hash:{favicon_hash}"
                results = self.api.search(query, limit=5)
                intel["strategy"] = "Hash Search (Global)"
                for match in results['matches']:
                    intel["data"].append(self._parse_match(match))
                return intel
            except shodan.APIError as e:
                # Se for erro de plano (403), ignoramos e vamos para o Plano B
                if "forbidden" not in str(e).lower() and "access denied" not in str(e).lower():
                    intel["error"] = str(e)
                    return intel
        
        # TENTATIVA 2: Consulta Direta de Host (Plano B: Reconhecimento do Alvo)
        # O plano Free permite consultar IPs específicos (/shodan/host/{ip})
        if ip:
            try:
                host_info = self.api.host(ip)
                intel["strategy"] = "Direct Host Lookup (IP Target)"
                intel["data"].append({
                    "ip": host_info.get('ip_str'),
                    "org": host_info.get('org', 'N/A'),
                    "portas": host_info.get('ports', []),
                    "pais": host_info.get('country_name', 'N/A'),
                    "vulns": list(host_info.get('vulns', []))
                })
                return intel
            except Exception as e:
                intel["error"] = f"Falha na consulta de Host: {str(e)}"
                return intel
        
        intel["error"] = "Sem dados suficientes para consulta Shodan (Hash 403 e Sem IP)."
        return intel

    def _parse_match(self, match):
        return {
            "ip": match.get('ip_str'),
            "org": match.get('org', 'N/A'),
            "portas": match.get('port', []),
            "pais": match.get('location', {}).get('country_name', 'N/A'),
            "vulns": list(match.get('vulns', {}).keys()) if 'vulns' in match else []
        }