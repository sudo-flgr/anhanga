import mmh3
import requests
import codecs
import urllib3
import shodan
import socket
import whois 
from bs4 import BeautifulSoup
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class InfraHunter:
    def __init__(self, url):
        self.raw_url = url
        if "://" in url:
            self.domain = url.split("://")[1].split("/")[0]
            self.url = url
        else:
            self.domain = url.split("/")[0]
            self.url = f"https://{url}"

    def resolve_ip(self):
        try:
            return socket.gethostbyname(self.domain)
        except:
            return None

    def get_favicon_hash(self):
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        icon_url = None
        try:
            try:
                r = requests.get(self.url, headers=headers, verify=False, timeout=5)
                soup = BeautifulSoup(r.content, 'html.parser')
                icon_link = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
                if icon_link and icon_link.get('href'):
                    icon_url = urljoin(self.url, icon_link.get('href'))
            except: pass
            
            if not icon_url: icon_url = f"{self.url.rstrip('/')}/favicon.ico"

            r = requests.get(icon_url, headers=headers, verify=False, timeout=8)
            if r.status_code == 200:
                favicon_base64 = codecs.encode(r.content, 'base64')
                hash_val = mmh3.hash(favicon_base64)
                return hash_val, f"https://www.shodan.io/search?query=http.favicon.hash%3A{hash_val}"
            return None, None
        except: return None, None

class WhoisIntel:
    """Consulta dados de Registro de Domínio (O 'RG' do site)."""
    def get_whois(self, domain):
        try:
            w = whois.whois(domain)
            
            def clean(val):
                if isinstance(val, list): return str(val[0])
                return str(val) if val else "N/A"

            return {
                "registrar": clean(w.registrar),
                "creation_date": clean(w.creation_date),
                "emails": str(w.emails) if w.emails else "N/A",
                "org": clean(w.org),
                "name": clean(w.name),
                "status": "Sucesso"
            }
        except Exception as e:
            return {"status": "Erro", "error": str(e)}

class IPGeo:
    def get_data(self, ip):
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,isp,org,as", timeout=5)
            if r.status_code == 200 and r.json().get('status') == 'success':
                data = r.json()
                return f"{data['isp']} ({data['country']}) - {data['as']}"
        except: pass
        return "Dados Indisponíveis"

class VirusTotalIntel:
    def __init__(self, api_key):
        self.key = api_key
        self.base = "https://www.virustotal.com/api/v3/ip_addresses"

    def analyze_ip(self, ip):
        if not self.key: return None
        headers = {"x-apikey": self.key}
        try:
            r = requests.get(f"{self.base}/{ip}", headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                total_bad = stats.get('malicious', 0) + stats.get('suspicious', 0)
                
                verdict = "✅ LIMPO"
                if total_bad > 0: verdict = f"⚠️ SUSPEITO ({total_bad} detectções)"
                if total_bad > 5: verdict = f"🚨 MALICIOSO ({total_bad} detectções)"
                
                return {
                    "verdict": verdict,
                    "owner": data.get('as_owner', 'N/A'),
                    "country": data.get('country', 'N/A')
                }
            elif r.status_code == 401: return {"error": "Key Inválida"}
            elif r.status_code == 429: return {"error": "Limite Excedido"}
        except Exception as e: return {"error": str(e)}
        return None

class CertificateHunter:
    def get_subdomains(self, domain):
        try:
            r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
            if r.status_code == 200:
                subs = set()
                for entry in r.json():
                    name_val = entry.get('name_value', '')
                    for s in name_val.split('\n'):
                        if s and '*' not in s: subs.add(s.lower())
                return list(subs)
        except: pass
        return []

class ShodanIntel:
    def __init__(self, api_key):
        self.api = shodan.Shodan(api_key)

    def enrich_target(self, ip, favicon_hash=None):
        intel = {"strategy": "N/A", "data": [], "error": None}
        if favicon_hash:
            try:
                res = self.api.search(f"http.favicon.hash:{favicon_hash}", limit=5)
                intel["strategy"] = "Hash Search"
                intel["data"] = res['matches']
                return intel
            except: pass
        if ip:
            try:
                host = self.api.host(ip)
                intel["strategy"] = "IP Lookup"
                intel["data"] = [host]
                return intel
            except Exception as e: intel["error"] = str(e)
        return intel