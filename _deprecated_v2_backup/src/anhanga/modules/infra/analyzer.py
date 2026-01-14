import requests
from bs4 import BeautifulSoup
import ollama

class ContractAnalyzer:
    def __init__(self, url):
        self.url = url
        if not self.url.startswith("http"):
            self.url = f"http://{self.url}"

    def extract_text(self):
        """Baixa o site e limpa o HTML para sobrar só o texto jurídico."""
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        try:
            response = requests.get(self.url, headers=headers, timeout=10)
            if response.status_code != 200:
                return None
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            for script in soup(["script", "style", "nav", "footer"]):
                script.extract()
            
            text = soup.get_text(separator=' ')
            
            return " ".join(text.split())[:6000]
        except:
            return None
    def analyze_shodan_data(self, shodan_json):
        """
        Envia os dados técnicos do Shodan para o Phi-3 interpretar.
        """
        prompt = f"""
        Você é um especialista em Cibersegurança e Red Teaming.
        Analise os dados brutos abaixo coletados do Shodan sobre a infraestrutura de um site de apostas.
        
        Dados Técnicos:
        {shodan_json}
        
        Sua missão:
        1. Identificar o Provedor de Hospedagem (Hosting).
        2. Listar portas críticas abertas (ex: 22, 3306, 8080).
        3. Dizer se há risco de segurança óbvio.
        4. Responda em Português de forma resumida e direta (Bullet points).
        """

        try:
            response = ollama.chat(model='phi3', messages=[
                {'role': 'user', 'content': prompt},
            ])
            return response['message']['content']
        except Exception as e:
            return f"Erro na IA: {str(e)}"

    def analyze_legal_entity(self):
        """Envia o texto para o Ollama (Phi-3) extrair a capivara."""
        text_content = self.extract_text()
        
        if not text_content:
            return {"erro": "Não foi possível ler o site."}

        prompt = f"""
        Analise o texto abaixo extraído de um site de apostas.
        Sua missão é encontrar a Entidade Legal responsável.
        
        Extraia APENAS estes 3 campos em formato curto:
        1. Entidade/Empresa 
        2. Licença/Registro 
        3. Jurisdição/País

        Se não encontrar, responda "Não identificado".
        
        Texto:
        {text_content}
        """

        try:
            response = ollama.chat(model='phi3', messages=[
                {'role': 'user', 'content': prompt},
            ])
            return response['message']['content']
        except Exception as e:
            return {"erro": f"Erro na IA: {str(e)} (Verifique se o Ollama está rodando)"}