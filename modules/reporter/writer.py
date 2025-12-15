import ollama
import json
from datetime import datetime

class AIReporter:
    def __init__(self):
        self.model = "phi3"  

    def generate_dossier(self, case_data):
        """
        Usa o Ollama para transformar o JSON técnico em um Relatório Policial/Executivo.
        """
        evidence_summary = json.dumps(case_data, indent=2, ensure_ascii=False)
        
        prompt = f"""
        VOCÊ É UM ANALISTA DE INTELIGÊNCIA CIBERNÉTICA SÊNIOR DA SWAT.
        Sua missão é escrever um RELATÓRIO TÉCNICO FINAL com base nas evidências JSON abaixo.

        EVIDÊNCIAS COLETADAS:
        {evidence_summary}

        DIRETRIZES DE ESCRITA:
        1. Comece com um "RESUMO EXECUTIVO" (Quem é o alvo, qual o site, qual o risco).
        2. Crie uma seção "ANÁLISE FINANCEIRA": Detalhe o recebedor do Pix, se é empresa ou pessoa, e suspeitas.
        3. Crie uma seção "INFRAESTRUTURA": Fale sobre o IP, Hospedagem (Cloudflare?), Data de Criação do domínio (Whois) e Riscos de Segurança.
        4. Crie uma seção "VÍNCULOS": Explique como o Pix se conecta ao Site.
        5. Termine com "CONCLUSÃO E RECOMENDAÇÃO": Sugira bloqueio, investigação aprofundada ou monitoramento.
        6. Use linguagem formal, direta e em Português do Brasil.
        7. NÃO invente dados. Use apenas o que está no JSON.

        Gere o relatório agora:
        """

        try:
            print("   [Thinking] O Ollama está analisando todas as evidências e escrevendo o dossiê...")
            response = ollama.chat(model=self.model, messages=[
                {'role': 'user', 'content': prompt},
            ])
            return response['message']['content']
        except Exception as e:
            return f"Erro ao gerar relatório com IA: {str(e)}"

    def save_report(self, text):
        filename = f"DOSSIE_FINAL_{datetime.now().strftime('%Y%m%d_%H%M')}.md"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# RELATÓRIO DE INTELIGÊNCIA ANHANGÁ\n\n{text}")
        return filename