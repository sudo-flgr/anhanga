# Arquivo: anhanga/modules/crypto/hunter.py
import re
import requests
from anhanga.core.base import AnhangáModule

class CryptoModule(AnhangáModule):
    def __init__(self):
        super().__init__()
        self.meta = {
            "name": "CryptoHunter",
            "description": "Rastreio de Criptoativos (BTC/ETH/TRON)",
            "version": "2.0"
        }

    def run(self, text: str) -> bool:
        """
        Busca endereços de criptomoedas em um texto (ou recebe o endereço direto).
        """
        found = False
        
        # 1. Regex Patterns (Padrões de Endereço)
        patterns = {
            "BTC (Legacy)": r"\b(1[a-km-zA-Z1-9]{25,34})\b",
            "BTC (Segwit)": r"\b(bc1[a-zA-Z0-9]{35,59})\b",
            "ETH/EVM": r"\b(0x[a-fA-F0-9]{40})\b",
            "TRON (USDT)": r"\b(T[a-zA-Z0-9]{33})\b"
        }

        # 2. Varredura
        for net, pattern in patterns.items():
            matches = re.findall(pattern, text)
            for wallet in matches:
                found = True
                self._analyze_wallet(wallet, net)

        if not found:
            self.add_evidence("Info", "Nenhuma carteira cripto detectada no alvo.", "low")
            return False
            
        return True

    def _analyze_wallet(self, wallet, network):
        """Enriquece o dado da carteira com APIs públicas."""
        
        # Dados básicos
        evidence_content = f"Endereço: {wallet}\nRede: {network}"
        
        # Consultas de Saldo (Free APIs - Best Effort)
        balance_info = "Consulta API Indisponível (Ver Link)"
        
        try:
            if "BTC" in network:
                # Blockchain.com API (Free)
                r = requests.get(f"https://blockchain.info/rawaddr/{wallet}", timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    total_rx = data.get('total_received', 0) / 100000000
                    final_bal = data.get('final_balance', 0) / 100000000
                    balance_info = f"💰 Saldo: {final_bal} BTC\n📥 Total Recebido: {total_rx} BTC"
                    
        except Exception:
            balance_info = "Erro na consulta online (API Rate Limit)"

        # Adiciona ao relatório
        full_report = f"{balance_info}\n\n🔗 Explorador:\n{self._get_explorer_link(wallet, network)}"
        self.add_evidence(f"Carteira Detectada ({network})", full_report, "high")

    def _get_explorer_link(self, wallet, network):
        if "BTC" in network: return f"https://www.blockchain.com/explorer/addresses/btc/{wallet}"
        if "ETH" in network: return f"https://etherscan.io/address/{wallet}"
        if "TRON" in network: return f"https://tronscan.org/#/address/{wallet}"
        return "N/A"