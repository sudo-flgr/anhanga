import re
from typing import List, Dict, Any
from anhanga.core.base import AnhangáModule

class WalletHunter(AnhangáModule):
    def __init__(self):
        super().__init__()
        self.meta = {
            "name": "Wallet Hunter v2.2 - Strict Anti-Hallucination",
            "description": "Crypto Wallet Extractor with CamelCase Filters and Entropy Checks",
            "version": "2.2"
        }
        # Keywords that indicate a financial context
        self.context_keywords = [
            "deposit", "deposito", "depósito",
            "address", "endereço", "wallet", "carteira",
            "send", "enviar", "pay", "pagar",
            "usdt", "btc", "eth", "tron", "sol", "bitcoin", "solana",
            "copy", "copiar", "erc20", "trc20", "bep20", "network", "rede"
        ]

        # Common English words/Code terms that often trigger false positives
        self.blacklist_words = [
            "success", "description", "part", "payment", "bank", "account",
            "edit", "delete", "update", "create", "new", "method", "type",
            "status", "message", "error", "code", "token", "auth", "session",
            "user", "id", "name", "email", "password", "key", "value",
            "params", "query", "body", "header", "footer", "div", "span",
            "class", "style", "script", "function", "var", "let", "const"
        ]

    def run(self, html: str) -> List[Dict[str, Any]]:
        return self.scan_html(html)

    def scan_html(self, html: str) -> List[Dict[str, Any]]:
        found_wallets = []
        
        # Regex Patterns
        patterns = {
            "BTC (Legacy)": r"\b(1[a-km-zA-Z1-9]{25,34})\b",
            "BTC (Segwit)": r"\b(bc1[a-zA-Z0-9]{35,59})\b",
            "ETH/EVM": r"\b(0x[a-fA-F0-9]{40})\b",
            "TRON (TRC20)": r"\b(T[a-zA-Z0-9]{33})\b",
            # Strict Solana: Base58 (no 0,O,I,l), 32-44 chars.
            "SOL": r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b"
        }
        
        for coin, pattern in patterns.items():
            for match in re.finditer(pattern, html):
                wallet_address = match.group(0) # Use group 0 as some patterns don't have groups
                start, end = match.span()
                
                # --- FILTER 1: CamelCase / Code Variable Check ---
                # A real wallet is random. It shouldn't look like "PaymentSuccessMessage"
                # If it has a lowercase letter followed by an uppercase letter multiple times, suspicious.
                if re.search(r'[a-z]+[A-Z]', wallet_address):
                    continue

                # --- FILTER 2: Entropy / Blacklist Check ---
                # Check for common words inside the string (case insensitive)
                lowered_wallet = wallet_address.lower()
                if any(word in lowered_wallet for word in self.blacklist_words):
                    continue
                
                # Specific check for Solana: Must contain at least one number
                if coin == "SOL" and not any(char.isdigit() for char in wallet_address):
                     continue

                # --- FILTER 3: Context Validation (Strict 50 chars) ---
                if self._validate_context(html, start, end):
                    # Dedifferentiate
                    if not any(w['address'] == wallet_address for w in found_wallets):
                        found_wallets.append({
                            'coin': coin,
                            'address': wallet_address,
                            'confidence': 'Alta'
                        })
                        
        return found_wallets

    def _validate_context(self, html: str, start: int, end: int, window: int = 50) -> bool:
        snippet_start = max(0, start - window)
        snippet_end = min(len(html), end + window)
        snippet = html[snippet_start:snippet_end].lower()
        
        return any(keyword in snippet for keyword in self.context_keywords)
