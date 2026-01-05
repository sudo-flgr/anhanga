import json
import os
from urllib.parse import urlparse
from typing import Dict, Any

class BetCompliance:
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Determine path relative to this file
            base_dir = os.path.dirname(os.path.abspath(__file__))
            # Assuming src/anhanga/modules/fincrime/compliance/validator.py
            # and src/anhanga/data/bets_db.json
            # We need to go up 3 levels to src/anhanga and then into data
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(base_dir))))
            # Wait, base_dir is src/anhanga/modules/fincrime/compliance
            # up 1: fincrime
            # up 2: modules
            # up 3: anhanga
            # up 4: src
            # Actually, let's use a simpler way or the provided path structure
            # src/anhanga/modules/fincrime/compliance/validator.py
            # src/anhanga/data/bets_db.json

            # Use relative import based on expected project structure
            # from validator.py (compliance) -> fincrime -> modules -> anhanga -> data
            root_module_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(base_dir))))
            # This calculation seems fragile if executed from different places,
            # but usually reliable if installed as package.
            # However, safer to rely on 'src/anhanga' if we know the anchor.

            # Let's try to find 'src/anhanga/data/bets_db.json' relative to cwd or use relative path from this file.
            # this file: .../src/anhanga/modules/fincrime/compliance/validator.py
            # want: .../src/anhanga/data/bets_db.json

            # ../../../data/bets_db.json
            db_path = os.path.join(base_dir, "..", "..", "..", "data", "bets_db.json")

        self.db_path = os.path.abspath(db_path)
        self.whitelist = []
        self.load_db()

    def load_db(self):
        try:
            with open(self.db_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.whitelist = data.get("whitelist", [])
        except FileNotFoundError:
            # Fallback or empty if file not found (should handle error properly in production)
            print(f"Warning: Database file not found at {self.db_path}")
            self.whitelist = []
        except Exception as e:
            print(f"Error loading database: {e}")
            self.whitelist = []

    def check_compliance(self, url: str) -> Dict[str, Any]:
        """
        Check if the domain exists in whitelist.
        If Found: Return status: AUTHORIZED, auth_type: (from JSON), operator: (from JSON).
        If Not Found: Check if ends with .bet.br. If yes -> UNLICENSED_SOVEREIGN. If no -> ILLEGAL_FOREIGN.
        """
        # Normalize URL to domain
        if not url.startswith(("http://", "https://")):
            # If the user passed something like "HTTPS://ZeroUm.Bet", urlparse might fail if we just prepend http://
            # But "HTTPS://ZeroUm.Bet" is already having a scheme if we lowercase it.
            # However, `urlparse` is case sensitive for scheme detection sometimes? No.
            # If input is "HTTPS://ZeroUm.Bet", urlparse("HTTPS://ZeroUm.Bet").scheme is "https" (case insensitive usually)

            # If it doesn't start with http/https, assume it's a domain
            if "://" not in url:
                url = "http://" + url

        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]

        # Check whitelist
        for entry in self.whitelist:
            for whitelisted_domain in entry.get("domains", []):
                # Normalize whitelisted domain
                whitelisted_domain = whitelisted_domain.lower()
                # Check exact match or subdomain
                if domain == whitelisted_domain or domain.endswith("." + whitelisted_domain):
                    return {
                        "status": "AUTHORIZED",
                        "auth_type": entry.get("auth_type"),
                        "operator": entry.get("operator"),
                        "brand": entry.get("brands", ["Unknown"])[0] # Taking first brand as representative
                    }

        # Not found in whitelist
        if domain.endswith(".bet.br"):
            return {
                "status": "UNLICENSED_SOVEREIGN",
                "reason": "Domain ends with .bet.br but is not in whitelist"
            }
        else:
            return {
                "status": "ILLEGAL_FOREIGN",
                "reason": "Foreign domain not in whitelist"
            }
