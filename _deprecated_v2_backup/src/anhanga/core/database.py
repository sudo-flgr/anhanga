# Arquivo: anhanga/core/database.py
import json
import os
from datetime import datetime

DB_FILE = "investigation_current.json"

class CaseManager:
    def __init__(self):
        self.db_file = DB_FILE
        self._load_db()

    def _load_db(self):
        if not os.path.exists(self.db_file):
            self.data = {
                "meta": {"start": str(datetime.now()), "case_name": "OP_DEFAULT"},
                "entities": [],
                "infra": [],
                "relations": [] # AQUI MORA A VERDADE
            }
            self._save_db()
        else:
            try:
                with open(self.db_file, 'r', encoding='utf-8') as f:
                    self.data = json.load(f)
            except:
                # Se corromper, recria (Fail-safe)
                os.remove(self.db_file)
                self._load_db()

    def _save_db(self):
        with open(self.db_file, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=4, ensure_ascii=False)

    def add_entity(self, name, doc, role="suspect"):
        # Evita duplicatas pelo Documento
        for ent in self.data["entities"]:
            if ent["document"] == doc: return False
        
        self.data["entities"].append({
            "name": name, "document": doc, "role": role,
            "timestamp": str(datetime.now())
        })
        self._save_db()
        return True

    def add_infra(self, domain, ip="Pending", extra_info=""):
        # Evita duplicatas pelo Domínio
        for inf in self.data["infra"]:
            if inf["domain"] == domain: return False
                
        self.data["infra"].append({
            "domain": domain, "ip": ip, "info": extra_info,
            "timestamp": str(datetime.now())
        })
        self._save_db()
        return True

    def add_relation(self, source_id, target_id, type_rel):
        """Cria um vínculo FORENSE entre dois nós."""
        # Verifica se já existe para não poluir o grafo
        for rel in self.data["relations"]:
            if rel["source"] == source_id and rel["target"] == target_id:
                return
        
        self.data["relations"].append({
            "source": source_id,
            "target": target_id,
            "type": type_rel,
            "timestamp": str(datetime.now())
        })
        self._save_db()

    def get_full_case(self):
        return self.data

    def nuke(self):
        if os.path.exists(self.db_file):
            os.remove(self.db_file)
        self._load_db()# Arquivo: anhanga/core/database.py
import json
import os
from datetime import datetime

DB_FILE = "investigation_current.json"

class CaseManager:
    def __init__(self):
        self.db_file = DB_FILE
        self._load_db()

    def _load_db(self):
        if not os.path.exists(self.db_file):
            self.data = {
                "meta": {"start": str(datetime.now()), "case_name": "OP_DEFAULT"},
                "entities": [],
                "infra": [],
                "relations": [] # AQUI MORA A VERDADE
            }
            self._save_db()
        else:
            try:
                with open(self.db_file, 'r', encoding='utf-8') as f:
                    self.data = json.load(f)
            except:
                # Se corromper, recria (Fail-safe)
                os.remove(self.db_file)
                self._load_db()

    def _save_db(self):
        with open(self.db_file, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=4, ensure_ascii=False)

    def add_entity(self, name, doc, role="suspect"):
        # Evita duplicatas pelo Documento
        for ent in self.data["entities"]:
            if ent["document"] == doc: return False
        
        self.data["entities"].append({
            "name": name, "document": doc, "role": role,
            "timestamp": str(datetime.now())
        })
        self._save_db()
        return True

    def add_infra(self, domain, ip="Pending", extra_info=""):
        # Evita duplicatas pelo Domínio
        for inf in self.data["infra"]:
            if inf["domain"] == domain: return False
                
        self.data["infra"].append({
            "domain": domain, "ip": ip, "info": extra_info,
            "timestamp": str(datetime.now())
        })
        self._save_db()
        return True

    def add_relation(self, source_id, target_id, type_rel):
        """Cria um vínculo FORENSE entre dois nós."""
        # Verifica se já existe para não poluir o grafo
        for rel in self.data["relations"]:
            if rel["source"] == source_id and rel["target"] == target_id:
                return
        
        self.data["relations"].append({
            "source": source_id,
            "target": target_id,
            "type": type_rel,
            "timestamp": str(datetime.now())
        })
        self._save_db()

    def get_full_case(self):
        return self.data

    def nuke(self):
        if os.path.exists(self.db_file):
            os.remove(self.db_file)
        self._load_db()