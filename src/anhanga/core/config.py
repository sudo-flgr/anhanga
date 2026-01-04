# Arquivo: anhanga/core/config.py
import json
import os

# Points to root/config.json assuming src layout
CONFIG_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../config.json"))

class ConfigManager:
    def __init__(self):
        self.file = CONFIG_FILE
        self._load()

    def _load(self):
        if not os.path.exists(self.file):
            self.data = {"shodan_key": None, "virustotal_key": None}
            self._save()
        else:
            try:
                with open(self.file, 'r') as f:
                    self.data = json.load(f)
            except:
                self.data = {}

    def _save(self):
        with open(self.file, 'w') as f:
            json.dump(self.data, f, indent=4)

    def set_key(self, service, key):
        self.data[f"{service}_key"] = key
        self._save()

    def get_key(self, service):
        return self.data.get(f"{service}_key")