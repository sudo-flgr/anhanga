class PixForensics:
    def __init__(self, raw_payload):
        self.raw_payload = raw_payload.strip().strip("'").strip('"')
        self.parsed_data = {}

    def parse_tlv(self, data):
        """Lê a estrutura Tag-Length-Value padrão EMV."""
        i = 0
        result = {}
        while i < len(data):
            tag_id = data[i:i+2]
            i += 2
            
            try:
                length_str = data[i:i+2]
                if not length_str: break 
                length = int(length_str)
            except ValueError:
                break 
            
            i += 2 
            
            value = data[i:i+length]
            i += length
            
            result[tag_id] = value
        return result

    def analyze(self):
        """Executa a extração de inteligência"""
        root_data = self.parse_tlv(self.raw_payload)
        
        intelligence = {
            "merchant_name": root_data.get("59", "DESCONHECIDO"),
            "merchant_city": root_data.get("60", "DESCONHECIDO"),
            "txid": "***", 
            "pix_key": "*** NÃO ENCONTRADA ***"
        }

        if "26" in root_data:
            merchant_account_info = root_data["26"]
            nested_data = self.parse_tlv(merchant_account_info)
            
            if "01" in nested_data:
                intelligence["pix_key"] = nested_data["01"]
            else:
                clean_key = merchant_account_info.replace("0014br.gov.bcb.pix", "")
                intelligence["pix_key"] = clean_key

        if "62" in root_data:
            additional_data = self.parse_tlv(root_data["62"])
            if "05" in additional_data:
                intelligence["txid"] = additional_data["05"]

        self.parsed_data = intelligence
        return intelligence