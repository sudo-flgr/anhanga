import crcmod
from anhanga.core.base import AnhangáModule

class PixModule(AnhangáModule):
    def __init__(self):
        super().__init__()
        self.meta = {
            "name": "Pix Forensics Decoder",
            "description": "Parser EMV/BR Code com validação CRC16 e extração recursiva",
            "version": "2.1 (Production)"
        }

    def run(self, target_pix: str) -> bool:
        raw_pix = target_pix.strip()
        
        # 1. Validação CRC16 (A prova matemática de integridade)
        if not self._verify_crc16(raw_pix):
            self.add_evidence("Integridade", "❌ CRC16 Inválido (Código corrompido ou adulterado)", "high")

        # 2. Parsing TLV (Tag-Length-Value)
        try:
            emv_data = self._parse_tlv(raw_pix)
            
            # 3. Extração Inteligente de Campos
            self._analyze_emv_data(emv_data)
            return True

        except Exception as e:
            self.add_evidence("Erro de Parsing", f"Falha ao estruturar dados EMV: {str(e)}", "high")
            return False

    def _verify_crc16(self, payload):
        """Calcula o CRC16-CCITT (0x1021) conforme norma do Banco Central."""
        try:
            # O CRC são os últimos 4 caracteres. Para validar, removemos eles e calculamos.
            # O padrão é terminar com '6304'.
            if "6304" not in payload: return False
            
            crc_pivot = payload.rfind("6304")
            data_to_check = payload[:crc_pivot+4] 
            provided_crc = payload[crc_pivot+4:]
            
            crc16_func = crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, rev=False, xorOut=0x0000)
            calculated_crc = hex(crc16_func(data_to_check.encode('utf-8')))[2:].upper().zfill(4)
            
            return calculated_crc == provided_crc
        except:
            return False

    def _parse_tlv(self, payload):
        """Lê a estrutura Tag-Length-Value recursivamente."""
        data = {}
        i = 0
        while i < len(payload):
            tag = payload[i:i+2]
            i += 2
            
            try:
                length = int(payload[i:i+2])
            except ValueError:
                break
            i += 2
            
            value = payload[i:i+length]
            i += length
            
            if tag in ["26", "62"]:
                data[tag] = self._parse_tlv(value) 
            else:
                data[tag] = value
                
        return data

    def _analyze_emv_data(self, data):
        """Transforma os IDs numéricos em inteligência legível."""
        
        if "59" in data:
            self.add_evidence("Beneficiário", data["59"], "high")
            
        if "60" in data:
            self.add_evidence("Cidade", data["60"], "medium")
            
        if "26" in data and isinstance(data["26"], dict):
            merchant_info = data["26"]
            if "01" in merchant_info:
                key = merchant_info["01"]
                key_type = "Aleatória"
                if "@" in key: key_type = "E-mail"
                elif len(key) == 11 and key.isdigit(): key_type = "CPF"
                elif len(key) == 14 and key.isdigit(): key_type = "CNPJ"
                elif len(key) > 20: key_type = "EVP (Aleatória)"
                
                self.add_evidence("Chave Pix", f"{key} ({key_type})", "high")
            
            if "02" in merchant_info:
                self.add_evidence("Descrição/Mensagem", merchant_info["02"], "medium")

        if "62" in data and isinstance(data["62"], dict):
            if "05" in data["62"]:
                self.add_evidence("ID Transação (TXID)", data["62"]["05"], "low")