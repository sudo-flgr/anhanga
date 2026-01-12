import re
import crcmod
from typing import List, Dict, Any, Optional
from anhanga.core.base import AnhangáModule

class PixIntelligence(AnhangáModule):
    def __init__(self):
        super().__init__()
        self.meta = {
            "name": "Pix Intelligence v3",
            "description": "Advanced PIX Decoder with EMV Parsing and CRC16 Validation",
            "version": "3.0"
        }

    def run(self, html: str) -> Dict[str, Any]:
        """
        Main entry point for PIX analysis.
        Returns a dictionary with extracted data and flags.
        """
        results = {
            "raw_codes": [],
            "decoded": [],
            "risk_flags": []
        }
        
        # 1. Extract
        raw_codes = self.extract_from_html(html)
        results["raw_codes"] = raw_codes
        
        # 2. Decode & Validate
        for code in raw_codes:
            decoded = self.decode_emv(code)
            if decoded:
                results["decoded"].append(decoded)
                
        return results

    def extract_from_html(self, html: str) -> List[str]:
        """
        Extracts raw Copy-Paste PIX strings (EMV QRCPS) using Regex.
        Pattern: Starts with 000201 and contains BR.GOV.BCB.PIX
        """
        # Regex explanation:
        # \b000201: Starts with payload format indicator
        # [\w\.\-\$\%\@\s]+: Permissible characters (very broad to catch dirty inputs)
        # BR\.GOV\.BCB\.PIX: Mandatory domain
        # .+?6304[A-F0-9]{4}: Ends with CRC tag (6304) and 4 hex chars
        
        # Updated Regex: More permissive to capture various EMV content characters
        # Matches: Start (000201) ... Domain ... End (6304 + 4 hex)
        pattern = r"(000201.+?BR\.GOV\.BCB\.PIX.+?6304[A-F0-9]{4})"
        matches = re.findall(pattern, html, re.IGNORECASE | re.DOTALL)
        
        # Clean up whitespace/newlines from matches
        # CAUTION: Do NOT remove spaces " " as they are valid within Name/City fields.
        cleaned_matches = [m.replace("\n", "").replace("\r", "").replace("\t", "") for m in matches]
        return list(set(cleaned_matches))

    def decode_emv(self, payload: str) -> Optional[Dict[str, Any]]:
        """
        Parses the EMV TLV structure and extracts critical IDs.
        """
        if not self._verify_crc16(payload):
            self.add_evidence("Integridade", "CRC16 Inválido", "high")
            # We continue parsing even if CRC is bad, but flag it.
            
        data = self._parse_tlv(payload)
        
        extracted = {
            "full_payload": payload,
            "beneficiary_name": data.get("59"),
            "city": data.get("60"),
            "amount": data.get("54"),
            "txid": None,
            "pix_key": None
        }
        
        # Extract TxID (05 inside 62)
        if "62" in data and isinstance(data["62"], dict) and "05" in data["62"]:
            extracted["txid"] = data["62"]["05"]
            
        # Extract PIX Key (01 inside 26)
        if "26" in data and isinstance(data["26"], dict) and "01" in data["26"]:
            extracted["pix_key"] = data["26"]["01"]
            
        return extracted

    def _verify_crc16(self, payload: str) -> bool:
        """Calculates CRC16-CCITT (0x1021)."""
        try:
            if "6304" not in payload: return False
            
            # Use the last occurrence of 6304 to split
            crc_pivot = payload.rfind("6304")
            data_to_check = payload[:crc_pivot+4] 
            provided_crc = payload[crc_pivot+4:]
            
            if len(provided_crc) != 4: return False
            
            crc16_func = crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, rev=False, xorOut=0x0000)
            calculated_crc = hex(crc16_func(data_to_check.encode('utf-8')))[2:].upper().zfill(4)
            
            return calculated_crc == provided_crc.upper()
        except Exception:
            return False

    def _parse_tlv(self, payload: str) -> Dict[str, Any]:
        """Recursive TLV Parser."""
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
            
            # Tags 26 (Merchant Account Info) and 62 (Additional Data Field) contain nested TLV
            if tag in ["26", "62"]:
                data[tag] = self._parse_tlv(value) 
            else:
                data[tag] = value
                
        return data