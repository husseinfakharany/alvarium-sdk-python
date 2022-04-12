import datetime

from requests import Request

from alvarium.sign.contracts import SignInfo
from alvarium.sign.ed25519 import Ed25519ignProvider
from .base import parseSignature


class requestHandler():
    request: Request

    def __init__(self, request: Request) -> None:
        self.request = request

    def add_signature_headers(self, ticks: datetime, fields: list, keys: SignInfo):
        headerValue = ""
        
        for i in range(len(fields)):
            headerValue = headerValue + '"' + str(fields[i]) + '"'
            if i < len(fields) - 1:
                headerValue = headerValue + " " 

        headerValue = headerValue + ';created=' + str(int(ticks.timestamp())) + ';keyid="' + str(keys.public.path) + '";alg="' + str(keys.public.type) + '";'

        self.request.headers['Signature-Input'] = headerValue
        
        parsed = parseSignature(self.request)
        inputValue = bytes(parsed.seed, 'utf-8')
        
        p = Ed25519ignProvider() 
        
        with open(keys.private.path, 'r') as file:
            prv_hex = file.read()
            prv = bytes.fromhex(prv_hex)

        signature = p.sign(prv, inputValue)

        self.request.headers['Signature'] = str(signature)
