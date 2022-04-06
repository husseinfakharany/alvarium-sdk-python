import requests
from alvarium.sign.contracts import SignInfo, SignType
from .interfaces import RequestHandler
from .exceptions import RequestHandlerException

class RequestHandlerFactory():

    def getRequestHandler(request: requests, keys: SignInfo) -> RequestHandler:
        if keys.private.type == SignType.ED25519:
            pass
        else:
            raise RequestHandlerException("Key type is not supported")
