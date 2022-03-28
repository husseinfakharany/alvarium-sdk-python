from urllib.request import Request
from alvarium.contracts.config import SdkInfo
from alvarium.sign.contracts import SignInfo, SignType
from .interfaces import Annotator, RequestHandler
from alvarium.contracts.annotation import AnnotationType
from .exceptions import AnnotatorException, RequestHandlerException
from .mock import MockAnnotator
from .tpm import TpmAnnotator
from .pki import PkiAnnotator
from .source import SourceAnnotator
from .tls import TlsAnnotator


class AnnotatorFactory():
    """A factory that provides multiple implementations of the Annotator interface"""

    def get_annotator(self, kind: AnnotationType, sdk_info: SdkInfo) -> Annotator:

        if kind == AnnotationType.MOCK:
            return MockAnnotator(hash=sdk_info.hash.type, signature=sdk_info.signature, kind=kind)
        elif kind == AnnotationType.TPM:
            return TpmAnnotator(hash=sdk_info.hash.type, sign_info=sdk_info.signature)
        elif kind == AnnotationType.SOURCE:
            return SourceAnnotator(hash=sdk_info.hash.type, sign_info=sdk_info.signature)
        elif kind == AnnotationType.TLS:
            return TlsAnnotator(hash=sdk_info.hash.type, signature=sdk_info.signature)
        elif kind == AnnotationType.PKI:
            return PkiAnnotator(hash=sdk_info.hash.type, sign_info=sdk_info.signature)
        elif kind == AnnotationType.HTTPPKI:
            pass
        else:
            raise AnnotatorException("Annotator type is not supported")
            

class RequestHandlerFactory():

    def getRequestHandler(request: Request, keys: SignInfo) -> RequestHandler:
        if keys.private.type == SignType.ED25519:
            pass
        else:
            raise RequestHandlerException("Key type is not supported")
