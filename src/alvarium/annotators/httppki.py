import socket
import os

from alvarium.sign.exceptions import SignException
from alvarium.sign.factories import SignProviderFactory
from alvarium.contracts.annotation import Annotation, AnnotationType
from alvarium.hash.contracts import HashType
from alvarium.sign.contracts import KeyInfo, SignInfo, KeyInfo, SignType
from alvarium.utils import PropertyBag
from .contracts import Signable
from .utils import derive_hash, sign_annotation
from .interfaces import Annotator
from .exceptions import AnnotatorException
from alvarium.annotators.handler.base import parseSignature
class HttpPkiAnnotator(Annotator):
    def __init__(self, hash: HashType, sign_info: SignInfo) -> None:
        self.hash = hash
        self.sign_info = sign_info
        self.kind = AnnotationType.HTTPPKI


    def _verify_signature(self, key: KeyInfo, signable: Signable) -> bool:
        """ Responsible for verifying the signature, returns true if the verification passed
            , false otherwise."""
        
        if(len(signable.signature) == 0):
            return False

        try:
            sign_provider = SignProviderFactory().get_provider(sign_type=key.type)
        except SignException as e:
            raise AnnotatorException("cannot get sign provider.", e)
        
        if(not os.path.isfile(key.path)):
            raise AnnotatorException("Cannot read Public Key File.")

        with open(key.path, 'r') as file:
            pub_key = file.read()
            
            try:
                hex_pub_key = bytes.fromhex(pub_key)
            except Exception as e:
                raise AnnotatorException("Cannot read Public Key File.")

            try:
                hex_signature = bytes.fromhex(signable.signature)
            except:
                raise AnnotatorException("Invalid siganture syntax: It is not in hex.")


    
            return  sign_provider.verify(key=hex_pub_key, 
                                        content=bytes(signable.seed, 'utf-8'),
                                        signed=hex_signature)



    def execute(self, data: bytes, ctx: PropertyBag = None) -> Annotation:
        key = derive_hash(hash=self.hash, data=data)
        host: str = socket.gethostname()

        # call parser on request
        req = ctx.get_property('request')

        try:
            parsed_data = parseSignature(req)
        except ParserException as e:
            raise AnnotatorException("cannot parse the http request.", e)



        # create Signable object
        signable = Signable(parsed_data.seed, parsed_data.signature)



        try:
            signType = SignType(parsed_data.algorithm)
        except Exception as e:
            raise AnnotatorException("Invalid key type specified" + str(parsed_data.algorithm))

        k = KeyInfo(signType, parsed_data.keyid)


        try:
            is_satisfied = self._verify_signature(k, signable)
        except Exception as e:
            raise AnnotatorException(str(e))
        

        annotation = Annotation(key=key, host=host, hash=self.hash, kind=self.kind, is_satisfied=is_satisfied)
        

        signature: str = sign_annotation(key_info=self.sign_info.private, annotation=annotation)
        annotation.signature = signature
        return annotation