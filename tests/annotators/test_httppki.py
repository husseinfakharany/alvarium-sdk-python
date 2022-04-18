import unittest
import json
import datetime

from requests import Request

from alvarium.annotators.factories import AnnotatorFactory
from alvarium.contracts.annotation import Annotation, AnnotationType
from alvarium.contracts.config import SdkInfo
from alvarium.hash.contracts import HashInfo, HashType
from alvarium.sign.contracts import KeyInfo, SignInfo, SignType
from alvarium.annotators.contracts import Signable
from alvarium.annotators.handler.contracts import DerivedComponent
from alvarium.annotators.handler.ed25519 import Ed25519RequestHandler
from alvarium.utils import ImmutablePropertyBag

class HTTPPKITest(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(HTTPPKITest, self).__init__( *args, **kwargs)

        kind = AnnotationType.HTTPPKI
        hash = HashType.SHA256
        pub_key = KeyInfo(type=SignType.ED25519, path="./tests/sign/keys/public.key")
        priv_key = KeyInfo(type=SignType.ED25519, path="./tests/sign/keys/private.key")
        sdk_info = SdkInfo(annotators=[], hash=HashInfo(type=hash), stream=None, 
                            signature=SignInfo(public=pub_key, private=priv_key))
        self.annotator = AnnotatorFactory().get_annotator(kind=kind, sdk_info=sdk_info)
        self.request = self.buildRequest(sdk_info.signature)




    def test_httppki_execute_valid_test(self):

        ctx = ImmutablePropertyBag({'request': self.request})

        annotation = self.annotator.execute(data=bytes(self.request.json, 'utf-8'), ctx=ctx)
        
        self.assertTrue(annotation.is_satisfied)
        self.assertEqual(type(annotation), Annotation)


    def test_httppki_execute_invalid_algorithm_test(self):

        modified_request = self.request
        modified_request.headers['Signature-Input'] = '\"@method\" \"@path\" \"@authority\" \"Content-Type\" \"Content-Length\";created=1646146637;keyid=\"public.key\";alg=\"invalid\"'
        ctx = ImmutablePropertyBag({'request': modified_request})

        try:
            annotation = self.annotator.execute(data=bytes(modified_request.json, 'utf-8'), ctx=ctx)
            self.assertFalse(annotation.is_satisfied)
            self.assertEqual(type(annotation), Annotation)

        except Exception as e:
            self.assertEqual(str(e), "'invalid' is not a valid SignType")
            return
        
        self.assertTrue(False)

    def test_httppki_execute_invalid_key_test(self):

        modified_request = self.request
        modified_request.headers['Signature-Input'] = '\"@method\" \"@path\" \"@authority\" \"Content-Type\" \"Content-Length\";created=1646146637;keyid=\"invalid\";alg=\"ed25519\"'
        ctx = ImmutablePropertyBag({'request': modified_request})

        try:
            annotation = self.annotator.execute(data=bytes(modified_request.json, 'utf-8'), ctx=ctx)
        except Exception as e:
            self.assertEqual(str(e), "Cannot read Public Key File.")
            return
        
        self.assertTrue(False)


    def test_httppki_execute_empty_signature_test(self):

        modified_request = self.request
        modified_request.headers['signature'] = ""
        
        ctx = ImmutablePropertyBag({'request': modified_request})

        try:
            annotation = self.annotator.execute(data=bytes(modified_request.json, 'utf-8'), ctx=ctx)
        except Exception as e:
            self.assertEqual(str(e), "Signature is empty.")
            return
        
        self.assertTrue(False)
            
    
    def test_httppki_execute_invalid_signature_test(self):

        modified_request = self.request
        modified_request.headers['signature'] = "invalid"
        
        ctx = ImmutablePropertyBag({'request': modified_request})

        try:
            annotation = self.annotator.execute(data=bytes(modified_request.json, 'utf-8'), ctx=ctx)
        except Exception as e:
            self.assertEqual(str(e), "Cannot verify signature.")
            return
        
        self.assertTrue(False)
            

    def buildRequest(self, keys: SignInfo):
        # seed = "helloo"


        payload = {'KeyA': 'This is some test data'}
        headers = {'Content-Type': 'application/json',
                "Host":"example.com",
		        "Date":"Tue, 20 Apr 2021 02:07:55 GMT",
                'Content-Length':'18'}

        ticks = datetime.datetime.now()

        #The URL has to be a absolute
        url = 'http://example.com/foo?var1=&var2=2'
        
        data=json.dumps(payload)


        fields = [DerivedComponent.Method, DerivedComponent.Path, DerivedComponent.Authority, "Content-Type", "Content-Length"]
        req = Request('POST',url,headers=headers,json=data)
        

        handler = Ed25519RequestHandler(req)


        handler.AddSignatureHeaders(ticks, fields, keys)
        return handler.request


if __name__ == "__main__":
    unittest.main()