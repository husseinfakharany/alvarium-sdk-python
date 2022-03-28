from ast import parse
import json
import unittest
from requests import Request
from alvarium.annotators.handler.base import parseSignature
from alvarium.annotators.handler.contracts import parseResult

class ParserTest(unittest.TestCase):

    def __init__(self, *args, **kwargs) -> None:
        super(ParserTest, self).__init__( *args, **kwargs)
        payload = {'KeyA': 'This is some test data'}
        headers = {'Content-Type': 'application/json',
                "Host":"example.com",
		        "Date":"Tue, 20 Apr 2021 02:07:55 GMT",
                'Content-Length':'18'}

        #The URL has to be a absolute
        url = 'http://example.com/foo?var1=&var2=2'
        
        data=json.dumps(payload)

        self.req = Request('POST',url,headers=headers,json=data)

    def test_Parser_Should_Return_ParseResult(self):

        self.req.headers['Signature-Input'] = "\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\" \"@query-params\" \"@query\";created=1644758607;keyid=\"public.key\";alg=\"ed25519\";"
        parsed = parseSignature(self.req)

        expectedSeed = "\"date\" Tue, 20 Apr 2021 02:07:55 GMT\n\"@method\" POST\n\"@path\" /foo\n\"@authority\" example.com\n\"content-type\" application/json\n\"content-length\" 18\n\"@query-params\";name=\"var1\": \n\"@query-params\";name=\"var2\": 2\n\"@query\" ?var1=&var2=2\n;created=1644758607;keyid=\"public.key\";alg=\"ed25519\";"
        expectedAlg = "ed25519"
        expectedKeyId = "public.key"

        expectedResult = parseResult(seed=expectedSeed, signature="", keyid=expectedKeyId, algorithm=expectedAlg)

        self.assertTrue(parsed.__eq__(expectedResult))

    def test_Method_Derived_Component_Should_Return_ParseResult(self):
        
        self.req.headers['Signature-Input'] = "\"@method\";"
        parsed = parseSignature(self.req)

        expectedSeed = "\"@method\" POST\n;"
        expectedAlg = ""
        expectedKeyId = ""

        expectedResult = parseResult(seed=expectedSeed, signature="", keyid=expectedKeyId, algorithm=expectedAlg)

        self.assertTrue(parsed.__eq__(expectedResult))
    
    def test_Authority_Derived_Component_Should_Return_ParseResult(self):
        
        self.req.headers['Signature-Input'] = "\"@authority\";"
        parsed = parseSignature(self.req)

        expectedSeed = "\"@authority\" example.com\n;"
        expectedAlg = ""
        expectedKeyId = ""

        expectedResult = parseResult(seed=expectedSeed, signature="", keyid=expectedKeyId, algorithm=expectedAlg)

        self.assertTrue(parsed.__eq__(expectedResult))

    def test_Scheme_Derived_Component_Should_Return_ParseResult(self):
        
        self.req.headers['Signature-Input'] = "\"@scheme\";"
        parsed = parseSignature(self.req)

        expectedSeed = "\"@scheme\" http\n;"
        expectedAlg = ""
        expectedKeyId = ""

        expectedResult = parseResult(seed=expectedSeed, signature="", keyid=expectedKeyId, algorithm=expectedAlg)

        self.assertTrue(parsed.__eq__(expectedResult))

    def test_Request_Target_Derived_Component_Should_Return_ParseResult(self):
        
        self.req.headers['Signature-Input'] = "\"@request-target\";"
        parsed = parseSignature(self.req)

        expectedSeed = "\"@request-target\" http://example.com/foo?var1=&var2=2\n;"
        expectedAlg = ""
        expectedKeyId = ""

        expectedResult = parseResult(seed=expectedSeed, signature="", keyid=expectedKeyId, algorithm=expectedAlg)

        self.assertTrue(parsed.__eq__(expectedResult))

    def test_Path_Derived_Component_Should_Return_ParseResult(self):
        
        self.req.headers['Signature-Input'] = "\"@path\";"
        parsed = parseSignature(self.req)

        expectedSeed = "\"@path\" /foo\n;"
        expectedAlg = ""
        expectedKeyId = ""

        expectedResult = parseResult(seed=expectedSeed, signature="", keyid=expectedKeyId, algorithm=expectedAlg)

        self.assertTrue(parsed.__eq__(expectedResult))

    def test_Query_Derived_Component_Should_Return_ParseResult(self):
        
        self.req.headers['Signature-Input'] = "\"@query\";"
        parsed = parseSignature(self.req)

        expectedSeed = "\"@query\" ?var1=&var2=2\n;"
        expectedAlg = ""
        expectedKeyId = ""

        expectedResult = parseResult(seed=expectedSeed, signature="", keyid=expectedKeyId, algorithm=expectedAlg)

        self.assertTrue(parsed.__eq__(expectedResult))

    def test_Query_Params_Derived_Component_Should_Return_ParseResult(self):
        
        self.req.headers['Signature-Input'] = "\"@query-params\";"
        parsed = parseSignature(self.req)

        expectedSeed = "\"@query-params\";name=\"var1\": \n\"@query-params\";name=\"var2\": 2\n;"
        expectedAlg = ""
        expectedKeyId = ""

        expectedResult = parseResult(seed=expectedSeed, signature="", keyid=expectedKeyId, algorithm=expectedAlg)

        self.assertTrue(parsed.__eq__(expectedResult))
    
if __name__ == "__main__":
    unittest.main()