import json
import unittest
from requests import Request
from alvarium.annotators.handler.base import parseSignature
from alvarium.annotators.handler.contracts import parseResult

class ParserTest(unittest.TestCase):

    def test_Parser_Should_Return_ParseResult(self):
        payload = {'KeyA': 'This is some test data'}
        headers = {'Content-Type': 'application/json',
                "Host":"example.com",
		        "Date":"Tue, 20 Apr 2021 02:07:55 GMT",
                'Content-Length':'18',
                'Signature-Input':"\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\" \"@query-params\" \"@query\";created=1644758607;keyid=\"public.key\";alg=\"ed25519\";"}

        #The URL has to be a absolute
        url = 'http://example.com/foo?var1=&var2=2'
        
        data=json.dumps(payload)
        req = Request('POST',url,headers=headers,json=data)
    
        parsed = parseSignature(req)

        expectedSeed = "\"date\" Tue, 20 Apr 2021 02:07:55 GMT\n\"@method\" POST\n\"@path\" /foo\n\"@authority\" example.com\n\"content-type\" application/json\n\"content-length\" 18\n\"@query-params\";name=\"var1\": \n\"@query-params\";name=\"var2\": 2\n\"@query\" ?var1=&var2=2\n;created=1644758607;keyid=\"public.key\";alg=\"ed25519\";"
        expectedAlg = "ed25519"
        expectedKeyId = "public.key"

        #Type Check
        self.assertEqual(type(parsed), parseResult)

        #Seed Check
        self.assertEqual(parsed.seed, expectedSeed)

        #Algorithm Check
        self.assertEqual(parsed.algorithm, expectedAlg)

        #Keyid Check
        self.assertEqual(parsed.keyid, expectedKeyId)


if __name__ == "__main__":
    unittest.main()