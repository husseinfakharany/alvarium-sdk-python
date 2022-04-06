import json
from requests import Request, Session
from exceptions import ParserException
from urllib.parse import urlparse
from contracts import parseResult
from io import StringIO


def parseSignature(r: Request) -> parseResult:
    #Signature Inputs Extraction
    signatureInput = r.headers["Signature-Input"]
    try:
        signature = r.headers["Signature"]
    except KeyError:
        signature = ""

    # Returns key error if not found
    # print(signature)
    # print(signatureInput)

    signatureInputList = signatureInput.split(";",1)
    signatureInputHeader = signatureInputList[0].split(" ")
    signatureInputTail = signatureInputList[1]
    
    signatureInputParsedTail = signatureInputTail.split(";")

    for s in signatureInputParsedTail:
        if "alg" in s:
            raw = s.split("=")[1]
            algorithm = raw[1:len(raw)-1]
        if "keyid" in s:
            raw = s.split("=")[1]
            keyid = raw[1:len(raw)-1]

    parsed_url = urlparse(r.url)

    signatureInputFields = {}
    signatureInputBody = StringIO()

    for field in signatureInputHeader:
        #remove double quotes from the field to access it directly in the header map
        key = field[1 : len(field)-1]
        if key[0] == "@":
            #TODO use contracts
            if key == "@method":
                signatureInputFields[key] = [r.method]
            elif key == "@target-uri" or key == "@request-target":
                #Both derived components represent the same thing as we consider the URL to be absolute
                signatureInputFields[key] = [r.url]
            elif key == "@authority":
                signatureInputFields[key] = [parsed_url.netloc]
            elif key == "@scheme":
                signatureInputFields[key] = [parsed_url.scheme]
            elif key == "@path":
                signatureInputFields[key] = [parsed_url.path]
            elif key == "@query":
                signatureInputFields[key] = ["?"+parsed_url.query]
            elif key == "@query-params":
                queryParams = []
                rawQueryParams = parsed_url.query.split("&")
                for rawQueryParam in rawQueryParams:
                    if rawQueryParam != "":
                        parameter = rawQueryParam.split("=")
                        name = parameter[0]
                        value = parameter[1]
                        queryParam = f';name="{name}": {value}'
                        queryParams.append(queryParam)
                signatureInputFields[key] = queryParams
            else:
                raise ParserException(f"Unhandled Specialty Component {key}")
        else:
            try:
                fieldValues = r.headers[key]
                #Removing leading and trailing whitespaces
                signatureInputFields[key] = [fieldValues.strip()]
            except KeyError:
                raise ParserException(f"Header field not found {key}")
    
        #Construct final output string
        keyValues = signatureInputFields[key]
        if len(keyValues) == 1:
            signatureInputBody.write(f'"{key}" {keyValues[0]}\n')
        else:
            for value in keyValues:
                signatureInputBody.write(f'"{key}"{value}\n')
   
    parsedSignatureInput = f"{signatureInputBody.getvalue()};{signatureInputTail}"
    s = parseResult(seed=parsedSignatureInput, signature=signature, keyid=keyid, algorithm=algorithm)

    print(s.seed)
    return s

if __name__ == '__main__':
    payload = {'some': 'data'}
    headers = {'Content-Type': 'application/json',
                "Host":"example.com",
		        "Date":"Tue, 20 Apr 2021 02:07:55 GMT",
                'Content-Length':'18',
                'Signature-Input':"\"Date\" \"@method\" \"@path\" \"@authority\" \"Content-Type\" \"Content-Length\" \"@query-params\" \"@query\";created=1644758607;keyid=\"public.key\";alg=\"ed25519\";"}
    
    #The URL has to be a absolute
    url = 'http://example.com/foo?var1=&var2=2'
    

    data=json.dumps(payload)
    req = Request('POST',url,headers=headers,json=data)
   
    parseSignature(req)
    #prepped = req.prepare()
    #session = Session()
    #session.send(prepped)

