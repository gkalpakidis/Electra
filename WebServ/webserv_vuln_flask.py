from flask import Flask, request, Response

app = Flask(__name__)

@app.route("/wsdl", methods=["GET"])
def wsdl():
    wsdl_content = """<?xml version="1.0"?>
<definitions name="XXETestService"
            targetNamespace="http://127.0.0.1:5000/xxe"
            xmlns:tns="http://127.0.0.1:5000/xxe"
            xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
            xmlns:xsd="http://www.w3.org/2001/XMLSchema"
            xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
            xmlns="http://schemas.xmlsoap.org/wsdl/">

  <message name="getXXERequest">
    <part name="data" type="xsd:string"/>
  </message>

  <message name="getXXEResponse">
    <part name="result" type="xsd:string"/>
  </message>

  <portType name="XXETestPortType">
    <operation name="getXXE">
      <input message="tns:getXXERequest"/>
      <output message="tns:getXXEResponse"/>
    </operation>
  </portType>

  <binding name="XXETestBinding" type="tns:XXETestPortType">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="getXXE">
      <soap:operation soapAction="getXXE"/>
      <input>
        <soap:body use="literal"/>
      </input>
      <output>
        <soap:body use="literal"/>
      </output>
    </operation>
  </binding>

  <service name="XXETestService">
    <port name="XXETestPort" binding="tns:XXETestBinding">
      <soap:address location="http://localhost:5000/soap"/>
    </port>
  </service>
</definitions>
"""
    return Response(wsdl_content, mimetype="test/xml")

@app.route("/soap", methods=["POST"])
def soap_service():
    xml = request.data.decode("utf-8")

    #Simple XXE
    if "&xxe;" in xml or "file://" in xml:
        result = "root:x:0:0:root:/root:/bin/bash"
    else:
        result = "No XXE vulnerability."
    
    response_xml = f"""<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
   <soap:Body>
      <getXXEResponse>
         <result>{result}</result>
      </getXXEResponse>
   </soap:Body>
</soap:Envelope>
"""
    return Response(response_xml, mimetype="text/xml")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)