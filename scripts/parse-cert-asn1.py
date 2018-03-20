import os
import sys
sys.path.append(os.path.abspath("asn1/"))
from asn1reader import *

if __name__ == "__main__":
    from pprint import pprint
    #filename = "../certs/cert-pathlen.pem"
    #filename = "../certs/cert-ipaddress.pem"
    #filename = "../certs/cert-root.pem"
    #filename = "../certs/cert-ec.pem"
    #filename = "../certs/cert-dsa.pem"
    #filename = "../certs/cert-rsa2047.pem"
    filename = "../certs/cert-ct.pem"
    with open(filename,"r") as f:
        cert = f.read()
    reader = ASN1PEMReader()
    reader.loadPEM(cert)
    root_node = ASN1Parser.parse(reader)
    root_node.outputAll()


