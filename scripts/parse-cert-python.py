import os
import sys
sys.path.append(os.path.abspath("asn1/"))
from asn1cert import *

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
    f = ASN1Cert()
    f.loadPEM(cert)
    print("Version: %s" % f.getVersion())
    print("SerialNumber: %s" % f.getSerialNumber())
    print("Signature: %s" % f.getSignatureType())
    print("Issuer: %s" % f.getIssuer())
    print("Date: %s" % f.getValidDates())
    print("Subject: %s" % f.getSubject())
    print("Public Key: %s" % f.getPublicKeyInfo())
    print("Thumbprint: %s" % f.getThumbprint())
    print("X509v3 Extensions:")
    pprint(f.getExtensionInfo())

