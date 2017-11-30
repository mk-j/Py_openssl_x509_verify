#!/usr/bin/env python
# -*- coding: utf-8 -*-
from OpenSSL.SSL import FILETYPE_PEM
from OpenSSL import rand
from OpenSSL.crypto import (dump_certificate, X509, X509Name,  PKey, TYPE_RSA, X509Req, dump_privatekey, X509Extension)
import re

def create_self_signed_cert(cert_file_path):
    private_key_path = re.sub(r".(pem|crt)$", ".key", cert_file_path, flags=re.IGNORECASE)

    # create public/private key
    key = PKey()
    key.generate_key(TYPE_RSA, 2048)

    # Self-signed cert
    cert = X509()

    #subject = X509Name(cert.get_subject()) 
    subject = cert.get_subject() 
    subject.CN = 'localhost'
    subject.O = 'XYZ Widgets Inc'
    subject.OU = 'IT Department'
    subject.L = 'Seattle'
    subject.ST = 'Washington'
    subject.C = 'US'
    subject.emailAddress = 'e@example.com'

    cert.set_version(2)
    cert.set_issuer(subject)
    cert.set_subject(subject)
    #cert.set_serial_number(int(os.urandom(16).encode('hex'),16))
    cert.set_serial_number(int(rand.bytes(16).encode('hex'),16))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(31536000)
    cert.set_pubkey(key)
    cert.add_extensions([
          X509Extension("basicConstraints", True, "CA:TRUE, pathlen:0"),
          X509Extension("keyUsage", True, "keyCertSign, cRLSign"),
          X509Extension("subjectKeyIdentifier", False, "hash", subject=cert),
          ])
    cert.sign(key, 'sha256')

    with open(cert_file_path, 'wb+') as f:
        f.write(dump_certificate(FILETYPE_PEM, cert))
    with open(private_key_path, 'wb+') as f:
        f.write(dump_privatekey(FILETYPE_PEM, key))

if __name__ == "__main__":
    import sys
    import os
    os.chdir(sys.path[0])
    create_self_signed_cert("example-cert.pem");
    sys.exit(0)
