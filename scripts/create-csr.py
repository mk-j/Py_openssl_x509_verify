#!/usr/bin/env python
# -*- coding: utf-8 -*-
from OpenSSL.SSL import FILETYPE_PEM
from OpenSSL.crypto import (dump_certificate_request, dump_privatekey, PKey, TYPE_RSA, X509Req)
import re

def create_csr(csr_file_path):
    private_key_path = re.sub(r".(pem|crt)$", ".key", cert_file_path, flags=re.IGNORECASE)
    
    # create public/private key
    key = PKey()
    key.generate_key(TYPE_RSA, 2048)

    # Generate CSR
    req = X509Req()
    req.get_subject().CN = 'localhost'
    req.get_subject().O = 'XYZ Widgets Inc'
    req.get_subject().OU = 'IT Department'
    req.get_subject().L = 'Seattle'
    req.get_subject().ST = 'Washington'
    req.get_subject().C = 'US'
    req.get_subject().emailAddress = 'e@example.com'
    req.set_pubkey(key)
    req.sign(key, 'sha256')

    with open(csr_file_path, 'wb+') as f:
        f.write(dump_certificate_request(FILETYPE_PEM, req))
    with open(private_key_path, 'wb+') as f:
        f.write(dump_privatekey(FILETYPE_PEM, key))

if __name__ == "__main__":
    import sys
    import os
    os.chdir(sys.path[0])
    create_csr("example-csr.csr");
    sys.exit(0)
