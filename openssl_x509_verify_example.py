#!/usr/bin/python
import x509tools 
import os

def file_read(filename):
    content=''
    if os.path.exists(filename):
        fp = open(filename, "r")
        content = fp.read()
        fp.close()
    return content

def check_openssl_cipher():
    v = x509tools.openssl_cipher_iv_length('AES-128-CBC')
    print("openssl cipher iv length of aes-128-cbc is %s" % v)

def check_x509_verify_rsa():
    ca_pem = file_read('./certs/RSA_DigiCertGlobalRootCA.crt')
    cert_pem = file_read('./certs/RSA_DigiCertSHA2SecureServerCA.crt')
    x = x509tools.openssl_x509_verify(cert_pem, ca_pem)
    print("openssl x509 verify result for an RSA cert is %s" % x)

def check_x509_verify_ecc():
    ca_pem = file_read('./certs/ECC_DigiCertGlobalRootCA3.crt')
    cert_pem = file_read('./certs/ECC_DigiCertGlobalCAG3.crt')
    x = x509tools.openssl_x509_verify(cert_pem, ca_pem)
    print("openssl x509 verify result for an ECC cert is %s" % x)

def main():
    check_openssl_cipher()
    check_x509_verify_rsa()
    check_x509_verify_ecc()

if __name__ == "__main__":
    main()
