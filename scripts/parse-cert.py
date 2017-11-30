#!/usr/bin/env python
# -*- coding: utf-8 -*-
from OpenSSL.crypto import (load_certificate, dump_privatekey, dump_certificate, X509, X509Name, PKey, TYPE_DSA, TYPE_RSA, FILETYPE_PEM, FILETYPE_ASN1 )
from Crypto.Util.asn1 import (DerSequence, DerObject)
from datetime import datetime
import textwrap

def format_subject_issuer(x509name):
    items = []
    for item in x509name.get_components():
        items.append('%s=%s' %  (item[0], item[1]) )
    return ", ".join(items);

def format_split_bytes(aa):
    bb = aa[1:] if len(aa)%2==1 else aa #force even num bytes, remove leading 0 if necessary
    out = format(':'.join(s.encode('hex').lower() for s in bb.decode('hex')))
    return out
    
def format_split_int(serial_number):
    aa = "0%x" % serial_number #add leading 0
    return format_split_bytes(aa)

def format_asn1_date(d):
    return datetime.strptime(d.decode('ascii'), '%Y%m%d%H%M%SZ').strftime("%Y-%m-%d %H:%M:%S GMT")

def get_signature_bytes(x509):
    der = DerSequence()
    der.decode(dump_certificate(FILETYPE_ASN1, x509))
    der_tbs = der[0]
    der_algo = der[1]
    der_sig = der[2]
    der_sig_in = DerObject()
    der_sig_in.decode(der_sig)
    sig=der_sig_in.payload[1:] #skip leading zeros
    return sig.encode('hex')

def get_modulus_and_exponent(x509):
    if x509.get_pubkey().type()==TYPE_RSA:
        pub_der = DerSequence()
        pub_der.decode(dump_privatekey(FILETYPE_ASN1, x509.get_pubkey()))
        modulus = "%s:%s" % ( format_split_int(pub_der._seq[0]), format_split_int(pub_der._seq[1]) )
        exponent = pub_der._seq[2]
        return [ modulus, exponent ]
    return ''

def parse_cert(cert_file):
    with open(cert_file, 'rb+') as f:
        cert_pem = f.read()
        f.close()

        x509 = load_certificate(FILETYPE_PEM, cert_pem)
        subject_str = format_subject_issuer( x509.get_subject() )
        issuer_str = format_subject_issuer( x509.get_issuer() )

        keytype = x509.get_pubkey().type()
        keytype_list = {TYPE_RSA:'rsaEncryption', TYPE_DSA:'rsaEncryption', 408:'id-ecPublicKey'}
        key_type_str = keytype_list[keytype] if keytype in keytype_list else 'other'

        pkey_lines=[]
        pkey_lines.append("        Public Key Algorithm: %s" % key_type_str)
        pkey_lines.append("            Public-Key: (%s bit)" % x509.get_pubkey().bits())
        if x509.get_pubkey().type()==TYPE_RSA:
            modulus, exponent = get_modulus_and_exponent(x509)
            formatted_modulus = "\n                ".join(textwrap.wrap(modulus, 45))
            pkey_lines.append("            Modulus:")
            pkey_lines.append("                %s" % formatted_modulus)
            pkey_lines.append("            Exponent %d (0x%x)" % (exponent,exponent))
        sig_formatted = "\n         ".join( textwrap.wrap(format_split_bytes(get_signature_bytes(x509)), 54) )

        print("Certificate:")
        print("    Data:")
        print("        Version: %s (0x%x)" % (int(x509.get_version()+1), x509.get_version()) )
        print("        Serial Number:")
        print("            %s" % format_split_int(x509.get_serial_number()))
        print("    Signature Algorithm: %s" % x509.get_signature_algorithm())
        print("    Issuer: %s" % issuer_str )
        print("    Validity")
        print("        Not Before: %s" % format_asn1_date(x509.get_notBefore()))
        print("        Not After : %s" % format_asn1_date(x509.get_notAfter()))
        print("    Subject: %s" % subject_str )
        print("    Subject Public Key Info:")
        print("\n".join(pkey_lines))
        print("        X509v3 extensions:")
        for i in xrange(x509.get_extension_count()):
            critical = 'critical' if x509.get_extension(i).get_critical() else ''
            print("             x509v3 %s: %s" % (x509.get_extension(i).get_short_name(), critical) )
            print("                 %s" % x509.get_extension(i).__str__() )
        print("    Signature Algorithm: %s" % x509.get_signature_algorithm() )
        print("         %s" % sig_formatted)
        print("    Thumbprint MD5:    %s" % x509.digest('md5'))
        print("    Thumbprint SHA1:   %s" % x509.digest('sha1'))
        print("    Thumbprint SHA256: %s" % x509.digest('sha256'))
        
if __name__ == "__main__":
    import sys
    import os
    os.chdir(sys.path[0])
    #parse_cert("../certs/RSA_DigiCertGlobalRootCA.crt");
    parse_cert("../certs/ECC_DigiCertGlobalCAG3.crt");
    sys.exit(0)
