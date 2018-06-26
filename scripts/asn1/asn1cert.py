import os
import sys
import re
from asn1reader import *

class ASN1Cert:
    def __init__(self):
        self.root=None
        self.version=1
        self.pem=''
        pass
    def loadPEM(self,pem):
        self.pem = pem
        reader = ASN1PEMReader()
        reader.loadPEM(pem)
        self.root= ASN1Parser.parse(reader)
        if self.root and self.root.childpath("0-0") and self.root.childpath("0-0").tag()==0xa0:
            self.version = ord(self.root.childpath("0-0-0").content())+1    
    def _tbs(self,which): #tbs => to be signed/body, portion of x509 cert
        if self.version==1 and which>0:
            which = which-1 #version1 had no version tag, so it makes the other nodes off by one
        return self.root.childpath("0-%s" % which) if self.root else None
    def _dn(self,n): #distinguished name, either subject or issuer fields
        dn = {}
        more=''
        for dn_set in n.children():
            for c in dn_set.children():
                if len(c.children())==2:
                    val = c.childpath("1").as_string()
                    key = c.childpath("0").as_oid_name()
                    key = 'street2' if key=='street1' and key in dn else key
                    if key in dn:
                        more = "%s,%s=%s" % (more, key, val)
                    else:
                        dn[key]=val
                pass
            pass
        pass
        if len(more)>0:
            dn['more']=more[1:] #trim off leading comma
        return dn
    def _count_bits(self,keybin):
        two_bytes = bin(int(keybin[0:2].encode('hex'), 16))[2:].zfill(16).lstrip("0")
        return ((len(keybin)-2)*8) + len(two_bytes)
    def getVersion(self):
        return self.version
    def getSerialNumber(self):
        n = self._tbs(1)
        return n.as_hex() if n else ''
    def getSignatureType(self):
        n = self._tbs(2)
        return n.childpath("0").as_oid_name() if n and n.childpath("0") else ''
    def getIssuer(self):
        n = self._tbs(3)
        return self._dn(n) if n else {}
    def getValidDates(self):
        n = self._tbs(4)
        dates = {}
        dates['notBefore'] = n.childpath("0").as_date() if n.childpath("0") else ''
        dates['notAfter'] = n.childpath("1").as_date()  if n.childpath("1") else ''
        return dates
    def getSubject(self):
        n = self._tbs(5)
        return self._dn(n) if n else {}
    def getPublicKeyInfo(self):
        n = self._tbs(6)
        info = {}
        oid = n.childpath("0-0").as_string() if n and n.childpath("0-0") else ''
        if oid=='1.2.840.113549.1.1.1':
            node = ASN1Parser.parseBytes( n.childpath("1").content()[1:] ) #key bytes are doubly-encoded as asn1 so we parse AGAIN
            modulus = node.childpath("0").content()
            info['keysize'] = self._count_bits(modulus)
            info['exponent'] = node.childpath("1").as_hex()
            info['type'] = 'rsa'
        elif oid=='1.2.840.10045.2.1':
            curve = n.childpath("0-1").as_oid_name()
            info['type'] = 'ec'
            info['algorithmCurve'] = curve
            info['keysize'] = int(re.search(r'\d+', curve).group())
        elif oid=='1.2.840.10040.4.1':
            pubkey = n.childpath("0-1-0").content() if n.childpath("0-1-0") else ''
            info['type'] = 'dsa'
            info['keysize'] = self._count_bits(pubkey)
        return info
    def getExtensionInfo(self):
        if self.version!=3:
            return {}
        n = self._tbs(7)
        extensions = {}
        if n and n.tag()==0xa3 and n.childpath("0") and n.childpath("0").tag()==0x30: #seq
            for extension in n.childpath("0").children():
                if extension.childpath("0") and extension.childpath("1") and extension.childpath("0").tag()==0x06:
                    oid = extension.childpath("0").as_string()
                    oid_name = extension.childpath("0").as_oid_name()
                    crit_content = extension.childpath("1").content()
                    crit_byte = 1 if len(crit_content)>0 and ord(crit_content[0])>0 else 0
                    child_count = len(extension.children())
                    critical = True if child_count==3 and crit_byte >0 else False
                    next_offset = "1" if child_count==2 else "2"
                    data_node = extension.childpath(next_offset)
                    parsed_node = ASN1Parser.parseBytes( data_node.content() )
                    extensions[oid_name] = self.extension( oid, parsed_node, False )
        return extensions
    def extension(self,oid,data_node,critical):
        entries = []
        if (oid=='2.5.29.14'):#subjectKeyIdentifier
            return data_node.as_string()
        if (oid=='2.5.29.35'):#authorityKeyIdentifier
            return data_node.childpath("0").as_hex() if data_node.childpath("0") else ''
        elif (oid=='2.5.29.19'):#basicConstraints
            info = {'CA':'FALSE'}
            for child_node in data_node.children():
                if child_node.tag()==0x01 and ord(child_node.content()[0])>0: #ASN1BOOL
                    info['CA']='TRUE'
                elif child_node.tag()==0x02: #ASN1INT
                    info['pathlen']=ord(child_node.content()[0])
            return info
        elif (oid=='2.5.29.32'):#certificatePolicies
            for n in data_node.children():
                entry = {}
                if n.childpath("0") and n.childpath("0").tag()==0x06: #OID
                    entry['policy'] = n.childpath("0").as_string()
                if n.childpath("1-0-1") and n.childpath("1-0-0").as_string()=='1.3.6.1.5.5.7.2.1': #OID
                    entry['cps'] = n.childpath("1-0-1").as_string()
                entries.append(entry)
            return entries
        elif (oid=='2.5.29.31'):#crlDistributionPoints
            for crl_node in data_node.children():
                url = crl_node.childpath("0-0-0").content()
                entries.append(url)
            return entries
        elif (oid=='2.5.29.37'):#extendedKeyUsage
            if critical: 
                entries.append('critical')
            for c in data_node.children():
                if c.tag()==0x06:
                    entries.append(c.as_oid_name())
            return entries
        elif (oid=='1.3.6.1.5.5.7.1.1'):#authorityInfoAccess
            for c in data_node.children():
                if c.has_children():
                    oid_name = c.childpath("0").as_oid_name()
                    entries.append( { oid_name : c.childpath("1").content() } )
            return entries
        elif (oid=='2.5.29.17'):#subjectAltName
            for san in data_node.children():
                if san.tag()!=0x87: 
                    entries.append(san.content())
                elif len(san.content())==4: #ipv4
                    entries.append( ".".join(map(str,map(ord,list(san.content())))) )
                elif len(san.content())==16: #ipv6
                    entries.append( ":".join(filter(None,re.split('(.{1,4})', san.as_hex()))))
                pass
            return entries
        elif (oid=='2.5.29.15'):#keyUsage
            b = data_node.content()
            masks = [0xff,0xfe,0xfc,0xf8,0xf0,0xe0,0xc0,0x80]
            b0 = ord(b[0])   if len(b)>=1 else 0
            mask = masks[b0] if b0<=7 else 0xff
            b1 = ord(b[1])   if len(b)>=2 else 0
            b1 = (b1 & mask) if len(b)==2 else b1
            b2 = ord(b[2])   if len(b)>=3 else 0
            b2 = (b2 & mask) if len(b)==3 else b2
            if (b1 & 0x80): entries.append("digitalSignature")
            if (b1 & 0x40): entries.append("nonRepudiation")
            if (b1 & 0x20): entries.append("keyEncipherment")
            if (b1 & 0x10): entries.append("dataEncipherment")
            if (b1 & 0x08): entries.append("keyAgreement")
            if (b1 & 0x04): entries.append("keyCertSign")
            if (b1 & 0x02): entries.append("cRLSign")
            if (b1 & 0x01): entries.append("encipherOnly")
            if (b2 & 0x80): entries.append("decipherOnly")
            if (critical): entries.append('critical')
            return entries
        else:
            if not data_node.has_children():
                return data_node.as_oid_name() if data_node.tag()==0x06 else data_node.as_string()
            for child in data_node.children():
                v = data_node.as_oid_name() if data_node.tag()==0x06 else data_node.as_string()
                entries.append(v)
            pass
        return entries
    def getThumbprint(self,hash_type='sha1'):
        return ASN1FileUtils.thumbprint(self.pem,hash_type)

if __name__ == "__main__":

    from pprint import pprint
    #filename = "cert-pathlen.pem"            
    #filename = "cert-ipaddress.pem"            
    #filename = "cert-root.pem"            
    #filename = "cert-ec.pem"            
    #filename = "cert-dsa.pem"            
    #filename = "cert-rsa2047.pem"            
    filename = "certs/cert-ct.pem"            
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

