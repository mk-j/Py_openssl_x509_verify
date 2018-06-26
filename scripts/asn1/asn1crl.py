#!/bin/env python
import sys
import os

sys.path.append(os.path.abspath("../../libs/"))
from filetools import *
from asn1reader import *

class ASN1NodeTraversal:
    _asn1_file=False
    def __init__(self,asn1_file):
        self._asn1_file = asn1_file
    def nextChildren(self):
        return ASN1Parser.parse(self._asn1_file)
    def nextNode(self):
        startpos = self._asn1_file.pos()
        tag = self._asn1_file.nextbyte()
        clength = ASN1Parser.asn1_node_length(self._asn1_file)
        hlength = self._asn1_file.pos() - startpos
        cstart = self._asn1_file.pos()

        has_children = 1 if tag & 0x20   else 0
        content = ''
        if not has_children and clength>0:
            content = ASN1Parser.asn1_get_content(self._asn1_file,clength)
        return ASN1Node(tag, content, hlength, cstart, clength)
def nextNodeIsChild(node):
    return True if node.tag() & 0x20 else False

##asn1_file = ASN1FileReader('PositiveSSLCA2.crl')
##navigator = ASN1NodeTraversal(asn1_file)
##load 1 node at a time, outputall
##try:
##    for i in range(1,12000):
##        n = navigator.nextNode()
##        n.output(depth=0)
##except StopIteration:
##    pass
#sys.exit(0)

class ASN1CRL:
    _filename=''
    def __init__(self, filename):
        self._filename = filename
    def getRevokeEntries(self):
        for entry in self.getFields():
            name, v1, v2 = entry
            if name=='serial':
                yield [v1,v2]
            pass
        pass
    def getFields(self):
        asn1_file = ASN1FileReader(self._filename)
        navigator = ASN1NodeTraversal(asn1_file)
        n = navigator.nextNode()#SEQ #n.output(depth=0)
        if not nextNodeIsChild(n): raise ValueError
        
        n = navigator.nextNode()#SEQ #n.output(depth=1)
        if not nextNodeIsChild(n): raise ValueError
        
        n = navigator.nextNode()#version #n.output(depth=2)

        tagNumber = n.tag() & 0x1F
        if tagNumber==0x02: #special handling because version is not always present
            yield ["version", n.as_string(), n.as_hex()]
            n = navigator.nextChildren()#sig has type #n.outputAll(depth=2)
            n = n.childpath("0")
        elif tagNumber==0x10:
            n = navigator.nextNode()

        sig_oid = n.as_string()
        sig_hash = n.as_oid_name()
        yield ["signature_hash", sig_hash, sig_oid]

        if tagNumber==0x10:
            n = navigator.nextNode()#skip null
        
        if nextNodeIsChild(n):  raise ValueError
        
        n = navigator.nextChildren()#issuer #n.outputAll(depth=2)
        #n.outputAll()
        #issuer ={}
        for dn_set in n.children():
            for c in dn_set.children():
                if len(c.children())==2:
                    val = c.childpath("1").as_string()
                    key = c.childpath("0").as_oid_name()
                    yield ["issuer", key, val]
        
        n = navigator.nextNode()#UTCTime last_update #n.output(depth=2)
        #n.output()
        last_update = n.as_date()
        
        n = navigator.nextNode()#UTCTime next_update #n.output(depth=2)
        next_update = n.as_date()
        yield ["crl_update", last_update, next_update]
        
        if nextNodeIsChild(n):  raise ValueError
        
        n = navigator.nextNode() #SEQ Serial List #n.output(depth=3)
        remaining_bytes=0
        #n.output()
        #print(n.tag())
        if n.tag()==0x30:
            remaining_bytes = n.clength()
        while remaining_bytes>0:
            pair = navigator.nextChildren() #SEQ serial_pair
            remaining_bytes-=(pair.clength() + pair.hlength())
        
            n = pair.childpath("0")
            rev_serial = n.as_hex()
            n = pair.childpath("1")
            #pair.outputAll()
            rev_date = n.as_date()
            yield ["serial", rev_serial, rev_date]        
        #n = navigator.nextChildren() #Extensions, including issuer_auth_key
        #n.outputAll(depth=3)
        #n = navigator.nextChildren() #Signature Info
        #n.outputAll(depth=3)
        #n = navigator.nextChildren() #Signature itself
        #n.outputAll(depth=3)
        pass
    def outputAll(self):#only good for small CRLs you can preload the nodes in memory
        asn1_file = ASN1FileReader(self._filename)
        navigator = ASN1NodeTraversal(asn1_file)
        n = navigator.nextChildren()#issuer
        n.outputAll(depth=0)
    def outputForced(self):
        asn1_file = ASN1FileReader(self._filename)
        navigator = ASN1NodeTraversal(asn1_file)
        try:
            while 1:
                n = navigator.nextNode()
                n.output(depth=0)
            pass
        except StopIteration:
            pass
        pass

if __name__ == "__main__":
    crl= ASN1CRL('certs/PositiveSSLCA2.crl')
    for field in crl.getFields():
        n,v1,v2 = field
        print(field)

    sys.exit(0)





