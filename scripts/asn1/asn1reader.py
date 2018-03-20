#!/usr/bin/python

import os
import sys
import hashlib
from asn1oids import *


class ASN1Node:
    def __init__(self, tag, content, hlength, cstart, clength):
        self._tag = tag
        self._content = content
        self._hlength = hlength
        self._cstart = cstart
        self._clength = clength
        self._child_nodes = []
    def tag(self):
        return self._tag
    def cstart(self):
        return self._cstart
    def clength(self):
        return self._clength
    def header(self):
        return self._header
    def add_child(self,child):
        return self._child_nodes.append(child)
    def has_children(self):
        return True if len(self._child_nodes)>0 else False
    def children(self):
        return self._child_nodes
    def childpath(self,child_path_string):
        pieces = child_path_string.split("-")
        node = self
        for piece in pieces:
            which_child = int(piece)
            if which_child < len(node.children()):
                node = node.children()[which_child]
            else:
                return None
        return node
    def output(self,depth=0):
        Lshape = "\xe2\x94\x94";
        tabs = " " * depth
        has_children = 1 if self._tag & 0x20   else 0
        print "%s[%s]" % (tabs, ASN1NodeInfo.info_string(self._tag,self._clength) )
        if not has_children:
            print "%s%s[%s]" % (tabs, Lshape, ASN1Content.content(self._tag,self._content))
    def outputAll(self,depth=0):
        self.output(depth)
        for child in self.children():
            child.outputAll(depth+1)        
    def content(self):
        return self._content
    def as_string(self):
        return ASN1Content.content(self._tag,self._content)
    def as_hex(self):
        return ASN1Content.hex(self._content)
    def as_date(self):
        return ASN1Content.date(self._content)
    def as_oid_name(self):
        return ASN1Content.oid_name(self._content)

class ASN1FileUtils:
    @staticmethod
    def pem_to_der(pem_string):
        content=[]
        lines = pem_string.split("\n")
        for line in lines:
            if not line.startswith("-----"):
                content.append(line.strip())
        der_binary = "".join(content).decode('base64')
        return der_binary
    @staticmethod
    def thumbprint(pem_string,hash_type='sha1'):
        der_binary = ASN1FileUtils.pem_to_der(pem_string)
        if hash_type=='sha1':
            return hashlib.sha1(der_binary).hexdigest()
        elif hash_type=='sha256':
            return hashlib.sha256(der_binary).hexdigest()
        else:
            return ''
        pass
        

#load DER one byte at a time, for large files, like CRLs
class ASN1FileReader:
    def __init__(self, filename):
        self.fd = open(filename, "rb")
        self.chunk =''
        self.chunkpos=0
        self.filepos=0
    def __del__(self):
        if self.fd:
            self.fd.close()
    def type(self):
        return self.__class__.__name__
    def pos(self):
        return self.filepos
    def nextbyte(self):
        if self.chunkpos >= len(self.chunk):
            self.chunkpos=0
            self.chunk = self.fd.read(1024)
            if not self.chunk:
                raise StopIteration
        v = self.chunk[self.chunkpos];
        self.chunkpos=self.chunkpos+1
        self.filepos=self.filepos+1
        return ord(v);

#load PEM into memory all at once
class ASN1PEMReader:
    def __init__(self, filename=''):
        pem=''
        if os.path.exists(filename):
            with open(filename, "r") as fp:
                pem = fp.read()
        self._bytes = ASN1FileUtils.pem_to_der(pem)
        self._filepos=0
    def loadPEM(self,pem):
        self._bytes = ASN1FileUtils.pem_to_der(pem)
    def loadDER(self,file_bytes):
        self._bytes = file_bytes
    def type(self):
        return self.__class__.__name__
    def pos(self):
        return self._filepos
    def bytes(self,startpos,length):
        return self._bytes[startpos:startpos+length]
    def nextbyte(self):
        b = self._bytes[self._filepos]
        self._filepos = self._filepos+1
        return ord(b)

class ASN1Parser:
    @staticmethod
    def asn1_node_length(asn1_file):
        buf = asn1_file.nextbyte()
        l = buf & 0x7F;
        if l == buf:
            return l
        if l > 3:
            return -1 #length over 3 bytes not supported
        if l == 0:
            return -1 #undefined
        byte=0
        for i in range(l):
            buf = asn1_file.nextbyte()
            byte = (byte << 8) | buf
        return byte        
    @staticmethod
    def asn1_get_content(asn1_file,length):
        content=[]
        for i in range(length):
            c = chr(asn1_file.nextbyte())
            content.append(c)
        return b''.join(content)
    @staticmethod
    def parseBytes(content):
        asn1reader = ASN1PEMReader() #key bytes are doubly-encoded as asn1 so we parse AGAIN
        asn1reader.loadDER( content )
        node = ASN1Parser.parse( asn1reader,99 )
        return node
    @staticmethod
    def parse(asn1_file,depth=0):
        startpos = asn1_file.pos()
        tag = asn1_file.nextbyte()
        clength = ASN1Parser.asn1_node_length(asn1_file)
        end_pos = asn1_file.pos() + clength
        hlength = asn1_file.pos() - startpos
        cstart = asn1_file.pos()
        
        has_children = 1 if tag & 0x20   else 0
        content = ''
        #content = ''     if has_children else asn1_file.bytes(cstart,clength)
        if not has_children and asn1_file.type()=='ASN1PEMReader':
            content = asn1_file.bytes(cstart,clength)
        elif not has_children and asn1_file.type()=='ASN1FileReader':
            content = ASN1Parser.asn1_get_content(asn1_file,clength)
        node = ASN1Node(tag, content, hlength, cstart, clength)

        if has_children:
            if tag==0x03: # skip BitString unused bits, must be in [0, 7]
                asn1_file.nextbyte()
            if clength<=0 and (tag & 0x21): # indefinite length
                #print('indefinite length') maybe we can work on this later
                return node
            if clength>0:
                next_pos = asn1_file.pos()
                while next_pos < end_pos:
                    child = ASN1Parser.parse(asn1_file, depth+1)
                    node.add_child(child)
                    next_pos = asn1_file.pos()
                pass
            pass
        while asn1_file.pos() < end_pos:
            asn1_file.nextbyte()
        return node

class ASN1NodeInfo:
    @staticmethod
    def info_string(tag,length):
        tagHex = format(tag, '#04x')
        tagClass = tag >> 6;
        tagCon = (tag >> 5) & 1;
        tagNum = tag & 0x1F;
        tagName = ASN1NodeInfo.node_name(tag);
        clen = length
        return "tag:%s:{len:%s,class:%s,constructed:%s,number:%s,name:%s}" % (tagHex,clen,tagClass,tagCon,tagNum,tagName)
    @staticmethod
    def node_name(tag):
        nodeNameDict = {
            0x00:"EOC"             , 0x09:"Real"           , 0x15:"VideoTexString"  ,
            0x01:"BOOLEAN"         , 0x0A:"Enumerated"     , 0x16:"IA5String"       ,
            0x02:"INTEGER"         , 0x0B:"EmbeddedPDV"    , 0x17:"UTCTime"         ,
            0x03:"BIT_STRING"      , 0x0C:"UTF8String"     , 0x18:"GeneralizedTime" ,
            0x04:"OCTET_STRING"    , 0x10:"SEQUENCE"       , 0x19:"GraphicString"   ,
            0x05:"NULL"            , 0x11:"SET"            , 0x1A:"VisibleString"   ,
            0x06:"OID"             , 0x12:"NumericString"  , 0x1B:"GeneralString"   ,
            0x07:"ObjectDescriptor", 0x13:"PrintableString", 0x1C:"UniversalString" ,
            0x08:"External"        , 0x14:"T61String"      , 0x1E:"BMPString"       #
        }
        tagClass = tag >> 6;
        tagNumber = tag & 0x1F;
        if tagClass==0: #universal
            if tagNumber in nodeNameDict:
                return nodeNameDict[tagNumber]
            else:
                return "Universal_%s" % (format(tagNumber, '02X'))
        elif tagClass==1:
            return "Application_%s" % (format(tagNumber, '02X'))
        elif tagClass==2:
            return "CONTEXT_SPECIFIC";
        elif tagClass==3:
            return "Private_%s" % (format(tagNumber, '02X'))
        return 'unknown';

class ASN1Content:
    @staticmethod
    def content(tag,content):
        tagNumber = tag & 0x1F
        hexTags = {0x01:'bool', 0x02:'int', 0x03:'bitstring', 0x04:'octetstring'}
        strTags = {0x0C:'utf8', 0x12:'numeric',  0x16:'ia5',  0x1A:'visible', 0x1B:'general'} #0x15:'videotex',0x19:'graphic',
        latinTags = {0x13:'printable',0x14:'t61'}
        timeTags = {0x17:'utc',0x18:'generalized'}

        if tagNumber==0x05: # NULL
            return ''
        elif tagNumber==0x06: # OID/OBJECT_IDENTIFIER
            return ASN1Content.oid(content)
        elif tagNumber in latinTags:
            return content.decode('iso-8859-1').encode('utf8')
        elif tagNumber in hexTags:
            return ASN1Content.hex(content)
        elif tagNumber in strTags:
            return content
        elif tagNumber in timeTags:
            return ASN1Content.date(content)
        elif tagNumber==0x1C: # UniversalString //UCS4 UTF-32
            return content.decode('utf_32').encode('utf8')
        elif tagNumber==0x1C: # BMPString //UCS2
            return content.decode('utf_16').encode('utf8')
        return '[content]'
    @staticmethod
    def oid_name(content):
        oid = ASN1Content.oid(content)
        return ASN1OIDs.oid_name(oid)
    @staticmethod
    def oid(content):
        s=[]
        n=0
        bits=0
        for c in content:
            v = ord(c)
            n = (n << 7 ) | (v & 0x7f)
            bits +=7
            if not (v & 0x80):
                if len(s)==0:
                    s.append( "%s.%s" % ( int(n/40), n%40 ) )
                else:
                    s.append(".%s" % n if bits <32 else "bigint")
                n=0
                bits=0
            pass
        pass
        return "".join(s);
    @staticmethod
    def hex(content):
        s=[]
        for c in content:
            s.append( format(ord(c),"02x") )
        return "".join(s);
    @staticmethod
    def date(d):
        # YYMMDDhhmmZ (test) (YY below 50, 2049... YY>=50 1951)
        # YYYYMMDDhhmmZ (test)
        if len(d)==13 and d[0:12].isdigit() and d[12]=='Z':
            prefix = 20 if int(d[0])<5 else 19
            return "%s%s-%s-%s %s:%s:%s GMT" % (prefix, d[0:2],d[2:4],d[4:6],d[6:8],d[8:10],d[10:12])
        elif len(d)==15 and d[0:14].isdigit() and d[14]=='Z':
            return "%s%s-%s-%s %s:%s:%s GMT" % (d[0:2],d[2:4],d[4:6],d[6:8],d[8:10],d[10:12],d[12:14])
        return "[invalid date]"
        

if __name__ == "__main__":

    filename = "cert.pem"
    try:
        reader = ASN1PEMReader(filename)
        node = ASN1Parser.parse(reader)
        node.outputAll()

    except Exception as e:
        print("Parse Error for %s %s %s" % (filename, type(e), e.message) )
        pass

    sys.exit(0)

