#!/bin/bash

#yum install python-devel gcc openssl-devel

gcc -fpic -shared x509tools.c -o x509tools.so $(python-config --includes) -lssl -lcrypto
#gcc -fpic $(python-config --includes)  x509verify.c -o x509verify.so  -lssl -lcrypto $(python-config --libs)
