#!/bin/bash
openssl req -newkey rsa:1024 \
    -passout pass:abcd \
    -subj "/" -sha1 \
    -keyout rootkey.pem \
    -out rootreq.pem
openssl x509 -req -in rootreq.pem \
    -passin pass:abcd \
    -sha1 -extensions v3_ca \
    -signkey rootkey.pem \
    -out rootcert.pem
cat rootcert.pem rootkey.pem  > cacert.pem

openssl req -newkey rsa:1024 \
    -passout pass:abcd \
    -subj "/" -sha1 \
    -keyout serverkey.pem \
    -out serverreq.pem
openssl x509 -req \
    -in serverreq.pem \
    -passin pass:abcd \
    -sha1 -extensions usr_cert \
    -CA cacert.pem  \
    -CAkey cacert.pem \
    -CAcreateserial \
    -out servercert.pem
cat servercert.pem serverkey.pem rootcert.pem > myserver.pem