#!/bin/bash
g++ -g -I/usr/include/libxml2 -I/usr/include/libofetion  -lofetion -lxml2 -lssl -lcrypto  -lpthread -o fetion-mail cliofetion.c
