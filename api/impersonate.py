#!/usr/bin/env python3
import sys
from healthid.security import impersonate

if len(sys.argv) != 2:
    print('Usage: impersonate.py <ACCOUNT>') 
    exit(1)
token = impersonate(sys.argv[1])
print (token)