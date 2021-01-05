#!/usr/bin/python

import sys
from shell import shell

path = sys.argv[1]
raw_key = shell(f"openssl req -in {path} -text")

i = 0

for l in raw_key.output():
    i += 1
    if "Subject Key Identifier" in l:
        break

ski = raw_key.output()[i].replace(":", "").upper().strip()
print(ski)
