#!/usr/bin/python

import sys

raw_key = [l for l in sys.stdin]

i = 0

for l in raw_key:
    i += 1
    if "Subject Key Identifier" in l:
        break

ski = raw_key[i].replace(":", "").upper().strip()
print(ski)
