#!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Counter
import sys
import os.path
# from secrets import token_bytes
# token_bytes(len(ptexts[0]))


if __name__=="__main__":
    if len(sys.argv) < 3:
        print "Usage: %s key filenames..."
        exit
    key = sys.argv[1]
    args = sys.argv[2:]

    h = SHA256.new()
    h.update(key)
    key = h.digest()
    
    
    for name in args:
        print name
        outname = name + ".out"
        if name.endswith(".out") and not os.path.isfile(name[0:len(name)-4]):
            outname = name[0:len(name)-4]
        f = open(name, mode='r')
        data = f.read()
        ctr = Counter.new(128)
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        out = open(outname, mode='w')
        out.write(cipher.encrypt(data))
        f.close()
        out.close()
                  

    
