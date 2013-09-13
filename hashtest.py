import hashintf
import sys

bits, message = sys.argv[1:3]

digest = hashintf.hash(bits, message)
print(hex(digest))
