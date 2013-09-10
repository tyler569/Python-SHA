import hashint
import sys

try:
    bits = sys.argv[1]
except:
    bits = '1'
try:
    message = sys.argv[2]
except:
    message = ''

digest = hashint.hash(bits, message)
print(hex(digest))
