import hashintf
import sys

try:
	sys.argv[2]
except IndexError:
	sys.argv.append('')

bits, message = sys.argv[1:3]

digest = hashintf.hash(bits, message)


print(hex(digest))
