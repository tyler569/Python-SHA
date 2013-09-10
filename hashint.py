import algorithms.SHA1 as SHA1
import algorithms.SHA2 as SHA2

def hash(bits, message):

    if bits in ('1', '224', '256', '384', '512', '512/224', '512/256'):
        if bits == '1':
            digest = SHA1._sha1hash(message)
        else:
            digest = SHA2._sha2hash(message, bits)

    return(digest)
