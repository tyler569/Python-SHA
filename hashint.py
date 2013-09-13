import algorithms.SHA1 as SHA1
import algorithms.SHA2 as SHA2

class InputError(RuntimeError):
    pass

##CONVERT WHOLE THING TO ACCEPT INTS INSTEAD< ITS BETTER -
##PERHAPS MAP ALGOS TO ARBITRARY VALUES INSTEAD OF BIT LENGTH
#EG
##MD5 - 0
##SHA1 - 1
##SHA2 - 2
###SHA224 - 2.1
###SHA256 - 2.2

#ETC.

######## DOO IT ########

def hash(bits, message):

    if bits in ('1', '224', '256', '384', '512', '512/224', '512/256'):
        if bits == '1':
            digest = SHA1._sha1hash(message)
        else:
            digest = SHA2._sha2hash(message, bits)

        return(digest)
    else:
        raise InputError('Algorithm nonexistant or unimplemented')
