import algorithms.SHA1 as SHA1
import algorithms.SHA2 as SHA2

class InputError(RuntimeError):
    pass

#determine and pass leading0s here

def hash(bits, message):

    if type(message) is str:
        print(message)
        message = repr(message)
        print(message)
        m = message.encode()
        message = 0
        for i in m:
            message <<= 8
            message += i
        i = 0
        leading0s = 0
        while leading0s == 8*i:
            leading0s += 8 - m[0].bit_length()
            i += 1
        print(leading0s)


    if bits in ('1', '224', '256', '384', '512', '512/224', '512/256'):
        if bits == '1':
            digest = SHA1._sha1hash(message, leading0s)
        else:
            digest = SHA2._sha2hash(message, bits)

        return(digest)
    else:
        raise InputError('Algorithm nonexistant or unimplemented')
