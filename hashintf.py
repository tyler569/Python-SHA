import algorithms.SHA1 as SHA1
import algorithms.SHA2 as SHA2

class InputError(RuntimeError):
    pass

_valid_algorithms = [
    'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'SHA512/224',
    'SHA512/256'
]

def valid_algorithms():
    return _valid_algorithms

def hash(algo, message):
    if type(message) is str:
        message = repr(message)
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
    else:
        raise InputError('Message is not string')

    if algo in _valid_algorithms:
        if algo == 'SHA1':
            digest = SHA1._sha1hash((message, leading0s))
        elif algo.startswith('SHA'):
            digest = SHA2._sha2hash((message, leading0s), algo)
        return(digest)
    else:
        raise InputError('Algorithm nonexistant or unimplemented')
