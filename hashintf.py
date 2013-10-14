# Python_SHA
# Copyright (C) 2013 Tyler Philbrick
# See LICENSE.txt for full license


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

def _hash_prep(algo, message):
    assert type(message) is str
    message_enc = message.encode()
    message_int = 0
    for i in message_enc:
        message_int <<= 8
        message_int += i
    i = 0
    leading0s = 0
    while leading0s == 8*i:
        try:
            leading0s += 8 - message_enc[i].bit_length()
        except IndexError:
            break
        i += 1
    return message_int, leading0s


def sha1(message, debug="no"):
    hash_inpt = _hash_prep(message)
    SHA1._hash(message, debug)

def sha224(message, debug="no"):
    hash_inpt = _hash_prep(message)
    SHA2._hash(message, "sha224", debug)
    
def sha256(message, debug="no"):
    hash_inpt = _hash_prep(message)
    SHA2._hash(message, "sha256", debug)
    
def sha384(message, debug="no"):
    hash_inpt = _hash_prep(message)
    SHA2._hash(message, "sha384", debug)
    
def sha512(message, debug="no"):
    hash_inpt = _hash_prep(message)
    SHA2._hash(message, "sha512", debug)
    
def sha512_224(message, debug="no"):
    hash_inpt = _hash_prep(message)
    SHA2._hash(message, "sha512/224", debug)

def sha512_256(message, debug="no"):
    hash_inpt = _hash_prep(message)
    SHA2._hash(message, "sha512/256", debug)
    
