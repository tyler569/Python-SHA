# Python_SHA
# Copyright (C) Tyler Philbrick; 2013
# Licensed GNU GENERAL PUBLIC LICENSE Version 2
# See LICENSE.txt for full license

def _init_vars():
    '''
    Initialises variables for the SHA1 hash algorithm
    '''
    hash_vars = [
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    ]
    ROUND_CONSTS = [
        0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
    ]
    return hash_vars, ROUND_CONSTS

def _msg2chunks(message_):
    '''
    Converts message input to SHA1 chunks.
    
    Input is message in form (message, leading0s)
    message and leading0s are ints

    Outputs array of chunks as integers
    '''
    message, leading0s = message_
    message_len = message.bit_length() + leading0s
    if message_len > (1<<64) - 1:
        raise RuntimeError('Input too large')
    message <<= 1; message += 1  #append '1' to the message4
    message_len += 1
    message <<= 512 - (message_len % 512)
    if message_len % 512 > 448:
        message <<= 512
    message += message_len - 1
    message_len = message.bit_length() + leading0s

    if (message_len/512) % 1 != 0:
        raise RuntimeError('Chunk had bad length')

    if message_len > 448:
        chunks = [(message >> (512*i)) & ((1<<512) - 1)
                for i in range(int(message_len/512))]
        chunks.reverse()
    else:
        chunks = [message]
    return chunks


def _words(chunk):
    '''
    Given an SHA1 chunk and information about what function is being called,
    function generated the word array corresponding to it

    Takes SHA1 chunk as binary string

    Returns array of (ct) binary words as strings for use in SHA1 calculation
    '''
    w = [0 for i in range(80)]
    for i in range(16):
        mask = 0xffffffff << (512-32*(i+1))
        w[i] = (chunk & mask) >> (512-32*(i+1))
    for i in range(16, 80):
        w[i] = _rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)
    return w
    
def _rol(num, val):
    '''
    Binary left rotate

    Takes number to rotate (num) as int and places to rotate (val) as int

    Returns int - rotated number
    '''
    pre = num << val
    over = pre - (pre % 2**32)
    pre -= over
    post = over >> 32
    out = pre + post
    return out
    
def _sha1hash(message):
    '''
    Main loop of the SHA1 hash algorithm

    Takes message as input in form (message, leading0s); tuple of ints
        as provided by hashintf.hash(..)

    Returns hash digest as int
    '''
    chunks = _msg2chunks(message)
    h, K = _init_vars()
    for chunk in chunks:
        xs = h[:]
        w = _words(chunk)
        for i in range(80):
            if i in range(20):
                f = (xs[1] & xs[2]) | (~xs[1] & xs[3])
            elif i in range(20, 40):
                f = xs[1] ^ xs[2] ^ xs[3]
            elif i in range(40, 60):
                f = (xs[1] & xs[2]) | (xs[1] & xs[3]) | (xs[2] & xs[3])
            elif i in range(60, 80):
                f = xs[1] ^ xs[2] ^ xs[3]
            temp = (_rol(xs[0], 5) + f + xs[4] + K[i//20] + w[i]) % 2**32
            xs = [temp, xs[0], _rol(xs[1], 30), xs[2], xs[3]]
            # print(str(i).zfill(2) + ': ' + 
            #       ' '.join([hex(int(i))[2:].zfill(8) for i in xs])) ##
        h = [(h[i] + xs[i]) % 2**32 for i in range(5)]
    digest = sum([h[i] << 32 * (4-i) for i in range(5)])
    return(digest.to_bytes(20, byteorder='big'))
