import sys


def init_vars():
    '''
    Initialises variables for the SHA256 hash algorithm.

    Takes message as input

    Returns tuple - (hash_vars, ROUND_CONSTS)
    '''
    hash_vars = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    ROUND_CONSTS = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    return hash_vars, ROUND_CONSTS

def in2chunks(message):
    '''
    Converts command line input to SHA256 chunks.

    Takes command line (concatinates all arguments [1:] with spaces
    to mirror how they are input.  Can be given all as one argument as well

    Returns array of SHA256 chunks corresponding to input data
    as binary string
    '''
    message_bin = ''
    try:
        message_bin = bin(int(message))
    except:
        for i in message.encode():
            message_bin += fill_bin(i, 8)
    length = len(message_bin)
    message_bin += '1' # Appended bit
    chunks = []

    pad_0s = '0' * (512 - (len(message_bin) + 64) % 512)
    chunk_bin = message_bin + pad_0s
    length_bin = bin(length)[2:]
    pad_0s = (64 - len(length_bin)) * '0'
    chunk_bin += (pad_0s + length_bin)
    chunks = []
    
    if len(chunk_bin) > 512:
        for i in range(int(len(chunk_bin) / 512)):
            chunks.append(chunk_bin[512*i:512*(i+1)])
    else:
        chunks = [chunk_bin]
    return chunks

def fill_bin(val, num_bits):
    '''
    Fills in the dropped 0's for binary numbers

    Takes val as string from bin() function - format '0b...'

    Returns same number but with n 0's added such that len(input + n*'0')
    is == num_bits.  Function also snips '0b' from out
    '''
    bin_out = bin(val)[2:]
    bin_out = (num_bits - len(bin_out)) * '0' + bin_out
    return bin_out
    
def words(chunk_bin):
    '''
    Given an SHA256 chunk, function generated the word array corresponding to it

    Takes SHA256 chunk as binary string

    Returns array of 64 binary words as strings for use in SHA256 calculation
    '''
    w = [0 for i in range(64)]
    for i in range(16):
        start = 32*i
        end = 32*(i+1)
        w[i] = int(chunk_bin[start:end], 2)
    for i in range(16, 64):
        s0 = ror(w[i-15], 7) ^ ror(w[i-15], 18) ^ (w[i-15] >> 3)
        s1 = ror(w[i-2], 17) ^ ror(w[i-2], 19) ^ (w[i-2] >> 10)
        w[i] = (w[i-16] + s0 + w[i-7] + s1) % 2**32
    return w
    
def ror(num, val):
    '''
    Binary right rotate

    Takes number to rotate (num) as int and places to rotate (val) as int

    Returns int - rotated number
    '''
    pre = (num % 2 ** val) * 2**(32 - val) 
    post = num >> val
    return pre + post
    
def sha256hash(message):
    '''
    Main loop of the SHA256 hash algorithm

    Takes data as input

    Returns hash digest as hex string without '0x'
    '''
    chunks = in2chunks(message)
    h, k = init_vars()
    for chunk in chunks:
        xs = h[:]
        w = words(chunk)
        for i in range(64):
            S1 = ror(xs[4], 6) ^ ror(xs[4], 11) ^ ror(xs[4], 25)
            ch = (xs[4] & xs[5]) ^ (~xs[4] & xs[6])
            temp = (xs[7] + S1 + ch + k[i] + w[i]) % 2**32
            xs[3] = (xs[3] + temp) % 2**32
            S0 = ror(xs[0], 2) ^ ror(xs[0], 13) ^ ror(xs[0], 22)
            maj = (xs[0] & xs[1]) ^ (xs[0] & xs[2]) ^ (xs[1] & xs[2])
            temp = (temp + S0 + maj) % 2**32
            
            xs = [temp] + [xs[i-1] for i in range(1, 8)]
            # print(str(i) + ': ' + ' '.join([hex(int(i))[2:] for i in xs]))
        h = [(h[i] + xs[i]) % 2**32 for i in range(8)]
    digest = ''.join([str((8 - len(hex(i)[2:]))*'0' + hex(i)[2:]) for i in h])
    return(digest)
    
def main():
    hashinput = ' '.join(sys.argv[1:])
    digest = sha256hash(hashinput)
    digest = '0x' + digest#.upper()
    print(digest)
    
    
if __name__ == '__main__':
    main()
