
def chunks(seq, size):
    return (seq[i:i+size] for i in range(0, len(seq), size))


#def encode_16(seq):
#    return ''.join([hex(ord(c))[2:] for c in seq])

def decode_16(seq):
    return bytes(''.join(
        chr(int(chunk, 16)) for chunk in chunks(seq, 2)), 'ascii')


def pad(seq, l):
    for count, i in enumerate(seq):
        yield i
        while count < l - 1:
            count += 1
            yield '='

def pad2(seq, align):
    l = list(seq)
    length = len(l)
    mod = length % align
    if mod:
        return bytes(l + ([ord('=')]  * (align - mod)))
    return bytes(l)


def jex(chunk):
    SYMS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    x, y, z = chunk
    n = x << 16 | y << 8 | z
    n1 = n >> 18 & 63
    n2 = n >> 12 & 63
    n3 = n >> 6 & 63
    n4 = n  & 63
    return SYMS[n1]+SYMS[n2]+SYMS[n3]+SYMS[n4]


def encode_64(seq):
    return bytes(''.join(jex(chunk) for chunk in chunks(pad2(seq, 3), 3)), 'ascii')


def encode_16_64(seq):
    return encode_64(decode_16(seq))


def hex_iter(seq):
    return chunks(seq, 2)


def xor(s1, s2):
    return bytes(''.join('%0x' % (int(x, 16) ^ int(y, 16))
                          for x, y in zip(hex_iter(s1), hex_iter(s2))), 'ascii')


if __name__ == '__main__':
    base_16 = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    base_64 = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    b1 =  b'1c0111001f010100061a024b53535009181c'
    b2 = b'686974207468652062756c6c277320657965'
    c = b'746865206b696420646f6e277420706c6179'
    
    assert(encode_16_64(base_16) == base_64) 
    assert(xor(b1, b2) == c)
    #plain = decode_16(base_16)
    #print('plain', plain)
    #print('b64', encode_64(plain))
