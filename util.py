#!/usr/bin/env python

from textwrap import wrap
from itertools import chain, cycle
import base64
from binascii import hexlify, unhexlify


def chunks(seq, size):
    return (seq[i:i+size] for i in range(0, len(seq), size))


def chunks2(seq, size):
    itt = iter(seq)
    while(True):
        acc = []
        for e in range(size):
            acc.append(chr(next(itt)))
        yield bytes(''.join(acc), 'ascii')


def b16_decoded(seq):
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


SYMS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def b64lify(chunk):
    x, y, z = chunk
    if z == ord('='):
        n = x
        n1 = n >> 6 & 63
        n2 = n & 63
        return bytes(SYMS[n1]+SYMS[n2]+'==', 'ascii')

    elif y == ord('='):
        n = x << 8 | y
        n1 = n >> 12 & 63
        n2 = n >> 6 & 63
        n3 = n & 63
        return bytes(SYMS[n1]+SYMS[n2]+SYMS[n3]+'=', 'ascii')
    else:
        n = x << 16 | y << 8 | z
        n1 = n >> 18 & 63
        n2 = n >> 12 & 63
        n3 = n >> 6 & 63
        n4 = n & 63
        return bytes(SYMS[n1]+SYMS[n2]+SYMS[n3]+SYMS[n4], 'ascii')


def b64encoded(seq):
    acc = bytes('', 'ascii')
    for chunk in chunks(pad2(seq, 3), 3):
        acc += (b64lify(chunk))
    return acc


def b64decoded(seq):
    acc = []
    for chunk in chunks(seq, 4):
        if b'==' in chunk:
            x1 = SYMS.index(chr(chunk[0]))
            x2 = SYMS.index(chr(chunk[1]))
            x = (x1 << 6 | x2) >> 4 
            r1 = x & 255
            acc.append(chr(r1))
        elif b'=' in chunk:
            x1 = SYMS.index(chr(chunk[0]))
            x2 = SYMS.index(chr(chunk[1]))
            x3 = SYMS.index(chr(chunk[2]))
            x = (x1 << 18 | x2 << 12 | x3 << 6) >> 8
            r1 = x >> 8 & 255
            r2 = x & 255
            acc.append(chr(r1))
            acc.append(chr(r2))
        else:
            x1 = SYMS.index(chr(chunk[0]))
            x2 = SYMS.index(chr(chunk[1]))
            x3 = SYMS.index(chr(chunk[2]))
            x4 = SYMS.index(chr(chunk[3]))
            x = x1 << 18 | x2 << 12 | x3 << 6 | x4
            r1 = x >> 16 & 255
            r2 = x >> 8 & 255
            r3 = x & 255
            acc.append(chr(r1))
            acc.append(chr(r2))
            acc.append(chr(r3))
    return bytes(''.join(acc), 'ascii')


def b16_64_encoded(seq):
    return b64encoded(b16_decoded(seq))


def xor(s1, s2):
    return bytes(x ^ y for x, y in zip(s1, s2))


def xor_repeat(key, lines):
    c = cycle(ord(k) for k in key)
    return bytes(x ^ y for x, y in zip(lines, c))


def h_dist(s1, s2):
    return sum(bin(e).count('1') for e in xor(s1, s2))


def key_size_guess(seq):
    acc = []
    for size in range(2, 10):
        s1 = seq[:size]
        s2 = seq[size:size*2]
        dist = h_dist(s1, s2) / size
        acc.append((dist, size))
    return sorted(acc)[0][1]


def foo(seq):
    length = len(seq)
    for i in range(256):
        try:
            yield xor(seq, [i] * length), i
        except UnicodeEncodeError:
            continue


def cracked(seq):
    try:
        return sorted(((e, str(e).count(' '), k)
                       for e, k in foo(seq)), key=lambda x: -x[1])[0]
    except IndexError:
        return None, None


def bar():
    with open('input.txt') as f:
        for l in f:
            bs = bytes(l.strip(), 'ascii')
            msg, count = cracked(bs)
            if msg and count > 3:
                print(msg)


def transpose(bts, key_size):
    return bytes(zip(*chunks(bts, key_size)))
    acc = [[] for _ in range(key_size)]
    for n, chunk in enumerate(chunks(bts, key_size)):
        for m, val in enumerate(chunk):
            acc[m].append(val)
    return acc


if __name__ == '__main__':
    s1 = b'this is a test'
    s2 = b'wokka wokka!!!'
    assert(h_dist(s1, s2) == 37)
    base_16 = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    base_64 = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    b1 =  bytes.fromhex('1c0111001f010100061a024b53535009181c')
    b2 = bytes.fromhex('686974207468652062756c6c277320657965')
    c = bytes.fromhex('746865206b696420646f6e277420706c6179')
   # assert(enc_16_64(base_16) == base_64) 
    assert(xor(b1, b2) == c)

    lines = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    ref = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    cypher_text = xor_repeat('ICE', lines)
    assert(cypher_text.hex() == ref)
    assert(xor_repeat('ICE', cypher_text) == lines)
    msgs = [b'heynowss', b'heynows', b'heynow']
    for msg in msgs:
        cypher_text_ref = base64.b64encode(msg)
        cypher_text = b64encoded(msg)
        print(cypher_text_ref, cypher_text)
        assert(b64decoded(cypher_text_ref) == base64.b64decode(cypher_text_ref))
        #assert(cypher_text_ref == cypher_text)

    with open('6.txt') as f:
        msg = bytes([ord(x) for x in f.read().replace('\n', '')])

    ref = base64.b64decode(msg)
    bts = b64decoded(msg)
#    print (ref, '\n' +  bts)

#    print("ref   ", ref.hex()[:50], '\ncalcul', bts.hex()[:50])
    ct = b'HUIfTQsPAh9PE048GmllH0kcDk4TAQsHThsBFkU2AB4BSWQgVB0dQzNTTmVS'
    ct = b64encoded(b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    import pdb;pdb.set_trace()

    bts = b64decoded(ct)
    print(cracked(unhexlify(bts)))
    exit()
    print (bts)

    
    print(cracked(bts))
    exit()
    #print("decodeer test", bts)
    bts_in = unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')

    print('-----') 
    print(hexlify(b64decoded(ct)))
    print(base64.b64decode(ct))
    exit()

    #    print('decrypt', xor_repeat('ICE', cypher_text))
    # bts = xor_repeat('ICE', b'Since we are all here working on the farm we will talk a lot.  This is a test of some new crypto system')

    #    print('decrypt', xor_repeat('ICEMAN', bts))
    key_size = key_size_guess(bts)
#    print(bts)
    tran = transpose(bts,  key_size)

    from collections import defaultdict
    d = defaultdict(int)
    for tr in tran:
        msg, score, key = cracked(tr)
        d[key] += score

    print(d)
