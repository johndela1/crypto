#!/usr/bin/env python

from textwrap import wrap
from itertools import chain, cycle


def chunks(seq, size):
    return (seq[i:i+size] for i in range(0, len(seq), size))


def chunks2(seq, size):
    itt = iter(seq)
    while(True):
        acc = []
        for e in range(size):
            acc.append(chr(next(itt)))
        yield bytes(''.join(acc), 'ascii')


def dec_16(seq):
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


def jex(chunk):
    x, y, z = chunk
    n = x << 16 | y << 8 | z
    n1 = n >> 18 & 63
    n2 = n >> 12 & 63
    n3 = n >> 6 & 63
    n4 = n & 63
    return bytes(SYMS[n1]+SYMS[n2]+SYMS[n3]+SYMS[n4], 'ascii')


def enc_64(seq):
    acc = bytes('', 'ascii')
    for chunk in chunks(pad2(seq, 3), 3):
        acc += (jex(chunk))
    return acc


def dec_64(seq):
    acc = []
    for s1, s2, s3, s4 in chunks(pad2(seq,4), 4):
        x1 = SYMS.index(chr(s1))
        x2 = SYMS.index(chr(s2))
        x3 = SYMS.index(chr(s3))
        x4 = SYMS.index(chr(s4))
        x = x1 << 18 | x2 << 12 | x3 << 6 | x4
        r1 = x >> 16 & 255
        r2 = x >> 8 & 255
        r3 = x & 255
        acc.append(r1)
        acc.append(r2)
        acc.append(r3)
    return acc


def enc_16_64(seq):
    return enc_64(dec_16(seq))


def xor(s1, s2):
    return bytes(x ^ y for x, y in zip(s1, s2))


def xor_repeat(key, lines):
    c = cycle(ord(k) for k in key)
    return bytes(x ^ y for x, y in zip(lines, c))

def h_dist(s1, s2):
    return sum(bin(e).count('1') for e in xor(s1, s2))


def key_length_guess(seq):
    acc = []
    for size in range(2, 10):
        s1 = seq[:size]
        s2 = seq[size:size*2]
        dist = h_dist(s1, s2) / size
        acc.append((dist, size))
#    import pdb;pdb.set_trace()
    return sorted(acc)[:2]

def foo(seq):
    length = len(seq)
    for i in range(256):
        try:
            yield xor(seq, [i] * length)
        except UnicodeEncodeError:
            continue


def cracked(seq):
    try:
        return sorted(((e, str(e).count(' '))
                       for e in foo(seq)), key=lambda x: -x[1])[0]
    except IndexError:
        return None, None


def bar():
    with open('input.txt') as f:
        for l in f:
            bs = bytes(l.strip(), 'ascii')
            msg, count = cracked(bs)
            if msg and count > 3:
                print(msg)


if __name__ == '__main__':
    s1 = b'this is a test'
    s2 = b'wokka wokka!!!'
    assert(h_dist(s1, s2) == 37)
    base_16 = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    base_64 = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    b1 =  bytes.fromhex('1c0111001f010100061a024b53535009181c')
    b2 = bytes.fromhex('686974207468652062756c6c277320657965')
    c = bytes.fromhex('746865206b696420646f6e277420706c6179')
    assert(enc_16_64(base_16) == base_64) 
    assert(xor(b1, b2) == c)

    lines = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    ref = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    cypher_text = xor_repeat('ICE', lines)
    assert(cypher_text.hex() == ref)
    assert(xor_repeat('ICE', cypher_text) == lines)

    #enc_hex = b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    enc_b64 = b'HUIfTQsPAh9PE048GmllH0kcDk4TAQsHThsBFkU2AB4BSWQgVB0dQzNTTmVS'
    bts = dec_64(enc_b64)
    #    print('decrypt', xor_repeat('ICE', cypher_text))
    bts = xor_repeat('ICE', b'Since we are all here working on the farm we will talk a lot.  This is a test of some new crypto system')

    print('decrypt', xor_repeat('ICEMAN', bts))
    print(key_length_guess(bts))
