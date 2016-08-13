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


def enc_16(seq):
    return ''.join('%0x' % c for c in seq)


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


def jex(chunk):
    SYMS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    x, y, z = chunk
    n = x << 16 | y << 8 | z
    n1 = n >> 18 & 63
    n2 = n >> 12 & 63
    n3 = n >> 6 & 63
    n4 = n  & 63
    return SYMS[n1]+SYMS[n2]+SYMS[n3]+SYMS[n4]


def enc_64(seq):
    return bytes(''.join(jex(chunk) for chunk in chunks(pad2(seq, 3), 3)), 'ascii')


def enc_16_64(seq):
    return enc_64(dec_16(seq))


def hex_iter(seq):
    return chunks(seq, 2)


def xor(s1, s2):
    return bytes(''.join('%0x' % (int(x, 16) ^ int(y, 16))
                          for x, y in zip(hex_iter(s1), hex_iter(s2))), 'ascii')

def foo(seq):
    length = len(seq)
    for i in range(256):
        try:
            yield dec_16(xor(seq, ''.join(['%0x' % i] * length)))
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


def xor_repeat(key, lines):
    return (x ^ ord(y) for x, y in zip(
        bytes(''.join(chain(*lines)), 'ascii'),
        cycle(key)))


def h_dist(s1, s2):
    return sum(bin(int(e, 16)).count('1') for e in hex_iter(xor(s1, s2)))


if __name__ == '__main__':
    base_16 = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    base_64 = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    b1 =  b'1c0111001f010100061a024b53535009181c'
    b2 = b'686974207468652062756c6c277320657965'
    c = b'746865206b696420646f6e277420706c6179'

    assert(enc_16_64(base_16) == base_64) 
    assert(xor(b1, b2) == c)
    # plain = dec_16(base_16)
    # print('plain', plain)
    # print('b64', en_64(plain))
    # enc_hex = b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

    # print(cracked(enc_hex))
    # print(bar())
    s=["Burning 'em, if you ain't quick and nimble",
       "I go crazy when I hear a cymbal"]
    for l in wrap(enc_16(xor_repeat('ICE', s)), 74):
        print(l)

    # print(xor_repeat('ICE', xor_repeat('ICE', b'Hey now')))

    # 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
    # a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
    s1 = b'this is a test'
    s2 = b'wokka wokka!!!'

    print(h_dist(enc_16(s1), enc_16(s2)))
