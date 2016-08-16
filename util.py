#!/usr/bin/env python

from textwrap import wrap
from itertools import cycle
import base64
from binascii import hexlify, unhexlify


def chunks(seq, size):
    return (seq[i:i+size] for i in range(0, len(seq), size))


def chunks_lazy(seq, size):
    itt = iter(seq)
    while(True):
        yield bytes(''.join([chr(next(itt))
                             for _ in range(size)]),
                    'ascii',
                    )


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


def xor(s1, s2):
    return bytes(x ^ y for x, y in zip(s1, s2))


def xor_key(key, seq):
    return xor(seq, cycle(ord(k) for k in key))


def dist(s1, s2):
    return sum(bin(e).count('1') for e in xor(s1, s2))


def key_size_guess(seq):
    n = 0
    acc = []
    for size in range(2, 10):
        s1 = seq[:size]
        s2 = seq[size:size*2]
        d = dist(s1, s2) / size
        acc.append((d, size))
    return sorted(acc)[0][1]


def xor_brute(seq):
    length = len(seq)
    for i in range(256):
        try:
            yield xor(seq, [i] * length), i
        except UnicodeEncodeError:
            continue


def cracked(seq):
    try:
        return sorted(
            ((res, str(res).count(' '), key)
             for res, key in xor_brute(seq)),
            key=lambda x: x[1],
            reverse=True,
            )[0]
    except IndexError:
        return None, None, None


def bar():
    with open('input.txt') as f:
        for l in f:
            bs = bytes(l.strip(), 'ascii')
            msg, count = cracked(bs)
            if msg and count > 3:
                print(msg)


def transpose(bts, key_size):
    return bytes(zip(*chunks(bts, key_size)))
