#!/usr/bin/env python

from util import *


def test_dist():
    s1 = b'this is a test'
    s2 = b'wokka wokka!!!'
    assert(dist(s1, s2) == 37)


def test_xor():
    b1 =  bytes.fromhex('1c0111001f010100061a024b53535009181c')
    b2 = bytes.fromhex('686974207468652062756c6c277320657965')
    c = bytes.fromhex('746865206b696420646f6e277420706c6179')
    assert(xor(b1, b2) == c)


def test_b64encoded():
    ours = b64encoded(unhexlify(
        '49276d206b696c6c696e6720796f757220627261696e206c696b6520612' +
        '0706f69736f6e6f7573206d757368726f6f6d'))
    ref = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert(ours == ref)


def test_xor_key():
    s = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    ref = (b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527' +
           b'2a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f')
    cypher_text = xor_key('ICE', s)
    assert(hexlify(cypher_text) == ref)
    assert(xor_key('ICE', cypher_text) == s)


def test_codec():
    msgs = [b'heynowss', b'heynows', b'heynow']
    for msg in msgs:
        cypher_text_ref = base64.b64encode(msg)
        cypher_text = b64encoded(msg)
        print(cypher_text_ref, cypher_text)
        assert(b64decoded(cypher_text_ref) == base64.b64decode(cypher_text_ref))
        #assert(cypher_text_ref == cypher_text)


if __name__ == '__main__':

    with open('6.txt') as f:
        msg = bytes(f.read().replace('\n', ''), 'ascii')

    ref = base64.b64decode(msg)
    bts = b64decoded(msg)
    #    print (ref, '\n' +  bts)

    #    print("ref   ", ref.hex()[:50], '\ncalcul', bts.hex()[:50])
    ours= hexlify(b64decoded(b'HUIfTQsPAh9PE048GmllH0kcDk4TAQsHThsBFkU2AB4BSWQgVB0dQzNT'))
    ref = b64decoded(base64.b64encode(
        b'1D421F4D0B0F021F4F134E3C1A69651F491C0E4E13010B074E1B01164536001E01496420541D1D433353'))


 #   print(cracked(unhexlify(ours)))
  #  print(cracked(unhexlify(ref)))
    
    print(cracked(unhexlify(ref.hex())))
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

    #    print('decrypt', xor_key('ICE', cypher_text))
    # bts = xor_key('ICE', b'Since we are all here working on the farm we will talk a lot.  This is a test of some new crypto system')

    #    print('decrypt', xor_key('ICEMAN', bts))
    key_size = key_size_guess(bts)
#    print(bts)
    tran = transpose(bts,  key_size)

    from collections import defaultdict
    d = defaultdict(int)
    for tr in tran:
        msg, score, key = cracked(tr)
        d[key] += score

    print(d)
