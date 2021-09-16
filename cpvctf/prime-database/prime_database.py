from Crypto.Cipher import PKCS1_OAEP
from Crypto.IO import PEM
from Crypto.PublicKey import RSA
from Crypto.Random import random

from local import flag

with open('primes.txt') as f:
	primes = [int(p) for p in f.readlines()]

print('{} primes in database.'.format(len(primes)))

p, q = random.sample(primes, 2)
n = p * q
e = 65537
key = RSA.construct((n, e))

cipher = PKCS1_OAEP.new(key)
enc = cipher.encrypt(flag)

print(key.exportKey().decode())
print(PEM.encode(enc, 'FLAG'))
