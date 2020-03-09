from Crypto.Cipher import PKCS1_OAEP
from Crypto.IO import PEM
from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto.Util.number import GCD, inverse

from local import flag

with open('primes.txt') as f:
	primes = [int(p) for p in f.readlines()]

def query():
	p, q = random.sample(primes, 2)
	n = p * q
	e = 65537
	key = RSA.construct((n, e))
	cipher = PKCS1_OAEP.new(key)
	enc = cipher.encrypt(flag)
	return key, enc

def collide():
	log = []
	while True:
		key, enc = query()
		for n in log:
			p = GCD(key.n, n)
			if p != 1:
				q = key.n // p
				return p, q, enc
		log.append(key.n)

p, q, enc = collide()
n = p * q
phi = (p-1) * (q-1)
e = 65537
d = inverse(e, phi)
key = RSA.construct((n, e, d))

cipher = PKCS1_OAEP.new(key)
flag = cipher.decrypt(enc).decode()
print(flag)
