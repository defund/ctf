#!/usr/local/bin/python

import hashlib
import sys
from Crypto.PublicKey import RSA

PARAM = 128
RSA_BITS = 4096
LOG_POW_COST = 8

def deserialize(n, s):
	x = int(s) % n
	assert x != 0 and x != 1 and x != n - 1
	return x

def _hash(*args):
	buf = b''.join([v.to_bytes(RSA_BITS // 8, 'big') for v in args])
	shake = hashlib.shake_256(buf)
	return int.from_bytes(shake.digest(PARAM // 8), 'big')

def _prove(n, g, h):
	proof = []
	new_g = g
	new_h = h
	for i in range(LOG_POW_COST):
		v = pow(g, 1 << (1 << (LOG_POW_COST - i - 1)), n)
		proof.append(v)
		r = _hash(g, *proof)
		new_g = pow(new_g, r, n) * v % n
		new_h = pow(v, r, n) * new_h % n
	return proof

def _verify(n, g, h, proof):
	new_g = g
	new_h = h
	for i in range(LOG_POW_COST):
		v = proof[i]
		r = _hash(g, *proof[:i + 1])
		new_g = pow(new_g, r, n) * v % n
		new_h = pow(v, r, n) * new_h % n
	return pow(new_g, 2, n) == new_h

def prove_pow(n, g):
	h = pow(g, 1 << (1 << LOG_POW_COST), n)
	return h, _prove(n, g, h)

def verify_pow(n, g, h, proof):
	assert _verify(n, g, h, proof)

if __name__ == '__main__':
	if len(sys.argv) == 2 and sys.argv[1] == 'setup':
		key = RSA.generate(RSA_BITS)
		with open('n.txt', 'w') as f:
			f.write(str(key.n))
	else:
		with open('flag.txt') as f:
			flag = f.read().strip()
		with open('n.txt') as f:
			n = int(f.read())
		print(f'{n = }')
		g = deserialize(n, input('g: '))
		h = deserialize(n, input('h: '))
		proof = [deserialize(n, s) for s in input('proof: ').split(',')]
		verify_pow(n, g, h, proof)
		print(flag)
