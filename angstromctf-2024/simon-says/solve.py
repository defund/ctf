from Crypto.Random.random import getrandbits
from z3 import *

from simon_says import Simon

def decrypt_block(simon, x, y):
	for i in range(simon.T - 1, -1, -1):
		tmp = x
		x = y ^ (simon.S(x, 1) & simon.S(x, 8)) ^ simon.S(x, 2) ^ simon.k[i]
		y = tmp
	return y, x

def decrypt(simon, ct):
	pt = bytes()
	for i in range(0, len(ct), 16):
		x = int.from_bytes(ct[i:i+8], 'big')
		y = int.from_bytes(ct[i+8:i+16], 'big')
		x, y = decrypt_block(simon, y, x)
		pt += x.to_bytes(8, 'big')
		pt += y.to_bytes(8, 'big')
	return pt

with open('simon_says_out.txt') as f:
	ct68, ct69, ct72 = map(bytes.fromhex, f.readlines())

simon = Simon([0,0,0,0], 68)
n = simon.n
m = simon.m
z = simon.z

def S(x, j):
	if type(x) == z3.BitVecRef:
		s = RotateLeft
	else:
		s = simon.S
	return s(x, j)

def f(x):
	return S(x, 1) & S(x, 8) ^ S(x, 2)

solver = Solver()
k68, k69, k70, k71 = BitVecs('k68 k69 k70 k71', n)
for i in range(0, len(ct68), 16):
	e68 = (int.from_bytes(ct68[i:i+8], 'big'), int.from_bytes(ct68[i+8:i+16], 'big'))
	e69 = (int.from_bytes(ct69[i:i+8], 'big'), int.from_bytes(ct69[i+8:i+16], 'big'))
	e72 = (int.from_bytes(ct72[i:i+8], 'big'), int.from_bytes(ct72[i+8:i+16], 'big'))
	e70 = BitVecs(f'e70_{i}_0 e70_{i}_1', n)
	e71 = BitVecs(f'e71_{i}_0 e71_{i}_1', n)
	solver.add(e69[0] == e68[1] ^ f(e68[0]) ^ k68)
	solver.add(e69[1] == e68[0])
	solver.add(e70[0] == e69[1] ^ f(e69[0]) ^ k69)
	solver.add(e70[1] == e69[0])
	solver.add(e71[0] == e70[1] ^ f(e70[0]) ^ k70)
	solver.add(e71[1] == e70[0])
	solver.add(e72[0] == e71[1] ^ f(e71[0]) ^ k71)
	solver.add(e72[1] == e71[0])
assert solver.check()
model = solver.model()

while True:
	print(solver.check())
	model = solver.model()

	k = [0]*68
	k.append(model[k68].as_long())
	k.append(model[k69].as_long())
	k.append(model[k70].as_long())
	k.append(model[k71].as_long())

	for i in range(71, m-1, -1):
		tmp = S(k[i - 1], -3)
		tmp ^= k[i - 3]
		tmp ^= S(tmp, -1)
		zi = (z >> ((i - m) % 62)) & 1
		k[i - 4] = k[i] ^ tmp ^ zi ^ 0xfffffffffffffffc

	simon72 = Simon(k[:4], 72)
	flag = decrypt(simon72, ct72)
	if flag.startswith(b'actf{'):
		print(flag.strip(b'\x00'))
		exit()

	solver.add(k71 != model[k71].as_long())
