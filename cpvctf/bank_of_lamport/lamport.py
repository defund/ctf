from Crypto.Hash import SHA3_256
from Crypto.Random import get_random_bytes

def pack(fn, k):
	with open(fn, 'w') as f:
		f.write('\n'.join([' '.join([x.hex() for x in y]) for y in k]))

def unpack(fn):
	with open(fn, 'r') as f:
		return [[bytes.fromhex(x.strip()) for x in y.split(' ')] for y in f.readlines()]

def generate():
	sk = [[get_random_bytes(32) for _ in range(2)] for _ in range(256)]
	pk = [[SHA3_256.new().update(x).digest() for x in y] for y in sk]
	return pk, sk

def sign(m, sk):
	h = int.from_bytes(SHA3_256.new().update(m).digest(), 'big')
	s = []
	for i in range(256):
		b = (h >> i) & 1
		s.append(sk[i][b])
	return s

def verify(m, s, pk):
	h = int.from_bytes(SHA3_256.new().update(m).digest(), 'big')
	for i in range(256):
		b = (h >> i) & 1
		if SHA3_256.new().update(s[i]).digest() != pk[i][b]:
			return False
	return True
