from Crypto.PublicKey import RSA
from Crypto.Util.number import getRandomRange

key = RSA.generate(2048)
n = key.n
e = key.e
d = key.d

def query(v):
	balls = [getRandomRange(0, 1024) for _ in range(6)]
	x = [getRandomRange(0, n) for _ in range(6)]
	m = []
	for i in range(6):
		k = pow(v-x[i], d, n)
		m.append((balls[i]+k) % n)
	return m, x, balls

def crack(m, x, v):
	for i in range(1024):
		if pow(m-i, e, n) == (v-x) % n:
			return i

v = 0
m, x, balls = query(v)
assert balls == [crack(m[i], x[i], v) for i in range(6)]
