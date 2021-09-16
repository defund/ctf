from Crypto.Util.number import GCD, getPrime, getRandomRange, inverse

def pack(fn, k):
	with open(fn, 'w') as f:
		f.write('\n'.join([str(x) for x in k]))

def unpack(fn):
	with open(fn, 'r') as f:
		return tuple([int(x) for x in f.readlines()])

def generate():
	p = getPrime(1024)
	q = getPrime(1024)
	n = p * q
	g = n + 1
	phi = (p-1) * (q-1)
	mu = inverse(phi, n)
	return (n, g), (n, phi, mu)

def encrypt(m, pk):
	n, g = pk
	mod = n * n
	while True:
		r = getRandomRange(0, n)
		if GCD(r, n) == 1:
			break
	return pow(g, m, mod) * pow(r, n, mod) % mod

def decrypt(c, sk):
	n, phi, mu = sk
	mod = n * n
	return ((pow(c, phi, mod)-1) // n) * mu % n
