from gmpy2 import div, gcd, invert, powmod

from Crypto.Util.number import getPrime, getRandomRange

def generate():
	p = getPrime(128)
	q = getPrime(128)
	n = p*q
	g = n+1
	phi = (p-1)*(q-1)
	mu = invert(phi, n)
	return (n, g), (n, phi, mu)

def encrypt(m, pk):
	n, g = pk
	mod = n**2
	while True:
		r = getRandomRange(0, n)
		if gcd(r, n) == 1:
			break
	return powmod(g, m, mod)*powmod(r, n, mod) % mod

def decrypt(c, sk):
	n, phi, mu = sk
	mod = n**2
	return div(powmod(c, phi, mod)-1, n)*mu % n