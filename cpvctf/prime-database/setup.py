from Crypto.Util.number import getPrime

with open('primes.txt', 'w') as f:
	for _ in range(128):
		p = getPrime(1024)
		f.write('{}\n'.format(p))
