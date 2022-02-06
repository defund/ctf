import gmpy2
from pathlib import Path
from tqdm import tqdm

from server import *

def get_backdoor():
	path = Path('backdoor.txt')
	if path.is_file():
		with path.open() as f:
			return gmpy2.mpz(f.read())
	else:
		L = gmpy2.mpz(1)
		for p in range(1, 2**20):
			if p < 256 or gmpy2.is_prime(p):
				L *= p
		g = gmpy2.powmod(2, L, n)
		for i in tqdm(range(1000000)):
			m = H(int(g), 1)
			if gmpy2.gcd(L, m) == m:
				L <<= i
				with path.open('w') as f:
					f.write(str(L))
				return L
			g = gmpy2.powmod(g, 2, n)

L = get_backdoor()
g = int(gmpy2.powmod(2, L, n))
h = 1
m = H(g, h)
r = pow(2, T, m)
pi = int(gmpy2.powmod(2, -r*L//m, n))
verify(g, h, pi)

print(f'g: {g}')
print(f'h: {h}')
print(f'pi: {pi}')
