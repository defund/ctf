import itertools

n = 40
K = GF(257)

R = PolynomialRing(K, n, 'z')
z = R.gens()

def keygen():
	F = []
	for i in range(n):
		f = z[i]
		for zj in z[:i]:
			f += K.random_element() * zj
		for zj, zk in itertools.combinations_with_replacement(z[:i], 2):
			f += K.random_element() * zj * zk
		F.append(f)

	S = random_matrix(K, n)
	while S.is_singular():
		S.randomize()

	P = [sum(si * f for si, f in zip(s, F)) for s in S]
	return P, (F, S^-1)

def encrypt(pk, m):
	P = pk
	return vector(K, [p(*m) for p in P])

def decrypt(sk, c):
	w = []
	for f, t in zip(*sk):
		w.append(t * c - f.subs(dict(zip(z, w))).constant_coefficient())
	return vector(K, w)

if __name__ == '__main__':
	with open('flag.txt', 'rb') as f:
		flag = f.read().strip()
		assert len(flag) == n

	pk, sk = keygen()
	m = vector(K, flag)
	c = encrypt(pk, m)

	with open('pk.txt', 'w') as f:
		f.write(str(pk))

	with open('c.txt', 'w') as f:
		f.write(str(c))
