import itertools
from tqdm import tqdm

n = 40
K = GF(257)

R = PolynomialRing(K, n, 'z')
z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15, z16, z17, z18, z19, z20, z21, z22, z23, z24, z25, z26, z27, z28, z29, z30, z31, z32, z33, z34, z35, z36, z37, z38, z39 = R.gens()

def minrank(P, ell):
	Ms = []
	for p in P:
		M = zero_matrix(K, ell)
		for j, k in itertools.combinations_with_replacement(range(ell), 2):
			M[j,k] = p.monomial_coefficient(z[n - ell + j] * z[n - ell + k])
		Ms.append(M)

	while True:
		print('guessing kernel...')
		x = random_vector(K, ell)
		B = matrix(K, [M * x for M in Ms])
		beta = B.left_kernel()[1]
		H = sum(beta[i] * M for i, M in enumerate(Ms))
		if H.rank() == 0:
			return beta

with open('pk.txt') as f:
	pk = eval(f.read().replace('^', '**'))

with open('c.txt') as f:
	c = vector(K, eval(f.read()))

P = pk
z = P[0].parent().gens()
flag = []
for i in tqdm(range(n)):
	beta = minrank(P, n - i)
	f = sum(beta[i] * p for i, p in enumerate(P))
	xi = (f - beta * c).univariate_polynomial().roots()[0][0]
	P = [p.subs({z[i]: xi}) for p in P]
	flag.append(xi)

print(bytes(flag))
