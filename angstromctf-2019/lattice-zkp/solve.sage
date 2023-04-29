import numpy as np

import lwe

A = lwe.public()
s, b = lwe.sample(A)

def query(A, s):
	r, b = lwe.sample(A)
	return b, lwe.add(r, s)

trials = 512
std_bound = lwe.sigma+1
low_bound = lwe.q/2

samples = []
for _ in range(trials):
	b, rs = query(A, s)
	samples.append(lwe.add(lwe.mul(A, rs), -b))

std = np.std(samples, axis=0)
for i in range(lwe.n):
	if std[i] > std_bound:
		for j in range(trials):
			if samples[j][i] < low_bound:
				samples[j][i] += lwe.q

y = np.mod(np.rint(np.mean(samples, axis=0)).astype(int), lwe.q)

Z = Integers(lwe.q)
M = matrix(Z, A).augment(vector(Z, y))

ref = []
for i in range(lwe.n-1):
	for j in range(i, lwe.n):
		if np.mod(M[j, i], 2) == 1:
			M.swap_rows(i, j)
			break
	M.rescale_row(i, M[i, i]^(-1))
	for j in range(i+1, lwe.n):
		M.add_multiple_of_row(j, i, -M[j, i])
for i in range(lwe.q):
	if M[-1, -2]*i == M[-1, -1]:
		T = copy(M)
		T[-1, -2] = 1
		T[-1, -1] = i
		ref.append(T)

rref = []
for M in ref:
	for i in range(lwe.n-1, -1, -1):
		for j in range(i-1, -1, -1):
			M.add_multiple_of_row(j, i, -M[j, i])
	rref.append(M)

solution = []
for M in rref:
	solution.append(np.array(list(M.column(-1))))

assert any([np.array_equal(x, s) for x in solution])