import random

n = 1 << 2048
g = random.randint(0, n) | 1
x = random.randint(0, n)
gx = pow(g, x, n)

e = 2048-2
s = 0
for k in range(e):
	shift = pow(2, e-1-k, n)
	if pow(gx, shift, n) != pow(g, s*shift, n):
		s += pow(2, k)
assert pow(g, s, n) == gx