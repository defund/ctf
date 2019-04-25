import random

n = 1 << 2048
g = random.randint(0, n) | 1
x = random.randint(0, n)
gx = pow(g, x, n)

# order depends on the generator g
# for this problem, it was 2**2045
e = 2048-3
s = 0
for k in range(e):
	shift = pow(2, e-1-k, n)
	if pow(gx, shift, n) != pow(g, s*shift, n):
		s += pow(2, k)
assert pow(g, s, n) == gx
