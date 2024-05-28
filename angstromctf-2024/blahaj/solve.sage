with open('blahaj_out.txt') as f:
	c, n, x, y = map(ZZ, f.readlines())

e = 65537

R = Integers(n)

P.<a, b, p, q> = PolynomialRing(Integers(n))

f1 = a*p + q

f2 = p + b*q

f3 = p*q

I = Ideal([f1 - x, f2 - y, f3 - n])
B = I.groebner_basis()

print(B)

g = B[-1]

z = ZZ(g.coefficient({q: 1}))
assert g.constant_coefficient() == R(-y)

_, (z1, _), (z2, _) = list(g)
z1 = ZZ(z1)
z2 = ZZ(z2)

S = 2^1024

for p_upper_bits in range(16):
	p_upper = p_upper_bits << 1020
	for q_upper_bits in range(16):
		q_upper = q_upper_bits << 1020
		M = matrix(ZZ, [[S, -1, 0, 0], [S*z1, 0, -1, 0], [S*(z2 + p_upper + q_upper*z1), 0, 0, S], [S*n, 0, 0, 0]])
		B = M.LLL()
		for b in B:
			if b[-1] == S:
				if b[1] < 0:
					b *= -1

				p_guess = b[1] + p_upper
				q_guess = b[2] + q_upper
				if p_guess * q_guess == n:
					d = pow(e, -1, (p_guess - 1)*(q_guess - 1))
					print(int(pow(c, d, n)).to_bytes(1024//8, 'big'))
					exit()
