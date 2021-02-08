r = 17

with open('out.txt') as f:
	n, y = eval(f.readline())
	R = Integers(n)
	z = list(map(R, f.readlines()))

y = R(y)
log = {y^i: f'{i:x}' for i in range(r)}

P.<u, a, c> = PolynomialRing(R)

G = []
f = u
for i, m in enumerate(b'di'.hex()):
	G.append(f^r - z[i]/y^int(m, 16))
	f = a*f + c

B = Ideal(G).groebner_basis()
print(B)

flag = ''
f = -B[1].monomial_coefficient(c)*c
for i in range(len(z)):
	flag += log[z[i]/(f.monomial_coefficient(c)^r*-B[0].constant_coefficient())]
	f = -B[2].constant_coefficient()*f + c
print(bytes.fromhex(flag))
