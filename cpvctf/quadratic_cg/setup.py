import secrets

m = 1 << 32
x = secrets.randbelow(m)
a = secrets.randbelow(m)
b = secrets.randbelow(m)
c = secrets.randbelow(m)

with open('qcg.txt', 'w') as f:
	f.write('{}\n{}\n{}\n{}\n'.format(x, a, b, c))
