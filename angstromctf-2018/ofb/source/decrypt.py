import struct
import gmpy2

def lcg(m, a, c, x):
	return (a*x + c) % m

def xor(x, y):
	return struct.unpack('>I', x)[0] ^ struct.unpack('>I', y)[0]

m = pow(2, 32)

k = open('known').read()
k = [k[i:i+4] for i in range(0, len(k), 4)]

e = open('flag.png.enc').read()
e = [e[i:i+4] for i in range(0, len(e), 4)]

x0 = xor(k[0], e[0])
x1 = xor(k[1], e[1])
x2 = xor(k[2], e[2])

a = ((x1-x2) % m) * gmpy2.powmod(x0-x1, -1, m) % m
c = (x1 - a*x0) % m
x = x0

d = ''
for i in range(len(e)):
	d += struct.pack('>I', x ^ struct.unpack('>I', e[i])[0])
	x = lcg(m, a, c, x)

with open('flag.png', 'w') as f:
	f.write(d)
	f.close()