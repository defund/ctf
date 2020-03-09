import struct

pack = lambda x: struct.pack('>I', x)
unpack = lambda x: struct.unpack('>I', x)[0]

def qcg(x, a, b, c):
	mask = (1 << 32) - 1
	while True:
		x = (a*x*x + b*x + c) & mask
		yield x

enc = open('flag.png.enc', 'rb').read()
known = open('known', 'rb').read()

x = [unpack(enc[i:i+4]) ^^ unpack(known[i:i+4]) for i in range(0, 16, 4)]

m = 1 << 32
A = [[x[0]^2, x[0], 1], [x[1]^2, x[1], 1], [x[2]^2, x[2], 1]]
b = [x[1], x[2], x[3]]

A = matrix(Integers(m), A)
b = matrix(Integers(m), b).transpose()
s = A.solve_right(b)

stream = qcg(x[3], int(s[0][0]), int(s[1][0]), int(s[2][0]))

dec = known
for i in range(16, len(enc), 4):
	chunk = unpack(enc[i:i+4])
	dec += pack(chunk ^^ next(stream))

with open('flag_.png', 'wb') as f:
	f.write(dec)
	f.close()
