import struct

pack = lambda x: struct.pack('>I', x)
unpack = lambda x: struct.unpack('>I', x)[0]

def qcg(x, a, b, c):
	mask = (1 << 32) - 1
	while True:
		x = (a*x*x + b*x + c) & mask
		yield x

with open('qcg.txt') as f:
	x = int(f.readline())
	a = int(f.readline())
	b = int(f.readline())
	c = int(f.readline())
	stream = qcg(x, a, b, c)

dec = open('flag.png', 'rb').read()
dec += bytes(-len(dec) % 4)

enc = bytes()
for i in range(0, len(dec), 4):
	chunk = unpack(dec[i:i+4])
	enc += pack(chunk ^ next(stream))

with open('flag.png.enc', 'wb') as f:
	f.write(enc)
	f.close()
