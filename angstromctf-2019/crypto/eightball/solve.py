import random
import time

import benaloh

pk = benaloh.unpack('pk')
sk = benaloh.unpack('sk')

m = random.randint(0, 256)
c = benaloh.encrypt(m, pk)

def query(c):
	for i in range(32):
		benaloh.decrypt(c, sk)

n, y = pk
decrement = benaloh.encrypt(256, pk)
deltas = []
for i in range(257):
	start = time.time()
	query(c)
	deltas.append(time.time() - start)
	c = (c*decrement) % n
steps = [deltas[i+1]-deltas[i] for i in range(256)]
assert m == steps.index(max(steps))