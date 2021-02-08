from tqdm import tqdm
from lwe import *

with open('private.key', 'rb') as f:
	key = Key.deserialize(f.read())

def oracle(local=True):
	message = b'silly sheep'
	if local:
		while True:
			signature = key.sign(message)
			b, r = unpack(signature)
			c = gauss(random=ShakeRandom(pack(key.a, key.b, b) + message))
			yield c, r
	else:
		with open('signatures.bin', 'rb') as f:
			while True:
				b, r = unpack(f.read(4*n))
				c = gauss(random=ShakeRandom(pack(key.a, key.b, b) + message))
				yield c, r

query = oracle(local=False)
lift = np.vectorize(lambda x: int(x)-q if q-x < x else int(x))
C, R = zip(*[next(query) for _ in tqdm(range(800))])
C = lift(np.transpose(np.hstack(C)))
R = lift(np.transpose(np.hstack(R)))
solution = np.linalg.lstsq(C, R, rcond=None)[0]
S = -np.transpose(np.rint(solution)).astype(np.uint16)

from pwn import *
nc = remote('dicec.tf', 31614)
key.s = S
message = b'shep, the conqueror'
nc.send(key.sign(message))
nc.interactive()
