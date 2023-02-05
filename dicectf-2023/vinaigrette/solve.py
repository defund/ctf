import ctypes
import galois
import numpy as np

debug = False

if not debug:
	from pwn import process, remote

CRYPTO_SECRETKEYBYTES = 237912
CRYPTO_PUBLICKEYBYTES = 43576
CRYPTO_BYTES = 128

# make libpqov.so VARIANT=2
libpqov = ctypes.CDLL('./libpqov.so')

class Oracle:
	def __init__(self):
		if debug:
			self.sk = ctypes.create_string_buffer(CRYPTO_SECRETKEYBYTES)
			self.pk = ctypes.create_string_buffer(CRYPTO_PUBLICKEYBYTES)
			libpqov.crypto_sign_keypair(self.pk, self.sk)
		else:
			with open('pk.bin', 'rb') as f:
				self.pk = ctypes.create_string_buffer(f.read())

	def query(self):
		if debug:
			m = ctypes.create_string_buffer(0)
			mlen = ctypes.c_size_t(0)
			sm = ctypes.create_string_buffer(len(m) + CRYPTO_BYTES)
			smlen = ctypes.c_size_t(0)
			libpqov.crypto_sign(sm, ctypes.pointer(smlen), m, mlen, self.sk)
		else:
			# nc = process(['python', 'server.py'])
			nc = remote('mc.ax', 31337)
			nc.sendlineafter(b'order? ', b'foo')
			nc.recvuntil(b'is: ')
			sm = bytes.fromhex(nc.recvline().decode())
			nc.close()
		return bytes(sm)

	def solve(self, sk):
		m = b'the vinaigrette recipe'
		m = ctypes.create_string_buffer(m, len(m))
		mlen = ctypes.c_size_t(len(m))
		sm = ctypes.create_string_buffer(len(m) + CRYPTO_BYTES)
		smlen = ctypes.c_size_t(0)
		libpqov.crypto_sign(sm, ctypes.pointer(smlen), m, mlen, sk)

		if debug:
			assert libpqov.crypto_sign_open(m, ctypes.pointer(mlen), sm, smlen, oracle.pk) == 0
		else:
			nc = process(['python', 'server.py'])
			nc.sendlineafter(b'order? ', bytes(m))
			nc.sendlineafter(b'Authorization: ', bytes(sm).hex().encode())
			nc.interactive()

N = 112
M = 44
V = N - M

GF = galois.GF(256, irreducible_poly='x^8 + x^4 + x^3 + x^1 + 1')

def sample():
	s = oracle.query()[-CRYPTO_BYTES:]
	y = GF(list(s[:V]))
	x = GF(list(s[V:V + M]))
	return y, x

def forge(t1):
	sk = ctypes.create_string_buffer(CRYPTO_SECRETKEYBYTES)
	t1 = ctypes.create_string_buffer(t1, len(t1))
	'''
	Custom method (see expand_sk_with_t1.diff) which creates a secret key
	object given the secret subspace. We can't use expand_sk since we don't
	know the original seed. We also won't know the seed used for computing
	the initial vector, but we can just pick that arbitrarily.
	'''
	libpqov.expand_sk_with_t1(sk, oracle.pk, t1)
	return sk

oracle = Oracle()

Y = []
X = []
y0, x0 = sample()
for _ in range(M):
	y1, x1 = sample()
	y = y0 - y1
	x = x0 - x1
	Y.append(y0 - y1)
	X.append(x0 - x1)

Y = GF(Y)
X = GF(X)
O = np.linalg.solve(X, Y)
t1 = O.tobytes()
sk = forge(t1)

oracle.solve(sk)
