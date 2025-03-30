from uov import uov_1p_pkc as uov

F.<x> = GF(2)[]
K.<a> = GF(2^8, name='a', modulus=x^8 + x^4 + x^3 + x + 1)

n = uov.n
m = uov.m
v = uov.v

t_bytes = uov.shake256(b'shrooms', uov.m_sz)
t = vector(K, [K(ZZ(x).bits()) for x in t_bytes])

with open(f'keys/oberon.pub', 'rb') as f:
	tm = uov.expand_pk(f.read())

m1 = uov.unpack_mtri(tm, v)
m2 = uov.unpack_mrect(tm[uov.p1_sz:], v, m)
m3 = uov.unpack_mtri(tm[uov.p1_sz + uov.p2_sz:], m)

As = []
for k in range(m):
	A = [[None for _ in range(n)] for _ in range(n)]
	for i in range(n):
		for j in range(n):
			if j < i:
				A[i][j] = K(0)
			elif i < len(m1) and j < len(m1[0]):
				A[i][j] = K(((m1[i][j] >> ((m - k - 1) * 8)) & 0xff).bits())
			elif i < len(m1):
				A[i][j] = K(((m2[i][j - len(m1[0])] >> ((m - k - 1) * 8)) & 0xff).bits())
			else:
				A[i][j] = K(((m3[i - len(m1)][j - len(m1[0])] >> ((m - k - 1) * 8)) & 0xff).bits())
	A = matrix(K, A)
	As.append(A)

def quad(x):
	return vector(K, [x.dot_product(A * x) for A in As])

delta = random_vector(K, n)
M = matrix(K, [delta * (A + A.transpose()) for A in As])
u = M.solve_right(t - quad(delta))
assert quad(u) + quad(u + delta) == t

sig = bytes([ZZ(list(x), base=2) for x in u]) + bytes([ZZ(list(x), base=2) for x in u + delta])

import os
os.environ['TERM'] = 'xterm'
from pwn import process, remote

# io = process(['python', 'server.py'])
io = remote('dicec.tf', 31003)

io.sendlineafter(b'ring size: ', b'2')
io.sendlineafter(b'name 1: ', b'oberon')
io.sendlineafter(b'name 2: ', b'oberon')
io.sendlineafter(b'ring signature (hex): ', sig.hex().encode())
io.interactive()
