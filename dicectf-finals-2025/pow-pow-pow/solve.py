from pwn import process, remote

from server import LOG_POW_COST, _hash, verify_pow, prove_pow

# io = process(['python', 'server.py'])
io = remote('dicec.tf', 31001)

io.recvuntil(b'n = ')
n = int(io.recvline().decode())

g = 2
z = 1
new_g = g
proof = []
for _ in range(LOG_POW_COST):
	v = 2
	proof.append(v)
	r = _hash(g, *proof)
	new_g = pow(new_g, r, n) * v % n
	z = pow(v, r, n) * z % n
h = pow(new_g, 2, n) * pow(z, -1, n) % n

verify_pow(n, g, h, proof)

io.sendlineafter(b'g: ', str(g).encode())
io.sendlineafter(b'h: ', str(h).encode())
io.sendlineafter(b'proof: ', ','.join(map(str, proof)).encode())

io.interactive()
