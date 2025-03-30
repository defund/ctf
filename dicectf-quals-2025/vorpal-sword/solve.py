from pwn import process, remote
from tqdm import tqdm

from server import DEATH_CAUSES

PREFIX = b'you continue walking. turn to page '
SUFFIX = b'.'

def recvlineafter(io, delim):
	io.recvuntil(delim)
	return io.recvline()

# io = process(['python', 'server.py'])
io = remote('dicec.tf', 31001)

for _ in tqdm(range(64)):
	n = int(recvlineafter(io, b'n: '))
	x0 = int(recvlineafter(io, b'x0: '))
	x1 = int(recvlineafter(io, b'x1: '))
	v = pow(2, -1, n) * (x0 + x1) % n
	assert (v - x0) % n == -(v - x1) % n
	io.sendlineafter(b'v: ', str(v).encode())
	c0 = int(recvlineafter(io, b'c0: '))
	c1 = int(recvlineafter(io, b'c1: '))
	z = (c0 + c1) % n

	for cause in DEATH_CAUSES:
		die = f'you die of {cause}.'
		m = (z - int.from_bytes(die.encode(), 'big')).to_bytes(1024//8, 'big').strip(b'\x00')
		if m.startswith(PREFIX) and m.endswith(SUFFIX) and m[len(PREFIX):-len(SUFFIX)].isdigit():
			page = int(m[len(PREFIX):-len(SUFFIX)])
			break

	io.sendlineafter(b'turn to page: ', str(page).encode())

io.interactive()
