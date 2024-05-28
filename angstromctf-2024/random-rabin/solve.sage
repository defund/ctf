from pwn import process, remote
from tqdm import tqdm

io = process(['python', 'random-rabin.py'])
# io = remote('challs.actf.co', 31300)

for _ in tqdm(range(64)):
	io.recvuntil(b'pubkey: ')
	n = int(io.recvline())

	io.recvuntil(b'plaintext: ')
	m = int(io.recvline())

	if m.bit_length() <= 128:
		secret = m
	elif (n - m).bit_length() <= 128:
		secret = n - m
	else:
		P.<x> = Integers(n)[]
		secret = int((m + x).small_roots(beta=0.5)[0])
		if secret.bit_length() > 128:
			secret = n - secret

	io.sendlineafter(b'secret: ', secret.to_bytes(16, 'big').hex().encode())

io.interactive()
