# import os
# from hashlib import sha256
# from tqdm import tqdm

# msg = os.urandom(32)
# for _ in tqdm(range(2**32)):
# 	m = sha256(msg).digest()
# 	for n in m:
# 		if n >= 128:
# 			break
# 	else:
# 		print('low', msg.hex())
# 	for n in m:
# 		if n <= 128:
# 			break
# 	else:
# 		print('high', msg.hex())
# 	msg = m

from pwn import process, remote
from server import Wots

low = '86c3384427915fcf838d8b4983d17e441a08b1d8977df45aa1055d9dace0baeb'
high = '77495be1984783379b67274507be5d43dea544c17348c5c43fa36e74b58c77de'

io = process(['python', 'server.py'])

io.sendlineafter(': ', high.encode())
io.recvuntil(': ')
sig1 = bytes.fromhex(io.recvline().decode())

m1 = Wots.hash(bytes.fromhex(low), 1)
m2 = Wots.hash(bytes.fromhex(high), 1)
chunks = [sig1[i:i+32] for i in range(0, len(sig1), 32)]
sig2 = b''.join([Wots.hash(x, n2 - n1) for x, n1, n2 in zip(chunks, m1, m2)])

io.sendlineafter(': ', low.encode())
io.sendlineafter(': ', sig2.hex().encode())
io.interactive()
