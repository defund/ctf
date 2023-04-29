from Crypto.Util.strxor import strxor
from binteger import Bin
from pwn import process

nc = process(['python', 'server.py'])

nc.recvuntil(b'You have ')
n = int(nc.recvuntil(b' '))

for i in range(n):
	nc.sendlineafter(b'gate: ', f'and {i} {i}'.encode())
	nc.sendlineafter(b'gate: ', f'and {i} {i}'.encode())

nc.sendlineafter(b'gate: ', b'done')

in_labels = []
for _ in range(n):
	nc.recvuntil(b': ')
	key = bytes.fromhex(nc.recvuntil(b' ').decode())
	ptr = int(nc.recvline())
	in_labels.append((key, ptr))

nc.recvline()

tables = []
for _ in range(2*n):
	table = []
	for _ in range(4):
		ct = bytes.fromhex(nc.recvuntil(b' ').decode())
		nc.recvline()
		table.append(ct)
	tables.append(table)

bits = []
for i in range(n):
	table_xor = [strxor(x, y) for x, y in zip(tables[2*i], tables[2*i+1])]
	ptr = in_labels[i][1]
	ct = table_xor[2*ptr + ptr]
	bits.append(0 if table_xor.count(ct) == 3 else 1)

print(Bin(bits).bytes)
