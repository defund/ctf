from pwn import process

io = process(['python', 'cfb_trivia.py'])

io.recvuntil(b'encrypted flag: ')
buf = bytes.fromhex(io.recvline().decode())
iv, ct = buf[:16], buf[16:]

flag = iv
for i in range(len(ct)):
	io.sendlineafter(b'message: ', (flag[-16:] + ct[i:i+1]).hex().encode())
	io.recvuntil(b'encrypted message: ')
	buf = bytes.fromhex(io.recvline().decode())
	flag += buf[-1:]

print(flag[16:])
