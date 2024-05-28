from pwn import process, remote
import fastecdsa.keys
import fastecdsa.point

from tss1 import TARGET, hash_transcript, curve

io = process(['python', 'tss1.py'])
# io = remote('challs.actf.co', 31301)

io.recvuntil(b'key: ')
xy = eval(io.recvline())
pk1 = fastecdsa.point.Point(*xy, curve=curve)

ask, apk = fastecdsa.keys.gen_keypair(curve)
pk2 = apk - pk1

io.sendlineafter(b'x: ', f'{pk2.x}'.encode())
io.sendlineafter(b'y: ', f'{pk2.y}'.encode())

io.sendlineafter(b'message: ', b'foo'.hex())

_, R2 = fastecdsa.keys.gen_keypair(curve)
io.sendlineafter(b'x: ', f'{R2.x}'.encode())
io.sendlineafter(b'y: ', f'{R2.y}'.encode())

k, R = fastecdsa.keys.gen_keypair(curve)
c = hash_transcript(apk, R, TARGET)
s = (k - c * ask) % curve.q

io.sendlineafter(b'c: ', f'{c}'.encode())
io.sendlineafter(b's: ', f'{s}'.encode())

io.interactive()
