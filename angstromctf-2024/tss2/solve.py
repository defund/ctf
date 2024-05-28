from pwn import process, remote
from tqdm import tqdm
import fastecdsa.keys
import fastecdsa.point

from tss2 import TARGET, hash_transcript, curve, verify

q = curve.q

def spawn(pk2, sig):
	io = process(['python', 'tss2.py'])
	# io = remote('challs.actf.co', 31302)
	io.recvuntil(b'key: ')
	xy = eval(io.recvline())
	pk1 = fastecdsa.point.Point(*xy, curve=curve)
	io.sendlineafter(b'x: ', f'{pk2.x}'.encode())
	io.sendlineafter(b'y: ', f'{pk2.y}'.encode())
	io.sendlineafter(b'c: ', f'{sig[0]}'.encode())
	io.sendlineafter(b's: ', f'{sig[1]}'.encode())
	return io, pk1

ell = 256

sk2, pk2 = fastecdsa.keys.gen_keypair(curve)
k, R = fastecdsa.keys.gen_keypair(curve)
c = hash_transcript(pk2, R, b'foo')
s = (k - c * sk2) % q
sig = (c, s)

ios = []
for _ in tqdm(range(ell)):
	io, pk1 = spawn(pk2, sig)
	ios.append(io)

apk = pk1 + pk2

msgs = [f'foo{i}'.encode() for i in range(ell)]
R1s = []
c0s = []
c1s = []

for i, io in tqdm(enumerate(ios)):
	io.sendlineafter(b'message: ', msgs[i].hex())
	io.recvuntil(b'nonce: ')
	xy = eval(io.recvline())
	R1 = fastecdsa.point.Point(*xy, curve=curve)
	c0 = hash_transcript(apk, R1 + curve.G, msgs[i])
	c1 = hash_transcript(apk, R1 + 2*curve.G, msgs[i])
	assert c0 != c1
	R1s.append(R1)
	c0s.append(c0)
	c1s.append(c1)

rho = []
rho0 = 0
for i in range(ell):
	tmp = pow(2, i, q) * pow(c1s[i] - c0s[i], -1, q) % q
	rho.append(tmp % q)
	rho0 -= c0s[i] * tmp % q
rho0 %= q

R = 0 * curve.G
for i in range(ell):
	R += rho[i] * R1s[i]
c = hash_transcript(apk, R, TARGET)

foo = (c + rho0) % q
R2s = []
cs = []
for i in range(ell):
	if (foo >> i) & 1 == 0:
		R2s.append(curve.G)
		cs.append(c0s[i])
	else:
		R2s.append(2*curve.G)
		cs.append(c1s[i])

ss = []
for i, io in tqdm(enumerate(ios)):
	io.sendlineafter(b'x: ', f'{R2s[i].x}'.encode())
	io.sendlineafter(b'y: ', f'{R2s[i].y}'.encode())
	io.recvuntil(b'signature: ')
	s = int(io.recvline())
	ss.append(s)
s = sum([ss[i] * rho[i] for i in range(ell)]) % q
s -= c * sk2
s %= q

assert verify(apk, TARGET, (c, s))

io = ios[-1]
io.sendlineafter(b'c: ', f'{c}'.encode())
io.sendlineafter(b's: ', f'{s}'.encode())
io.interactive()
