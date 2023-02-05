from Crypto.Util.strxor import strxor
from Crypto.Hash import SHAKE128
from pwn import process, remote
import struct

def stream(buf, ss):
	pad = SHAKE128.new(bytes(ss)).read(len(buf))
	return strxor(buf, pad)

p = 0x65b48e8f740f89bf_fc8ab0d15e3e4c4a_b42d083aedc88c42_5afbfcc69322c9cd_a7aac6c567f35507_516730cc1f0b4f25_c2721bf457aca835_1b81b90533c6c87b

K = GF(p)
R.<t> = K[]

def load_coeff(buf):
	limbs = struct.unpack('<8Q', buf)
	return sum(x << (64*i) for i, x in enumerate(limbs))

def dump_coeff(coeff):
	coeff = int(coeff)
	limbs = [(coeff >> (64*i)) & 0xffffffffffffffff for i in range(8)]
	return struct.pack('<8Q', *limbs)

def twist(A):
	E = EllipticCurve(K, [0, A, 0, 1, 0])
	Et = E.quadratic_twist()
	a, b = Et.short_weierstrass_model().a_invariants()[-2:]
	r, = (t^3 + a*t + b).roots(multiplicities=False)
	s = sqrt(3*r^2 + a)
	return -3 * (-1)^is_square(s) * r / s

nc = process(['python', 'server.py'])
# nc = remote('mc.ax', 31336)

nc.recvuntil(b'pub0: ')
pub0 = bytes.fromhex(nc.recvline().decode())
nc.recvuntil(b'pub1: ')
pub1 = bytes.fromhex(nc.recvline().decode())

A0 = load_coeff(pub0)
A1 = load_coeff(pub1)

mask = dump_coeff(0)
nc.sendlineafter(b'mask: ', mask.hex())

nc.recvuntil(b'enc0: ')
enc0 = bytes.fromhex(nc.recvline().decode())
nc.recvuntil(b'enc1: ')
enc1 = bytes.fromhex(nc.recvline().decode())

ss0 = dump_coeff(twist(A0))
ss1 = dump_coeff(twist(A1))
msg0 = stream(enc0, ss0)
msg1 = stream(enc1, ss1)
flag = strxor(msg0, msg1)

print(flag.decode())
