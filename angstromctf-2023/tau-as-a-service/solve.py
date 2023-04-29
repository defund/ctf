import math
from tqdm import tqdm
from pwn import process
from blspy import G1Element as Element
from blspy import PrivateKey as Scalar
from modint import chinese_remainder

# order of curve
n = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

factors = [(2, 32), (3, 1), (11, 1), (19, 1), (10177, 1), (125527, 1), (859267, 1), (906349, 2), (2508409, 1), (2529403, 1), (52437899, 1), (254760293, 2)]

def is_primitive(zeta):
	for p, _ in factors:
		if pow(zeta, (n-1)//p, n) == 1:
			return False
	return True

# find primitive of (Z/nZ)*
zeta = 2
while True:
	if is_primitive(zeta):
		break
	zeta += 1
print(zeta)

with open('flag.txt', 'rb') as f:
	tau = int.from_bytes(f.read().strip(), 'big')
	assert tau < n

def mul_base(k):
	return Scalar.from_bytes(k.to_bytes(32, 'big')).get_g1()

def mul(k, P):
	# double-and-add, since blspy doesn't expose an API for arbitrary point multiplication
	Q = Scalar.from_bytes(bytes(32)).get_g1()
	while k:
		if k & 1:
			Q += P
		k >>= 1
		P += P
	return Q

nc = process(['python', 'server.py'])
def query(d):
	nc.sendlineafter(b'gimme the power: ', str(d).encode())
	return Element.from_bytes(bytes.fromhex(nc.readline().decode()))

def bsgs(H, p):
	table = dict()
	m = math.ceil(math.sqrt(p))
	for v in tqdm(range(m)):
		table[str(mul_base(pow(zeta, (n//p)*m*v, n)))] = v
	for u in tqdm(range(m)):
		if v := table.get(str(mul(pow(zeta, -(n//p)*u, n), H))):
			return (m*v + u) % p

l = [0 for _ in factors]
for i, (p, r) in enumerate(factors):
	for j in range(r):
		lift = n // p**(j+1)
		c = bsgs(mul(pow(zeta, -l[i] * lift, n), query(lift)), p)
		l[i] += c * p**j

log = chinese_remainder([p**r for p, r in factors], l)
tau = pow(zeta, log, n)

print(tau.to_bytes(32, 'big'))
