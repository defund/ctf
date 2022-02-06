import functools
import time
from functional import seq
from methodtools import lru_cache
from pwn import process, remote
from sage.schemes.elliptic_curves.weierstrass_morphism import *
from tqdm import tqdm

from server import *

p = 0x2341f271773446cfc5fd681c520567bc65c783158aea3fdc1767ae2ffffffffffffffffffffffffffffffffffffffffffffffffffffff
e2 = 0xd8
e3 = 0x89
xQ20 = 0xc7461738340efcf09ce388f666eb38f7f3afd42dc0b664d9f461f31aa2edc6b4ab71bd42f4d7c058e13f64b237ef7ddd2abc0deb0c6c
xQ21 = 0x25de37157f50d75d320dd0682ab4a67e471586fbc2d31aa32e6957fa2b2614c4cd40a1e27283eaaf4272ae517847197432e2d61c85f5
yQ20 = 0x1d407b70b01e4aee172edf491f4ef32144f03f5e054cef9fde5a35efa3642a11817905ed0d4f193f31124264924a5f64efe14b6ec97e5
yQ21 = 0xe7dec8c32f50a4e735a839dcdb89fe0763a184c525f7b7d0ebc0e84e9d83e9ac53a572a25d19e1464b509d97272ae761657b4765b3d6
xP20 = 0x3ccfc5e1f050030363e6920a0f7a4c6c71e63de63a0e6475af621995705f7c84500cb2bb61e950e19eab8661d25c4a50ed279646cb48
xP21 = 0x1ad1c1cae7840edda6d8a924520f60e573d3b9dfac6d189941cb22326d284a8816cc4249410fe80d68047d823c97d705246f869e3ea50
yP20 = 0x1ab066b84949582e3f66688452b9255e72a017c45b148d719d9a63cdb7be6f48c812e33b68161d5ab3a0a36906f04a6a6957e6f4fb2e0
yP21 = 0xfd87f67ea576ce97ff65bf9f4f7688c4c752dce9f8bd2b36ad66e04249aaf8337c01e6e4e1a844267ba1a1887b433729e1dd90c7dd2f
xR20 = 0xf37ab34ba0cead94f43cdc50de06ad19c67ce4928346e829cb92580da84d7c36506a2516696bbe3aeb523ad7172a6d239513c5fd2516
xR21 = 0x196ca2ed06a657e90a73543f3902c208f410895b49cf84cd89be9ed6e4ee7e8df90b05f3fdb8bdfe489d1b3558e987013f9806036c5ac
xQ30 = 0x12e84d7652558e694bf84c1fbdaaf99b83b4266c32ec65b10457bcaf94c63eb063681e8b1e7398c0b241c19b9665fdb9e1406da3d3846
xQ31 = 0x0
yQ30 = 0x0
yQ31 = 0xebaaa6c731271673beece467fd5ed9cc29ab564bded7bdeaa86dd1e0fddf399edcc9b49c829ef53c7d7a35c3a0745d73c424fb4a5fd2
xP30 = 0x8664865ea7d816f03b31e223c26d406a2c6cd0c3d667466056aae85895ec37368bfc009dfafcb3d97e639f65e9e45f46573b0637b7a9
xP31 = 0x0
yP30 = 0x6ae515593e73976091978dfbd70bda0dd6bcaeebfdd4fb1e748ddd9ed3fdcf679726c67a3b2cc12b39805b32b612e058a4280764443b
yP31 = 0x0
xR30 = 0x1cd28597256d4ffe7e002e87870752a8f8a64a1cc78b5a2122074783f51b4fde90e89c48ed91a8f4a0ccbacbfa7f51a89ce518a52b76c
xR31 = 0x147073290d78dd0cc8420b1188187d1a49dbfa24f26aad46b2d9bb547dbb6f63a760ecb0c2b20be52fb77bd2776c3d14bcbc404736ae4

Fp = GF(p)
Fp2.<ii> = GF(p^2, modulus=x^2 + 1)

A0 = Fp2(6)
xP2 = xP20 + xP21*ii
xQ2 = xQ20 + xQ21*ii
xR2 = xR20 + xR21*ii
xP3 = xP30 + xP31*ii
xQ3 = xQ30 + xQ31*ii
xR3 = xR30 + xR31*ii

_sqrt = (p + 1)/4
def sqrt(x):
	coeffs = x.polynomial().list()
	if len(coeffs) == 0:
		return 0
	elif len(coeffs) == 1:
		z, = coeffs
		alpha = z^_sqrt
		if alpha^2 == z:
			return alpha
		else:
			return alpha*ii
	else:
		a, b = coeffs
		z = (a + (a^2 + b^2)^_sqrt)/2
		alpha = z^_sqrt
		beta = b/(2*alpha)
		if alpha^2 == z:
			return alpha + beta*ii
		else:
			return beta + alpha*ii

def xADD(xP, xQ, xR):
	return (xP*xQ - 1)^2/(xP - xQ)^2/xR

def xDBL(x, A, n=1):
	for _ in range(n):
		x = (x^2 - 1)^2/(4*x*(x^2 + A*x + 1))
	return x

def xTPL(x, A, n=1):
	for _ in range(n):
		x = (x^4 - 6*x^2 - 4*A*x-3)^2*x/(3*x^4 + 4*A*x^3 + 6*x^2 - 1)^2
	return x

def ladder3pt(xP, xQ, xR, k, A):
	bits = k.bits()
	R0 = xQ
	R1 = xP
	R2 = xR
	for i in range(0, len(bits) - 1):
		if bits[i] == 1:
			R1 = xADD(R0, R1, R2)
		else:
			R2 = xADD(R0, R2, R1)
		R0 = xDBL(R0, A)
	R1 = xADD(R0, R1, R2)
	return R1

def cfpk(xP, xQ, xR):
	return (1 - xP*xQ - xP*xR - xQ*xR)^2/(4*xP*xQ*xR) - xP - xQ - xR

def jinv(A):
	return 256*(A^2 - 3)^3/(A^2 - 4)

def cinvs(A):
	b2 = 4*A
	return b2^2 - 48, -b2^3 + 72*b2

def iso2(alpha, A, pts):
	return 2*(1-2*alpha^2), [x*(alpha*x - 1)/(x - alpha) for x in pts]

def iso3(beta, A, pts):
	return (6 - 6*beta^2 + A*beta)*beta, [x*(beta*x - 1)^2/(x - beta)^2 for x in pts]

def isogen2(A, xS, pts=()):
	pts = [xS] + list(pts)
	for e in range(e2 - 1, 0, -1):
		alpha = xDBL(pts[0], A, n=e)
		A, pts = iso2(alpha, A, pts)
	return iso2(pts[0], A, pts[1:])

def isogen3(A, xS, pts=()):
	pts = [xS] + list(pts)
	for e in range(e3 - 1, 0, -1):
		beta = xTPL(pts[0], A, n=e)
		A, pts = iso3(beta, A, pts)
	return iso3(pts[0], A, pts[1:])

def iso2_debug(a, pts):
	return 2*(1-2*a^2), [(x*(a*x-1)/(x-a), y*sqrt(a)*((a - a^3)/(a - x)^2 + a)) for x, y in pts]

def isoex2_debug(A, S, P, Q):
	pts = (S, P, Q)
	debug = [{'A': A, 'pts': pts}]
	for e in range(e2-1, 0, -1):
		a = xDBL(pts[0][0], A, n=e)
		A, pts = iso2_debug(a, pts)
		debug.append({'A': A, 'pts': pts})
	a = pts[0][0]
	A, pts = iso2_debug(a, pts[1:])
	debug.append({'A': A, 'pts': pts})
	return debug[::-1]

def iso2_full(a, x, A):
	if a == 0:
		return (A + 6)/(2*sqrt(A + 2)), (x - 1)^2/(2*x*sqrt(A + 2))
	else:
		return 2*(1 - 2*a^2), x*(a*x - 1)/(x - a)

def isoex2_full(A, x, n=e2):
	for e in range(n-1, 0, -1):
		a = xDBL(x, A, n=e)
		A, x = iso2_full(a, x, A)
	a = x
	A = (A + 6)/(2*sqrt(A + 2)) if a == 0 else 2*(1 - 2*a^2)
	return jinv(A)

class Isogeny:
	def __init__(self, a, A):
		self.kernel = a
		self.domain = A
		if a == 0:
			self.r = 2*sqrt(A + 2)
			self.codomain = (A + 6)/self.r
		else:
			self.codomain = 2 - 4*a^2

	def __call__(self, x):
		a = self.kernel
		if a == 0:
			return (x - 1)^2/(x*self.r)
		else:
			return x*(a*x - 1)/(x - a)

	def dual(self):
		alpha = seq(torsion_points(self.domain)).find(lambda a: a != self.kernel)
		return Isogeny(self(alpha), self.codomain)

class Isomorphism:
	def __init__(self, A1, A2):
		c4_1, c6_1 = cinvs(A1)
		c4_2, c6_2 = cinvs(A2)
		self.u2 = c6_1*c4_2/(c6_2*c4_1)
		self.u3 = self.u2*sqrt(self.u2)
		self.r = (A2*self.u2 - A1)/3

	def __call__(self, P):
		return ((P[0] - self.r)/self.u2, P[1]/self.u3)

def lift_x(x, A):
	'''
	Lifts x-coordinate to points on E_A.
	'''
	y = sqrt(x^3 + A*x^2 + x)
	return (x, y), (x, -y)

def torsion_points(A):
	'''
	Finds the 2-torsion points of E_A. Their x-coordinates are roots of the
	elliptic curve equation
	  0 = x^3 + Ax^2 + x.
	'''
	s = -A/2
	t = sqrt(s^2 - 1)
	return 0, s + t, s - t

def division_points(P, A):
	'''
	Finds the 2-division points of P on E_A. Their x-coordinates satisfy the
	x-only point doubling formula
	  P[0] = (x^2 - 1)^2 / (4x (x^2 + Ax + 1)),
	and hence are roots of the polynomial
	  x^4 - 4 P[0] x^3 - (4A P[0] + 2) x^2 - 4 P[0] x + 1.
	'''
	r = sqrt(P[0]*(P[0] + A) + 1)
	s1 = P[0] + r
	s2 = P[0] - r
	t1 = sqrt(s1^2 - 1)
	t2 = sqrt(s2^2 - 1)
	X = seq(s1 + t1, s1 - t1, s2 + t2, s2 - t2).distinct()
	if X.len() == 2:
		return X.flat_map(lambda x: lift_x(x, A))
	Y = X.map(lambda x: ((3*x^2 + 2*A*x + 1)*(x - P[0])/2 - x*(x^2 + A*x + 1))/P[1])
	return X.zip(Y)

def preimage(phi, P):
	a = phi.kernel
	A = phi.domain
	if a == 0:
		r = sqrt(A + 2)
		u = P[1]*sqrt(2*r)^3
		s = P[0]*r + 1
		t = sqrt(s^2 - 1)
		X = seq(s + t, s - t).distinct()
		if X.distinct().len() == 1:
			return X.flat_map(lambda x: lift_x(x, A))
		Y = X.map(lambda x: u/(1 - 1/x^2))
		return X.zip(Y)
	else:
		u = P[1]/sqrt(a)
		s = (P[0] + 1)/(2*a)
		t = sqrt(s^2 - P[0])
		X = seq(s + t, s - t).distinct()
		if X.len() == 1:
			return X.flat_map(lambda x: lift_x(x, A))
		Y = X.map(lambda x: u/((a - a^3)/(x - a)^2 + a))
		return X.zip(Y)

class DummyOracle:
	def __init__(self, sk):
		self.sk = sk
		xS = ladder3pt(xP2, xQ2, xR2, self.sk, A0)
		self.pk = isogen2(A0, xS, pts=(xP3, xQ3, xR3))

	@lru_cache()
	def _isoex2(self, xP, xQ, xR):
		A = cfpk(xP, xQ, xR)
		xS = ladder3pt(xP, xQ, xR, self.sk, A)
		return jinv(isogen2(A, xS)[0])

	def query(self, xP, xQ, xR, j, m):
		return j == self._isoex2(xP, xQ, xR)

def serialize(x):
	if type(x) == list:
		return bytes().join(map(serialize, x))
	elif x.parent() == Fp:
		return int(x).to_bytes(sidh.p_bytes, byteorder='little')
	elif x.parent() == Fp2:
		return serialize(x.polynomial().list())
	else:
		raise ValueError(f'cannot serialize {type(x)}')

def deserialize(buf):
	coeffs = []
	for i in range(0, len(buf), sidh.p_bytes):
		coeffs.append(Fp(int.from_bytes(buf[i:i+sidh.p_bytes], byteorder='little')))
	if len(coeffs) == 1:
		return coeffs[0]
	elements = []
	for i in range(0, len(coeffs), 2):
		elements.append(coeffs[i] + coeffs[i+1]*ii)
	return elements

class RealOracle:
	def __init__(self):
		with open('pk.bin', 'rb') as f:
			pk = f.read()
		
		xP, xQ, xR = deserialize(pk)
		A = cfpk(xP, xQ, xR)
		self.pk = (A, (xP, xQ, xR))

	def query(self, xP, xQ, xR, j, m):
		c0 = serialize([xP, xQ, xR])
		c1 = xor(H(serialize(j)), m)
		ct = c0 + c1

		start = time.time()
		# nc = process(['python3', 'server.py'])
		nc = remote('mc.ax', 31338)
		nc.sendlineafter(b'ct (hex): ', ct.hex().encode())
		nc.recvline()

		nc.recvuntil(b'took ')
		delta = int(nc.recvuntil(b' '))
		nc.close()

		print(delta, time.time() - start)

		if delta > 100:
			return True
		else:
			return False

class Solver:
	def __init__(self, oracle):
		self.oracle = oracle
		self.cache = {
			'positive': dict(),
			'negative': set(),
		}

		with open('pk.bin', 'rb') as f:
			pk = f.read()

		kem = KEM(pk)
		self.m = b'defundtjdefundtj'
		r = G(self.m + kem.pk)
		self.sk = ZZ(deserialize(r))
		c0, _ = kem._encrypt(self.m, r)
		xP, xQ, xR = deserialize(c0)
		self.A = cfpk(xP, xQ, xR)
		E = EllipticCurve(Fp2, [0, self.A, 0, 1, 0])
		self.P = E.lift_x(xP)
		self.Q = seq(E.lift_x(xQ, all=True)).find(lambda Q: (self.P - Q)[0] == xR)

	def query(self, i, A, P):
		j = isoex2_full(A, P[0], n=i)

		if i in self.cache['positive']:
			return self.cache['positive'][i] == j

		if (i, j) in self.cache['negative']:
			return False

		xP = self.P[0]
		Q = (1 + 2^(e2-i-BITS))*self.Q
		xQ = Q[0]
		xR = (self.P - Q)[0]

		if self.oracle.query(xP, xQ, xR, j, self.m):
			self.cache['positive'][i] = j
			return True
		else:
			self.cache['negative'].add((i, j))
			return False

	def test(self, i, phi, S, Gs):
		E = EllipticCurve([0, phi.domain, 0, 1, 0])
		S = E(*S)
		return Gs.filter(lambda G: self.query(i+1, phi.domain, S + E(*G)))

	def phase1(self):
		A, _ = isogen3(oracle.pk[0], ladder3pt(*oracle.pk[1], self.sk, oracle.pk[0]))
		for a in torsion_points(A):
			phi = Isogeny(a, A).dual()
			S = (phi.kernel, 0)
			Gs = seq(torsion_points(phi.domain)).filter(lambda a: a != phi.kernel).map(lambda a: (a, 0))
			if hits := self.test(0, phi, S, Gs):
				return phi.domain, S, hits

	def phase2(self, i, A, S, G):
		phi = Isogeny(xDBL(G[0], A, n=i-1), A).dual()
		psi = Isomorphism(A, phi.codomain)
		SS = preimage(phi, psi(S))[0]
		for GG in preimage(phi, psi(G)):
			if hits := self.test(i, phi, SS, division_points(GG, phi.domain)):
				return phi.domain, SS, hits

	def offline(self, A, S, G):
		for i in range(e2//2+1, e2):
			phi = Isogeny(xDBL(G[0], A, n=e2//2), A).dual()
			psi = Isomorphism(A, phi.codomain)
			A = phi.domain
			S = preimage(phi, psi(S))[0]
			G = preimage(phi, psi(G))[0]
		assert jinv(A) == jinv(self.A)

		E = EllipticCurve(Fp2, [0, self.A, 0, 1, 0])
		psi = Isomorphism(A, self.A)
		S = E(psi(S))
		u, v = 0, 0
		for i in range(e2):
			lift = 2^(e2-(i+1))
			Pbar, Qbar, Sbar = seq(self.P, self.Q, S).map(lambda P: lift*P)
			u, v = seq(u, 2^i + u).cartesian(seq(v, 2^i + v)).find(lambda t: t[0]*Pbar + t[1]*Qbar == Sbar)
		return ZZ(mod(v/u, 2^e2))

BITS = 3
# oracle = DummyOracle(1337 << BITS)
oracle = RealOracle()

solver = Solver(oracle)

A, S, curr = solver.phase1()
for i in tqdm(range(1, e2//2+1)):
	for G in curr:
		if result := solver.phase2(i, A, S, G):
			A, S, curr = result
			break
	else:
		raise ValueError('something went wrong')

G = curr[0]
sk = solver.offline(A, S, G)
print(sk)

with open('flag.enc', 'rb') as f:
	flag = f.read()
	key = scrypt(serialize(Fp(sk)), salt=b'defund', n=int(1048576), r=int(8), p=int(1), maxmem=int(1073744896), dklen=len(flag))
	print(xor(key, flag))
