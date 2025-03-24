from random import SystemRandom

from fastecdsa.point import Point

from .params import curve

random = SystemRandom()


class Card:
	def __init__(self, P, Q):
		self.P = P
		self.Q = Q

	@classmethod
	def new(cls, value):
		return cls(Point.IDENTITY_ELEMENT, value)


class Shuffle:
	def __init__(self, perm, masks):
		self.perm = perm
		self.masks = masks

	@classmethod
	def random(cls, n):
		perm = random.sample(range(n), k=n)
		masks = [random.randrange(curve.q) for _ in range(n)]
		return cls(perm, masks)

	def __sub__(self, other):
		perm = [other.perm.index(x) for x in self.perm]
		masks = [(r1 - r2) % curve.q for r1, r2 in zip(self.masks, map(other.masks.__getitem__, perm))]
		return Shuffle(perm, masks)

	def apply(self, pub, cards, curve=curve):
		return [Card(c.P + r * curve.G, c.Q + r * pub) for c, r in zip(map(cards.__getitem__, self.perm), self.masks)]
