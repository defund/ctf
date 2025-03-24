import json
from random import SystemRandom

from Crypto.Hash import SHAKE128
import fastecdsa.keys

from .params import curve

random = SystemRandom()

def hash_to_chall(points):
	shake = SHAKE128.new()
	shake.update(json.dumps([(P.x, P.y) for P in points]).encode())
	return fastecdsa.keys.gen_private_key(curve, randfunc=shake.read)

def cp_prove(Gs, Hs, x):
	r = random.randrange(curve.q)
	As = [r * G for G in Gs]
	c = hash_to_chall(As)
	y = (x * c + r) % curve.q
	return c, y

def cp_verify(Gs, Hs, proof):
	c, y = proof
	As = [y * G - c * H for G, H in zip(Gs, Hs)]
	assert c == hash_to_chall(As)

def reveal_and_prove(card, pub, priv):
	share = priv * card.P
	proof = cp_prove([curve.G, card.P], [pub, share], priv)
	return share, proof

def verify(card, pub, share, proof):
	cp_verify([curve.G, card.P], [pub, share], proof)
