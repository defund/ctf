import itertools
import json
from multiprocessing import Pool

from Crypto.Hash import SHAKE128

from .card import Shuffle
from .params import curve, MIX_BIT_SECURITY, WORKERS

def slow_apply(shuffles, pub, decks):
	return [Shuffle.apply(shuffle, pub, deck, curve) for shuffle, deck in zip(shuffles, decks)]

def fast_apply(shuffles, pub, decks):
	with Pool(WORKERS) as p:
		return p.starmap(Shuffle.apply, [(shuffle, pub, deck, curve) for shuffle, deck in zip(shuffles, decks)])

def hash_to_chall(pub, old, new, tmps):
	points = [pub]
	for card in itertools.chain(old, new, *tmps):
		points.append(card.P)
		points.append(card.Q)
	shake = SHAKE128.new()
	shake.update(json.dumps([(P.x, P.y) for P in points]).encode())
	bits = int.from_bytes(shake.read((MIX_BIT_SECURITY + 7) // 8), 'big')
	return [bool((bits >> i) & 1) for i in range(MIX_BIT_SECURITY)]

def mix_and_prove(pub, old, par=True):
	snew = Shuffle.random(len(old))
	new = snew.apply(pub, old)
	stmps = [Shuffle.random(len(old)) for _ in range(MIX_BIT_SECURITY)]
	tmps = (fast_apply if par else slow_apply)(stmps, pub, itertools.repeat(old))
	chall = hash_to_chall(pub, old, new, tmps)
	shuffles = [s if c else s - snew for c, s in zip(chall, stmps)]
	return new, (chall, shuffles)

def verify(pub, old, new, proof, par=True):
	chall, shuffles = proof
	tmps = (fast_apply if par else slow_apply)(shuffles, pub, [old if c else new for c in chall])
	assert chall == hash_to_chall(pub, old, new, tmps)
