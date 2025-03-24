from multiprocessing import Pool
import random
import time

import fastecdsa.curve

curve = fastecdsa.curve.P256

'''
The goal of this script is to make sure that your machine is powerful enough
to run the client script. Set WORKERS to be roughly the number of cores on
your machine. delta should be comfortably less than 30 seconds. On my M1 Pro,
delta is ~6 seconds with WORKERS = 4.

When you receive the game logic code, update game/params.py to use the same
WORKERS constant.
'''

WORKERS = 4

def foo(r):
	P = r * curve.G
	Q = r * P
	return P + Q

if __name__ == '__main__':
	NGAMES = 88
	start = time.time()
	for _ in range(NGAMES):
		with Pool(WORKERS) as p:
			p.map(foo, [random.randrange(0, curve.q) for i in range(128)])
	end = time.time()
	print(f'delta: {end - start}')
