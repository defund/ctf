import base64
from Crypto.Util.strxor import strxor
from fastecdsa.curve import P256
from fastecdsa.keys import export_key
from fastecdsa.point import Point
from functools import reduce
import itertools
from operator import add
from tqdm import tqdm

G = Point(P256.gx, P256.gy)

hx = 0x7bd81aa93dd37b54e1d39c04f4db67dc65e6b9521107dd11c80e871ef3bd614b
hy = 0x1a17ad5a51b6cc7517618881702a23fe8cc6e4bb06af3a5c5c4dc7b84ccf1108
H = Point(hx, hy)

priv = b'    37PMrof3dNCpeuwsSUupbaUh3/+7+eDnRH+3   ='

d = int.from_bytes(base64.b64decode(priv.replace(b' ', b'A')), 'big')
print(bin(d)[2:].zfill(256))

s1 = base64.b64decode(priv.replace(b' ', b'A'))
s2 = base64.b64decode(priv.replace(b' ', b'/'))
mask = int.from_bytes(strxor(s1, s2), 'big')

inf = 0 * G
X = []
for i in range(256):
	if (mask >> i) & 1:
		X.append((inf, (1 << i) * G))

print(len(X))

P = d*G

table = dict()
for guess in tqdm(itertools.product(*X[:len(X)//2]), total=2**(len(X)//2)):
	t = reduce(add, guess)
	table[(P + t).x] = guess

for guess in tqdm(itertools.product(*X[len(X)//2:]), total=2**(len(X) - len(X)//2)):
	t = reduce(add, guess)
	if (H - t).x in table:
		print('found')
		points = itertools.chain(table[(H - t).x], guess)
		for i in range(256):
			if (mask >> i & 1) and next(points) != inf:
				d += 1 << i
		export_key(d, P256, 'id_ecdsa_recovered')
		exit()
