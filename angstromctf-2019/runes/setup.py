from Crypto.Util.number import bytes_to_long

import paillier

flag = b'actf{crypto_lives}'

template = '''\
n: {}
g: {}
c: {}'''

pk, sk = paillier.generate()
n, g = pk
m = bytes_to_long(flag)
c = paillier.encrypt(m, pk)

out = template.format(n, g, c)
with open('runes.txt', 'w') as f:
	f.write(out)