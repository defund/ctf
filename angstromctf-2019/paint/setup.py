import binascii
import random

from secret import flag

template = '''\
palette: {}
base: {}
my mix: {}
your mix: {}
painting: {}'''

m = int(binascii.hexlify(flag), 16)

n = 1 << 2048
g = random.randint(0, n) | 1
x = random.randint(0, n)
gx = pow(g, x, n)
y = random.randint(0, n)
gy = pow(g, y, n)
s = pow(gy, x, n)
c = m ^ s

out = template.format(n, g, gx, gy, c)
with open('paint.txt', 'w') as f:
	f.write(out)