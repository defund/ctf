import random

m = pow(2, 32)
a = random.randint(0, m)
c = random.randint(0, m)
x = random.randint(0, m)

with open('lcg', 'w') as f:
	f.write('{}\n{}\n{}'.format(a, c, x))