from Crypto.PublicKey import RSA

key = RSA.generate(2048)

with open('private.txt', 'w') as f:
	f.write('d: {}'.format(key.d))

with open('public.txt', 'w') as f:
	f.write('n: {}\ne: {}'.format(key.n, key.e))