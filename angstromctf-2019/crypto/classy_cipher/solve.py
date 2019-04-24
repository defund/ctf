def encrypt(d, s):
	e = ''
	for c in d:
		e += chr((ord(c)+s) % 0xff)
	return e

e = ':<M?TLH8<A:KFBG@V'
for i in range(256):
	d = encrypt(e, i)
	if d.startswith('actf'):
		print(d)
