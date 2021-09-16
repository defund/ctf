from base64 import b64decode

from Crypto.Cipher import AES

from local import flag, key

split = lambda s: (s[:16], s[16:])

while True:
	print('Who knocks at the guarded gate?')
	try:
		iv, enc = split(b64decode(input()))
		cipher = AES.new(key, AES.MODE_CBC, iv)
		dec = b64decode(cipher.decrypt(enc))
		if dec == b'One who has eaten the fruit and tasted its mysteries.':
			print(flag)
	except:
		print('\u2741')
