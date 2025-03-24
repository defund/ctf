from Crypto.Cipher import AES

def encrypt(key, pt):
	cipher = AES.new(key, AES.MODE_CFB)
	ct = cipher.decrypt(pt)
	return cipher.iv + ct

if __name__ == '__main__':
	import os

	with open('flag.txt', 'rb') as f:
		flag = f.read().strip()

	key = os.urandom(16)

	print(f'encrypted flag: {encrypt(key, flag).hex()}')
	while True:
		msg = bytes.fromhex(input('message: '))
		print(f'encrypted message: {encrypt(key, msg).hex()}')
