import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

if __name__ == '__main__':
	with open('flag.txt', 'rb') as f:
		flag = f.read().strip()

	key = secrets.token_bytes(16)
	cipher = AES.new(key, AES.MODE_ECB)
	flag_enc = cipher.encrypt(pad(flag, 16))

	with open('key.txt', 'w') as f:
		f.write(key.hex())

	with open('flag_enc.txt', 'w') as f:
		f.write(flag_enc.hex())
