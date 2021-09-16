from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor

from local import flag, key

def query(iv, enc):
	try:
		cipher = AES.new(key, AES.MODE_CBC, iv)
		dec = b64decode(cipher.decrypt(enc))
		if dec == b'One who has eaten the fruit and tasted its mysteries.':
			return flag
		return True
	except:
		return False

table64 = [[] for _ in range(256)]
table65 = [[] for _ in range(256)]
charset64 = list(range(48, 58)) + list(range(65, 91)) + list(range(97, 123)) + [43, 47]
charset65 = charset64 + [61]
for j in range(256):
	for c in range(256):
		table64[j].append(j^c in charset64)
		table65[j].append(j^c in charset65)

def generate(dec, enc):
	while True:
		iv = get_random_bytes(16)
		if query(iv, enc):
			break
	actual = []
	for i in range(16):
		tmp = list(iv)
		row = []
		for c in range(256):
			tmp[i] = c
			row.append(query(bytes(tmp), enc))
		if row.count(True) > row.count(False):
			row = [not x for x in row]
		try:
			if row.count(True) == 64:
				actual.append(table64.index(row))
			else:
				actual.append(table65.index(row))
		except:
			return generate(dec, enc)
	return strxor(dec, bytes(actual))

dec = pad(b64encode(b'One who has eaten the fruit and tasted its mysteries.'), 16)
dec = [dec[i:i+16] for i in range(0, len(dec), 16)][::-1]
enc = [bytes(16)]
for i in range(len(dec)):
	enc.append(generate(dec[i], enc[i]))
flag = query(enc[-1], b''.join(enc[-2::-1])).decode()
print(flag)
