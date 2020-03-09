import secrets

from local import flag

def query():
	enc = []
	for char in flag:
		key = secrets.randbelow(0xff)
		enc.append(char ^ key)
	return enc

table = [[False for _ in range(256)] for _ in query()]
for _ in range(3000):
	for i, char in enumerate(query()):
		table[i][char] = True

flag = bytes([row.index(False) ^ 0xff for row in table]).decode()
print(flag)
