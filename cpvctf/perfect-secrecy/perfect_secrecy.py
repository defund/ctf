import secrets

from local import flag

print('One-time pads have perfect secrecy!')
for char in flag:
	key = secrets.randbelow(0xff)
	print('{:02x}'.format(char ^ key), end='')
print()
