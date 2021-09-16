from paillier import *

sk = unpack('sk')

print('We specialize in giving useless metadata about encrypted messages!')
c = int(input('Encrypted message: '))
m = decrypt(c, sk)
length = m.bit_length()
print('The message is {} bits long'.format(length))
