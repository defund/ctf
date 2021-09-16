from paillier import *

from local import flag

pk, sk = generate()
pack('pk', pk)
pack('sk', sk)

m = int.from_bytes(flag, 'big')
c = encrypt(m, pk)
with open('flag.enc', 'w') as f:
	f.write(str(c))
