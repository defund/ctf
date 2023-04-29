import numpy as np

import lwe
import otp

flag = b'actf{oops_sorry_for_the_lack_of_randomness}'

A = lwe.public()
s, b = lwe.sample(A)
enc = otp.encrypt(s, flag)

with open('A.npy', 'wb') as f:
	np.save(f, A)

with open('s.npy', 'wb') as f:
	np.save(f, s)

with open('b.npy', 'wb') as f:
	np.save(f, b)

with open('flag.enc', 'wb') as f:
	f.write(enc)