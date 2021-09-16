from lamport import *

pk, sk = generate()
pack('pk', pk)
pack('sk', sk)
