# to generate constraints.json, run
# cargo run --bin client -- --circuit ../aes.txt --input 00000000000000000000000000000000 localhost:5000

import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

with open('constraints.json') as f:
	constraints = json.load(f)

with open('../flag_enc.txt') as f:
	flag_enc = bytes.fromhex(f.read())

n = 256
M = []
v = []

for c in constraints:
	M.append([1 if i in c['ids'] else 0 for i in range(n)])
	v.append(1 if c['bit'] else 0)

F = GF(2)
M = matrix(F, M)
v = vector(F, v)
u = M.solve_right(v)

for w in M.right_kernel():
	sol = u + w
	key = int(''.join(map(str, sol[128:])), 2).to_bytes(16, 'big')
	cipher = AES.new(key, AES.MODE_ECB)
	flag = cipher.decrypt(flag_enc)
	if flag.startswith(b'dice{'):
		print(unpad(flag, 16).decode())
		exit()
