import itertools
from pwn import process, remote
from tqdm import tqdm
from fastecdsa.curve import P256
from fastecdsa.point import Point
from fastecdsa.encoding.sec1 import SEC1Encoder

import dpp
import snarg
from add import build_adder, int_to_bits

n = 64
circuit = build_adder(n)
base = dpp.trace_len(circuit) * snarg.BOUND1 + 1

def get_crs_element(index):
	with open('crs.bin', 'rb') as f:
		f.seek(33 * index)
		c_enc = f.read(33)
		c = SEC1Encoder.decode_public_key(c_enc, P256)
		return c

def snarg_oracle():
	with open('vk.bin', 'rb') as f:
		st = snarg.vk_state(f)
	inputs = [0] * len(circuit.inputs)
	def batch_verify(proofs):
		return [snarg.verify(inputs, st, proof) for proof in proofs]
	return inputs, batch_verify

def snarg_oracle_server(p):
	# "what is {a} + {b}? (mod 2^64)"
	parts = p.recvline().decode().split()
	a = int(parts[2])
	b = int(parts[4].rstrip('?'))
	c = (a + b) % (1 << n)
	inputs = int_to_bits(a, n) + int_to_bits(b, n) + int_to_bits(c, n)
	def batch_verify(proofs):
		payload = []
		for h1, h2 in proofs:
			proof_hex = (
				SEC1Encoder.encode_public_key(h1, compressed=True) +
				SEC1Encoder.encode_public_key(h2, compressed=True)
			).hex()
			payload.append(str(c))
			payload.append(proof_hex)
		p.sendline('\n'.join(payload).encode())
		results = []
		for _ in range(len(proofs)):
			res = p.recvline().decode()
			results.append('correct!' in res)
		return results
	return inputs, batch_verify

def prove(circuit, dpp_proof):
	n = len(circuit.inputs)
	h1 = Point._identity_element()
	h2 = Point._identity_element()
	with open('crs.bin', 'rb') as crs:
		for i, t in enumerate(tqdm(dpp_proof[n:])):
			c_enc = crs.read(33)
			if t == 0:
				continue
			c = SEC1Encoder.decode_public_key(c_enc, P256)
			h1 += t * snarg.hash_to_point(i)
			h2 += t * c
	proof = (h1, h2)
	return proof

def leak(inputs, query):
	"""find v using the oracle"""
	dpp_proof = dpp.prove(circuit, inputs)
	h1, h2 = prove(circuit, dpp_proof)
	assert query([(h1, h2)])[0]

	indices = set()
	constraints = itertools.chain(dpp.input_constraints(circuit), dpp.gate_constraints(circuit), dpp.output_constraints(circuit))
	for constraint in constraints:
		for index, _ in constraint.scalars:
			indices.add(index)

	# sign could be flipped, but it doesn't affect the products
	v = [None for _ in range(dpp.trace_len(circuit))]
	for i in range(dpp.trace_len(circuit)):
		if dpp.pair_index(circuit, i, i) in indices:
			continue
		proofs = []
		values = []
		for vi in range(snarg.BOUND1 + 1):
			index = dpp.pair_index(circuit, i, i) - len(circuit.inputs)
			c1 = h1 + snarg.hash_to_point(index)
			c2 = h2 + get_crs_element(index) - (base * vi * vi) * P256.G
			proofs.append((c1, c2))
			values.append(vi)
		result = query(proofs)
		assert True in result
		vi = values[result.index(True)]
		v[i] = vi
		break
	else:
		print('bad circuit')
		exit()


	pbar = tqdm(total=len(v) - 1)
	for i in range(dpp.trace_len(circuit)):
		for j in range(i):
			if dpp.pair_index(circuit, i, j) in indices:
				continue

			if v[i] is None and v[j] is None:
				continue
			elif v[i] is None:
				pairs = zip(range(-snarg.BOUND1, snarg.BOUND1 + 1), itertools.repeat(v[j]))
			elif v[j] is None:
				pairs = zip(itertools.repeat(v[i]), range(-snarg.BOUND1, snarg.BOUND1 + 1))
			else:
				continue

			proofs = []
			values = []
			for vi, vj in pairs:
				index = dpp.pair_index(circuit, i, j) - len(circuit.inputs)
				c1 = h1 + snarg.hash_to_point(index)
				c2 = h2 + get_crs_element(index) - (2 * base * vi * vj) * P256.G
				proofs.append((c1, c2))
				values.append((vi, vj))
			result = query(proofs)
			assert True in result
			vi, vj = values[result.index(True)]
			v[i] = vi
			v[j] = vj
			pbar.update()
	pbar.close()

	assert None not in v
	return v

def forge(v, inputs):
	"""only works for some circuits"""
	_, trace = circuit.evaluate(inputs)
	proof = trace + [trace[i] * trace[j] for i in range(len(trace)) for j in range(i + 1)]

	usage = dict()
	constraints = itertools.chain(dpp.input_constraints(circuit), dpp.gate_constraints(circuit), dpp.output_constraints(circuit))
	for constraint in constraints:
		for index, _ in constraint.scalars:
			usage[index] = usage.get(index, 0) + 1

	new_proof = proof[:]
	overwrites = set()
	for constraint in dpp.output_constraints(circuit):
		assert len(constraint.scalars) == 1
		assert constraint.scalars[0][1] == -1
		new_proof[constraint.scalars[0][0]] = 1
		assert sum(new_proof[index]*coeff for index, coeff in constraint.scalars) == constraint.constant
		overwrites.add(constraint.scalars[0][0])

	for constraint in dpp.gate_constraints(circuit):
		if set(index for index, _ in constraint.scalars).intersection(overwrites):
			for index, scalar in constraint.scalars:
				if index >= dpp.trace_len(circuit):
					assert usage[index] == 1
					assert scalar == 1
					new_proof[index] += constraint.constant - sum(new_proof[index]*coeff for index, coeff in constraint.scalars)
					assert sum(new_proof[index]*coeff for index, coeff in constraint.scalars) == constraint.constant

	constraints = itertools.chain(dpp.input_constraints(circuit), dpp.gate_constraints(circuit), dpp.output_constraints(circuit))
	for constraint in constraints:
		assert sum(new_proof[index]*coeff for index, coeff in constraint.scalars) == constraint.constant

	z = new_proof[:dpp.trace_len(circuit)]
	zz = [z[i] * z[j] for i in range(len(z)) for j in range(i + 1)]
	new_proof_zz = new_proof[dpp.trace_len(circuit):]
	diff = [new_proof_zz[i] - zz[i] for i in range(len(zz))]
	vv = [0] * len(zz)
	for i in range(len(v)):
		for j in range(i + 1):
			vv[i * (i + 1) // 2 + j] = v[i] * v[j] if i == j else 2 * v[i] * v[j]
	extra = sum(x*y for x, y in zip(diff, vv))

	h1, h2 = prove(circuit, new_proof)
	h2 -= (base * extra) * P256.G
	proof = (h1, h2)
	return proof

def attack(v, p):
	"""submit forged proofs for wrong answers until the server prints the flag"""
	streak = 0
	while streak < 20:
		# "what is {a} + {b}? (mod 2^64)"
		parts = p.recvline().decode().split()
		a = int(parts[2])
		b = int(parts[4].rstrip('?'))
		c = (a + b + 1) % (1 << n)

		inputs = int_to_bits(a, n) + int_to_bits(b, n) + int_to_bits(c, n)
		h1, h2 = forge(v, inputs)
		proof_hex = (
			SEC1Encoder.encode_public_key(h1, compressed=True) +
			SEC1Encoder.encode_public_key(h2, compressed=True)
		).hex()

		p.sendlineafter(b'answer: ', str(c).encode())
		p.sendlineafter(b'proof: ', proof_hex.encode())

		response = p.recvline().decode().strip()
		print(response)
		if response == 'huh?':
			streak += 1
		else:
			streak = 0

	print(p.recvline().decode().strip())

# inputs, query = snarg_oracle()
p = process(['python', 'server.py'])
inputs, query = snarg_oracle_server(p)
v = leak(inputs, query)
print(v)

# v = [80, -76, -167, -2, 105, 34, -174, 148, 72, 223, 151, -73, 49, -216, 115, 82, 111, -186, -57, 73, -140, -139, 230, 13, -204, 53, 164, -168, -159, 61, 251, 22, -5, -20, 86, -131, -186, 154, 141, -237, 224, -230, -163, -96, -88, -7, -158, -182, 120, 62, 143, -11, 51, -183, -152, 256, 226, -104, -96, -90, 191, 151, 15, -251, 55, 128, -80, 115, 218, 78, -78, -116, -22, 154, -136, 1, 106, 173, 245, -128, -233, -28, -234, -237, -219, -114, -182, -225, 180, -28, -206, 180, 177, -51, -200, 124, -144, 63, 237, -184, 133, 106, -253, -59, 17, 82, 18, -232, 71, -129, -106, -139, 68, 173, -62, 85, 229, -5, -246, 154, -134, 9, 239, -58, 70, -156, 36, -182, -206, -10, 102, 126, 182, 105, -164, 215, -43, -14, 246, 24, 248, 182, 143, -146, 185, 245, -79, -124, 225, 166, 162, 250, -192, -18, -196, -128, -203, 108, -45, 155, -114, -134, -189, 186, 174, -239, 13, -241, 69, 199, -127, -243, 189, 60, -46, 155, 141, -164, -3, -46, -222, -105, 223, 97, 163, 184, -36, -145, 205, -102, 223, 74, 34, -3, 100, 128, 159, 7, -139, -94, 238, 226, -128, 205, 61, 171, -15, -222, 41, -81, -7, 29, -154, -135, -56, 133, 227, -106, -232, -45, -10, 143, -213, -148, -194, -17, 19, -10, -234, 159, 240, -117, 134, 225, -55, 79, -178, -191, 64, -14, 164, -204, -155, 0, 198, 50, 206, -162, -93, 68, -2, 117, 75, 68, 17, -59, 49, 199, 211, 193, 120, 81, 174, 106, 52, -175, 88, 121, 82, -223, 241, 87, 173, -134, -28, 214, 11, 195, -62, -128, -185, 127, -187, 16, 45, 217, 161, -198, 219, -68, 176, -210, -145, -188, 156, 92, -179, 25, 237, -227, -57, 226, 97, -248, -13, 90, -66, 237, -18, -160, -66, -38, -69, 38, -248, 55, 14, -71, -15, -6, 167, -215, -21, -115, 158, -195, 5, -91, 231, -78, -101, -144, -46, -119, 32, 123, -180, 175, 84, 77, 31, 112, 137, 125, -61, -172, -175, -234, 197, 139, -56, -183, 136, -168, 66, 88, -228, 93, 171, 251, -191, 249, -135, 0, -230, -19, -130, 124, -191, -125, 246, 21, -240, 92, 75, 105, 248, -236, 230, 113, -193, 188, -130, 40, 246, 60, 201, 6, -223, -27, -97, -5, 143, 204, -97, -161, 101, 182, 73, 101, 148, -32, 209, -54, 4, -72, 209, 159, -65, -139, 176, -122, 160, 6, 10, -46, -78, 121, 139, 219, -149, -210, 202, -100, 62, 75, 227, 74, -5, -148, -84, -214, -4, -88, 29, -147, 169, -5, 176, -183, 165, 178, -41, -160, 54, 219, -93, -31, 70, -158, 116, -55, 118, -105, -37, -68, -109, -234, -138, -246, -219, -69, 21, 95, -188, -164, 221, -169, 66, 5, -74, -69, 216, 25, -163, -81, 61, 139, -122, -63, 164, 235, 190, -50, -215, -163, -115, -163, -226, 52, -231, 123, 167, 235, -88, 120, -162, 57, 196, -9, -209, 50, -231, -199, 205, 69, -28, 241, -115, 127, 175, -15, -214, -22, -211, 48, 175, 62, 142, -35, -140, -84, -129, 74, -116, -43, -245, 138, 146, 54, -80, -164, 179, 245, -166, -37, 197, -1, 7, 174, -124, -57, 70, -191, -216, -79, -220, 251, 111, -14, -209, -1, -8, -10, 32, 128, -119, -225, -84, 224, -238, -132, -196, 117, 182, 150, -62, -48, -248, -115, -204, -189, 221, -231, -97, 42, 243, -230, 169, -226, 176, 247, 183, 209, -127, -224, 178, 193, -186, 96, 169, -93, -177, -116, 14, 120, -51, 39, -19, 13, 247, 141, 5, 91, -244, 94, 106, 147, -140, -65, 65, -56, -181, -220, -129, 256, -22, 21, 89, 88, 197, -157, -154, 49, 44, 141, 171, -100, -94, -65, -228, -88, -223, -113, 211, -56]
# p = process(['python', 'server.py'])
# attack(v, p)
