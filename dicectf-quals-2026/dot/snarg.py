import hashlib
import math
from itertools import islice
from multiprocessing import Pool
from typing import BinaryIO
from fastecdsa.curve import P256
from fastecdsa.keys import gen_private_key
from fastecdsa.point import Point
from fastecdsa.encoding.sec1 import SEC1Encoder
from tqdm import tqdm

from circuit import Circuit
import dpp


Proof = tuple[Point, Point]
State = tuple[int, list[int], set[bytes]]

BOUND1 = 2**8
BOUND2 = 2**40

def hash_to_point(i: int) -> Point:
	p = P256.p
	for ctr in range(256):
		x = int.from_bytes(hashlib.sha256(i.to_bytes(8, 'little') + bytes([ctr])).digest()) % p
		y_sq = (pow(x, 3, p) - 3 * x + P256.b) % p
		y = pow(y_sq, (p + 1) // 4, p)
		if pow(y, 2, p) == y_sq:
			return Point(x, y, curve=P256)
	raise ValueError(f'hash_to_point failed for i={i}')

def compute_c(args: tuple[int, int, int]) -> bytes:
	i, qi, sk = args
	c = qi * P256.G + sk * hash_to_point(i)
	return SEC1Encoder.encode_public_key(c, compressed=True)

def setup(circuit: Circuit, crs: BinaryIO, vk: BinaryIO) -> None:
	n = len(circuit.inputs)
	q, st = dpp.sample(circuit, BOUND1, BOUND2)
	sk = gen_private_key(P256)
	vk.write(f'{sk}\n'.encode())
	vk.write((','.join(str(qi) for qi in q[:n]) + '\n').encode())

	with Pool() as pool:
		args = ((i, qi, sk) for i, qi in enumerate(q[n:]))
		for c_enc in tqdm(pool.imap(compute_c, args), total=len(q) - n):
			crs.write(c_enc)

	# allow for small completeness error
	table_size = 10 * round(math.sqrt(dpp.trace_len(circuit) / 6) * BOUND1)
	for a in tqdm(islice(dpp.answers(st), table_size), total=table_size):
		p = a * P256.G
		p_enc = SEC1Encoder.encode_public_key(p, compressed=True)
		vk.write(p_enc)

def prove(circuit: Circuit, inputs: list[int], crs: BinaryIO) -> Proof:
	dpp_proof = dpp.prove(circuit, inputs)
	n = len(circuit.inputs)
	h1 = Point._identity_element()
	h2 = Point._identity_element()
	for i, t in enumerate(tqdm(dpp_proof[n:])):
		c_enc = crs.read(33)
		if t == 0:
			continue
		c = SEC1Encoder.decode_public_key(c_enc, P256)
		h1 += t * hash_to_point(i)
		h2 += t * c
	proof = (h1, h2)
	return proof

def vk_state(vk: BinaryIO) -> State:
	sk = int(vk.readline())
	q_inputs = [int(x) for x in vk.readline().split(b',')]
	table = set()
	while p_enc := vk.read(33):
		table.add(p_enc)
	return (sk, q_inputs, table)

def verify(inputs: list[int], st: State, proof: Proof) -> bool:
	sk, q_inputs, table = st
	assert len(inputs) == len(q_inputs)
	assert all(x in (0, 1) for x in inputs)
	h1, h2 = proof
	p = h2 - sk * h1
	input_sum = sum(q_inputs[i] * inputs[i] for i in range(len(inputs)))
	p += input_sum * P256.G
	p_enc = SEC1Encoder.encode_public_key(p, compressed=True)
	return p_enc in table
