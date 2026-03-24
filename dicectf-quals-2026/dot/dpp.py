import random
from dataclasses import dataclass
from itertools import chain
from typing import Iterator
from circuit import AndGate, Circuit, XorGate

random = random.SystemRandom()

State = tuple[int, int]
Vector = list[int]

@dataclass
class LinearConstraint:
	scalars: list[tuple[int, int]]
	constant: int

def trace_len(circuit: Circuit) -> int:
	return len(circuit.inputs) + len(circuit.gates)

def proof_len(circuit: Circuit) -> int:
	n = trace_len(circuit)
	return n + n * (n + 1) // 2

def pair_index(circuit: Circuit, index1: int, index2: int) -> int:
	i = max(index1, index2)
	j = min(index1, index2)
	return trace_len(circuit) + i * (i + 1) // 2 + j

def input_constraints(circuit: Circuit) -> Iterator[LinearConstraint]:
	for i in range(len(circuit.inputs)):
		yield LinearConstraint([(i, 1), (pair_index(circuit, i, i), -1)], 0)

def gate_constraints(circuit: Circuit) -> Iterator[LinearConstraint]:
	for i, gate in enumerate(circuit.gates):
		l = gate.left.index
		r = gate.right.index
		nl = int(gate.left.constant)
		nr = int(gate.right.constant)
		sl = 1 - 2 * nl
		sr = 1 - 2 * nr

		if isinstance(gate, AndGate):
			scalars = [(len(circuit.inputs) + i, 1), (pair_index(circuit, l, r), -sl * sr)]
			if sl * nr != 0:
				scalars.append((l, -sl * nr))
			if sr * nl != 0:
				scalars.append((r, -sr * nl))
			yield LinearConstraint(scalars, nl * nr)
		else:
			scalars = [(len(circuit.inputs) + i, 1), (l, -sl * sr), (r, -sl * sr), (pair_index(circuit, l, r), 2 * sl * sr)]
			yield LinearConstraint(scalars, nl ^ nr)

def output_constraints(circuit: Circuit) -> Iterator[LinearConstraint]:
	for wire in circuit.outputs:
		sl = 1 - 2 * int(wire.constant)
		nl = int(wire.constant)
		yield LinearConstraint([(wire.index, sl)], -nl)

def tensor_queries(circuit: Circuit, bound: int) -> tuple[Vector, Vector]:
	n = trace_len(circuit)
	v = [random.randint(-bound, bound) for _ in range(n)]
	q1 = [0] * proof_len(circuit)
	q2 = [0] * proof_len(circuit)
	for i in range(n):
		q1[i] = v[i]
		for j in range(i + 1):
			q2[pair_index(circuit, i, j)] = v[i] * v[j] if i == j else 2 * v[i] * v[j]
	return (q1, q2)

def constraint_query(circuit: Circuit, bound: int) -> tuple[Vector, int]:
	query = [0] * proof_len(circuit)
	val = 0
	constraints = chain(input_constraints(circuit), gate_constraints(circuit), output_constraints(circuit))
	for constraint in constraints:
		r = random.randint(-bound, bound)
		for idx, scalar in constraint.scalars:
			query[idx] += r * scalar
		val += r * constraint.constant
	return (query, val)

def prove(circuit: Circuit, inputs: Vector) -> Vector:
	outputs, trace = circuit.evaluate(inputs)
	assert all(o == 0 for o in outputs)
	proof = trace + [trace[i] * trace[j] for i in range(len(trace)) for j in range(i + 1)]
	return proof

def sample(circuit: Circuit, bound1: int, bound2: int) -> tuple[Vector, State]:
	n = trace_len(circuit)
	b = n * bound1 + 1
	q1, q2 = tensor_queries(circuit, bound1)
	q3, val = constraint_query(circuit, bound2)
	q = [q1[i] + b * (q2[i] - q3[i]) for i in range(proof_len(circuit))]
	st = (b, val)
	return (q, st)

def answers(st: State, bound: int | None = None) -> Iterator[int]:
	b, val = st
	if bound is None:
		bound = b
	for k in range(bound):
		rhs = k * k - val
		if k == 0:
			yield b * rhs
		else:
			yield k + b * rhs
			yield -k + b * rhs
