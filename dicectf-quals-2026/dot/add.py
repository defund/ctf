import dpp
from circuit import Circuit, Wire

def build_adder(n: int) -> Circuit:
    # inputs[0..n-1] = a, inputs[n..2n-1] = b, inputs[2n..3n-1] = c (LSB first)
    # single output wire constrained to 0 iff a+b == c (mod 2^n)
    circ = Circuit(3 * n)
    carry = Wire.constant(False)
    all_match = Wire.constant(True)

    for i in range(n):
        a = circ.inputs[i]
        b = circ.inputs[n + i]
        c = circ.inputs[2 * n + i]

        a_xor_b = circ.xor_gate(a, b)
        sum_bit = circ.xor_gate(a_xor_b, carry)
        carry = circ.or_gate(circ.and_gate(a, b), circ.and_gate(carry, a_xor_b))

        all_match = circ.and_gate(all_match, ~circ.xor_gate(sum_bit, c))

    circ.output_wire(~all_match)
    return circ

def int_to_bits(n: int, width: int) -> list[int]:
    return [(n >> i) & 1 for i in range(width)]

def bits_to_int(bits: list[int]) -> int:
    return sum(b << i for i, b in enumerate(bits))

if __name__ == '__main__':
    n = 8
    adder = build_adder(n)
    print(f'trace_len: {dpp.trace_len(adder)}')

    a, b = 123, 200
    c = (a + b) % (1 << n)
    inputs = int_to_bits(a, n) + int_to_bits(b, n) + int_to_bits(c, n)
    outputs, trace = adder.evaluate(inputs)
    print(f'{a} + {b} = {c}: outputs all zero = {all(o == 0 for o in outputs)}')
