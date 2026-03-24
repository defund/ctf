from dataclasses import dataclass
from typing import Optional


@dataclass
class Wire:
    index: Optional[int]
    constant: bool

    @classmethod
    def of(cls, index: int):
        return cls(index, False)

    @classmethod
    def constant(cls, value: bool):
        return cls(None, value)

    def __invert__(self):
        return Wire(self.index, not self.constant)

@dataclass
class AndGate:
    left: Wire
    right: Wire

@dataclass
class XorGate:
    left: Wire
    right: Wire

class Circuit:
    def __init__(self, num_inputs: int):
        self.inputs: list[Wire] = [Wire.of(i) for i in range(num_inputs)]
        self.gates: list[AndGate | XorGate] = []
        self.outputs: list[Wire] = []

    def gate_wire(self, gate: AndGate | XorGate) -> Wire:
        index = len(self.inputs) + len(self.gates)
        self.gates.append(gate)
        return Wire.of(index)

    def output_wire(self, wire: Wire) -> None:
        self.outputs.append(wire)

    def and_gate(self, left: Wire, right: Wire) -> Wire:
        if left.index is None:
            return Wire.constant(False) if not left.constant else right
        if right.index is None:
            return Wire.constant(False) if not right.constant else left
        return self.gate_wire(AndGate(left, right))

    def xor_gate(self, left: Wire, right: Wire) -> Wire:
        if left.index is None:
            return right if not left.constant else ~right
        if right.index is None:
            return left if not right.constant else ~left
        return self.gate_wire(XorGate(left, right))

    def or_gate(self, left: Wire, right: Wire) -> Wire:
        return ~self.and_gate(~left, ~right)

    def evaluate(self, input_values: list[int]) -> tuple[list[int], list[int]]:
        gate_values: list[int] = []

        def resolve(wire: Wire) -> int:
            if wire.index is None:
                return int(wire.constant)
            elif wire.index < len(self.inputs):
                return input_values[wire.index] ^ int(wire.constant)
            else:
                gate_index = wire.index - len(self.inputs)
                return gate_values[gate_index] ^ int(wire.constant)

        for gate in self.gates:
            left = resolve(gate.left)
            right = resolve(gate.right)
            if isinstance(gate, AndGate):
                gate_values.append(left & right)
            else:
                gate_values.append(left ^ right)

        outputs = [resolve(wire) for wire in self.outputs]
        trace = input_values + gate_values
        return (outputs, trace)
