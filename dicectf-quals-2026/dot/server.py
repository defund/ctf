import secrets
from fastecdsa.curve import P256
from fastecdsa.encoding.sec1 import SEC1Encoder

import snarg
from add import int_to_bits

if __name__ == '__main__':
	n = 64

	with open('vk.bin', 'rb') as f:
		st = snarg.vk_state(f)

	streak = 0
	while True:
		a = secrets.randbits(n)
		b = secrets.randbits(n)
		print(f'what is {a} + {b}? (mod 2^64)')

		while True:
			c = int(input('answer: '))
			assert 0 <= c < (1 << 64)
			correct = c == (a + b) % (1 << n)

			proof_buf = bytes.fromhex(input('proof: '))
			assert len(proof_buf) == 2 * 33
			h1 = SEC1Encoder.decode_public_key(proof_buf[:33], P256)
			h2 = SEC1Encoder.decode_public_key(proof_buf[33:], P256)

			inputs = int_to_bits(a, n) + int_to_bits(b, n) + int_to_bits(c, n)
			proof = (h1, h2)
			valid = snarg.verify(inputs, st, proof)

			if valid and correct:
				print('correct! but that was obvious...')
				streak = 0
			elif valid and not correct:
				print('huh?')
				streak += 1
				if streak >= 20:
					print(open('flag.txt').read().strip())
					exit()
				break
			else:
				streak = 0
				print('wrong...')
