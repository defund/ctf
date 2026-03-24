import snarg
from add import build_adder

if __name__ == '__main__':
	n = 64
	circuit = build_adder(n)

	with open('crs.bin', 'wb') as crs, open('vk.bin', 'wb') as vk:
		snarg.setup(circuit, crs, vk)
