def xor(x, y):
	o = ''
	for i in range(len(x)):
		o += chr(ord(x[i])^ord(y[i]))
	return o

out = '\x15\x02\x07\x12\x1e\x100\x01\t\n\x01"'

milk = 'actf{*******'
cream = '***********}'

print(xor(out, milk))
print(xor(out, cream))

milk = 'actf{co****_'
cream = 'tastes_****}'

print(xor(out, milk))
print(xor(out, cream))

milk = 'actf{co****_'
cream = 'tastes_good}'

print(xor(out, milk))
print(xor(out, cream))

milk = 'actf{coffee_'
cream = 'tastes_good}'