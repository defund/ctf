from lamport import *

from local import flag

options = '''\
[D]eposit money
[E]xecute receipt
[L]eave'''

pk = unpack('pk')
sk = unpack('sk')

print('$$$ Bank of Lamport $$$')

while True:
	print(options)
	choice = input('Choice: ')
	if choice == 'D':
		try:
			amount = int(input('Amount to deposit: '))
			assert amount > 0
		except:
			print('Amount must be a positive integer.')
			continue
		m = 'Deposit {}'.format(amount).encode()
		s = sign(m, sk)
		receipt = '{}_{}'.format(m.hex(), b''.join(s).hex())
		print(receipt)
	elif choice == 'E':
		receipt = input('Receipt: ')
		m, s = receipt.split('_')
		m = bytes.fromhex(m)
		s = [bytes.fromhex(s[i:i+64]) for i in range(0, len(s), 64)]
		if not verify(m, s, pk):
			print('Invalid receipt.')
			continue
		if m.startswith(b'Deposit '):
			print('Successful deposit.')
		elif m == b'Give flag':
			print(flag)
	else:
		print('Thank you for patronage.')
		break
