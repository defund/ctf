import binascii

from Crypto.Util.asn1 import DerSequence

import benaloh

flag = 'actf{deterministic_answers_not_guaranteed}'

question = 'Will this person solve the challenge? {}'.format(flag).encode()
template = '''\
Question: {}
It is certain'''

pk = benaloh.unpack('pk')
der = DerSequence([benaloh.encrypt(m, pk) for m in question])

out = template.format(binascii.hexlify(der.encode()).decode())
with open('eightball.txt', 'w') as f:
	f.write(out)