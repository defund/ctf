#!/usr/local/bin/python

import secrets
from Crypto.Util.strxor import strxor

from uov import uov_1p_pkc as uov
import uov_trapdoor
uov.set_random(secrets.token_bytes)

NAMES = ['oberon', 'titania', 'puck', 'gloriana', 'aibell', 'sebile']
MESSAGE = b'shrooms'

class Ring:
    def __init__(self, pks):
        self.pks = pks

    # sk should be the secret key corresponding to public key pks[idx]
    def sign(self, msg, sk, idx):
        xs = []
        t = uov.shake256(msg, uov.m_sz)
        for i, pk in enumerate(self.pks):
            if i != idx:
                x = secrets.token_bytes(uov.n_sz)
                xs.append(x)
                t = strxor(t, uov.pubmap(x, pk))
            else:
                xs.append(None)
        xs[idx] = uov_trapdoor.sample(uov, t, sk)
        return b''.join(xs)

    def verify(self, sig, msg):
        assert len(sig) == len(self.pks) * uov.n_sz, 'invalid signature'
        xs = [sig[i:i + uov.n_sz] for i in range(0, len(sig), uov.n_sz)]
        t = bytes(uov.m_sz)
        for x, pk in zip(xs, self.pks):
            t = strxor(t, uov.pubmap(x, pk))
        assert t == uov.shake256(msg, uov.m_sz), 'invalid signature'

if __name__ == '__main__':
    with open('flag.txt') as f:
        flag = f.read().strip()

    directory = {}
    for name in NAMES:
        with open(f'keys/{name}.pub', 'rb') as f:
            directory[name] = uov.expand_pk(f.read())

    print('=== FAIRIES ===')
    for name in NAMES:
        print(f'- {name}')
    print('===============')

    ring_size = int(input('ring size: '))
    assert 1 <= ring_size <= len(NAMES), 'invalid ring size'

    pks = []
    for i in range(ring_size):
        name = input(f'name {i + 1}: ')
        assert name in NAMES, f'not in directory'
        pks.append(directory[name])

    sig = bytes.fromhex(input('ring signature (hex): '))

    ring = Ring(pks)
    ring.verify(sig, MESSAGE)
    print(flag)
