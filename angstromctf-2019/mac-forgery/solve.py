from cbc_mac import CBC_MAC

from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes
from Crypto.Util.strxor import strxor

m = b'''\
If you provide a message (besides this one) with
a valid message authentication code, I will give
you the flag.'''

key = get_random_bytes(16)
cbc_mac = CBC_MAC(key)
iv, t = cbc_mac.generate(m)
l = len(pad(m, 16)) / 16

m_forged = pad(m, 16)+strxor(strxor(iv, long_to_bytes(l, 16)), t)+m
iv_forged = strxor(strxor(iv, long_to_bytes(l, 16)), long_to_bytes(2*l+1, 16))
t_forged = t
assert cbc_mac.verify(m_forged, iv_forged, t_forged)