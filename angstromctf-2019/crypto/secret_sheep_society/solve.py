import base64

from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

from manager import Manager

session = {
	'admin': False,
	'handle': 'defund'
}

key = get_random_bytes(16)
manager = Manager(key)
token = manager.pack(session)

raw = base64.b64decode(token)
iv = raw[:16]
enc = raw[16:]
offset = strxor(b'{"admin": false,', b'{"admin": true ,')
forged = base64.b64encode(strxor(iv, offset) + enc)

assert manager.unpack(forged)['admin']