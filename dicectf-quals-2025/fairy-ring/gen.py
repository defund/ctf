import os
import secrets
import shutil

from server import NAMES
from uov import uov_1p_pkc as uov

if __name__ == '__main__':
	uov.set_random(secrets.token_bytes)

	shutil.rmtree('keys')
	os.mkdir('keys')
	for name in NAMES:
		pk, _ = uov.keygen()
		with open(f'keys/{name}.pub', 'wb') as f:
			f.write(pk)
