import binascii
import socket
import time

from Crypto.Util.asn1 import DerSequence

import benaloh

class Netcat:
	def __init__(self, ip, port):
		self.request = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.request.connect((ip, port))
	def read(self, until=b'\n'):
		out = b''
		while not out.endswith(until):
			out += self.request.recv(1)
		return out[:-len(until)]
	def write(self, string, newline=True):
		self.request.send(string)
		if newline:
			self.request.send(b'\n')
	def close(self):
		self.request.close()

nc = Netcat('54.159.113.26', 19000)

def query(c):
	start = time.time()
	der = DerSequence([c]*8)
	nc.write(binascii.hexlify(der.encode()))
	nc.read()
	return time.time() - start

pk = benaloh.unpack('pk')
n, y = pk
decrement = benaloh.encrypt(256, pk)

der = DerSequence()
der.decode(binascii.unhexlify(open('eightball.txt').readline()[10:-1]))

valid = list(range(32, 127))

for c in der[:1]:
	deltas = []
	for i in range(128):
		if i in valid:
			deltas.append(query(c))
			print(i)
		c = (c*decrement) % n
	steps = [deltas[i+1]-deltas[i] for i in range(len(deltas)-1)]
	m = valid[steps.index(max(steps))]
	for i in range(len(steps)):
		print('{}: {}'.format(chr(valid[i]), steps[i]))
	print(m)
