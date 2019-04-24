import cairo
import zlib

stream = open('paper_cut.pdf','rb').read()
stream = stream[stream.find(b'stream')+7:]
vector = zlib.decompressobj().decompress(stream)
vector = vector[vector.rfind(b'sc')+3:vector.rfind(b'f')+1]
vector = vector.decode().replace('\n', ' ').split(' ')

width, height = 1024, 1024
surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, width, height)
context = cairo.Context(surface)
context.scale(width, height)
context.set_line_width(0.001)

commands = {
	'm': context.move_to,
	'c': context.curve_to,
	'l': context.line_to,
	'f': context.fill
}

params = []
for item in vector:
	if item in commands:
		commands[item](*params)
		params = []
		continue
	try:
		value = float(item)
	except:
		continue
	if len(params) % 2 == 0:
		params.append((value-190)/100)
	else:
		params.append(1-(value-500)/100)

context.stroke()
surface.write_to_png('signature.png')