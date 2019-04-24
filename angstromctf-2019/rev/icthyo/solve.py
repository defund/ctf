from PIL import Image
image = Image.open('out.png')
pixels = list(image.getdata())
flag = [0 for _ in range(256)]
for i in range(256):
	row = pixels[i*256:(i+1)*256]
	for j in range(8):
		pixel = row[j*32]
		bits = [x & 1 for x in pixel]
		bit = bits[0] ^ bits[1] ^ bits[2]
		flag[i] ^= bit << j
flag = bytes(flag)
print(flag)