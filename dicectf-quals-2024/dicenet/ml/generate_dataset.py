import numpy as np
import os
from PIL import Image

def add_noise(flag):
	arr = flag + np.random.normal(scale=5, size=(64, 64))
	arr *= 255/260
	return Image.fromarray(arr.astype('uint8')).convert('L')

def random_image():
	arr = np.random.rand(64, 64) * 255
	return Image.fromarray(arr.astype('uint8')).convert('L')

os.makedirs('dataset/flag')
os.makedirs('dataset/notflag')

img = Image.open('flag.png').convert('L').resize((64, 64))
flag = np.array(img.getdata()).astype(np.float32).reshape((64, 64))
for i in range(5000):
	im = add_noise(flag)
	im.save(f'dataset/flag/{i}.png')

for i in range(5000):
	im = random_image()
	im.save(f'dataset/notflag/{i}.png')
