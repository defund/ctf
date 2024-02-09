import json
import shutil

def zeroize(x):
	if type(x) == list:
		return [zeroize(y) for y in x]
	else:
		return 0

with open('./model.json') as f:
	model = json.load(f)

del model['config']['layers'][0]

with open('../challenge/net/model.json', 'w') as f:
	json.dump(model, f)

shutil.copyfile('./weights.json', '../challenge/net/weights.json')

with open('./weights.json') as f:
	weights = json.load(f)

dummy_weights = zeroize(weights)

with open('../challenge/net/dummy_weights.json', 'w') as f:
	json.dump(dummy_weights, f)
