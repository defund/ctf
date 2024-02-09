import json
import keras
import keras.backend as K
import matplotlib.pyplot as plt
import numpy as np
import tensorflow as tf

tf.compat.v1.disable_eager_execution()

with open('./model.json') as f:
	 m = keras.models.model_from_json(f.read().replace('tanh', 'linear'))

with open('./weights.json') as f:
	layers = []
	for layer in json.load(f):
		layers.append(np.array(layer))
	m.set_weights(layers) 

# intially random vector
crafted_input = np.random.rand(64, 64)

# learning rate
lr = 0.2

m_in = m.input
m_out = m.output

# probability of predicting class 4
cost = m_out[0,1]

# calculate the gradient through our model
grad = K.gradients(cost, m_in)[0]

# function to calculate current cost and gradient
step = K.function([m_in, K.learning_phase()], [cost, grad])

# fetch gradient and apply
p, gradients = step([crafted_input, 0])
crafted_input += gradients * lr

plt.imshow(crafted_input, interpolation='none')
plt.show()
