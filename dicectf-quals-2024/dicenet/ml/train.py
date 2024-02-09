import json
import numpy as np
import tensorflow as tf

def normalize_img(image, label):
	return tf.cast(image, tf.float32) / 255, label

ds_train, ds_test = tf.keras.utils.image_dataset_from_directory(
	'./dataset',
	color_mode='grayscale',
	image_size=(64, 64),
	seed=1337,
	validation_split=0.2,
	subset='both',
)

ds_train = ds_train.map(normalize_img)
ds_train = ds_train.prefetch(tf.data.AUTOTUNE)

ds_test = ds_test.map(normalize_img)
ds_test = ds_test.prefetch(tf.data.AUTOTUNE)

model = tf.keras.models.Sequential([
	tf.keras.layers.Flatten(input_shape=(64, 64)),
	tf.keras.layers.Dense(32, activation='tanh'),
	tf.keras.layers.Dense(32, activation='tanh'),
	tf.keras.layers.Dense(2),
])

model.summary()

model.compile(
	optimizer=tf.keras.optimizers.Adam(0.001),
	loss=tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True),
	metrics=[tf.keras.metrics.SparseCategoricalAccuracy()],
)

model.fit(
	ds_train,
	epochs=16,
	validation_data=ds_test,
)

config = model.to_json()
with open('model.json', 'w') as f:
	f.write(config)

weights = model.get_weights()
with open('weights.json', 'w') as f:
	json.dump([(x*255).astype(np.int16).tolist() for x in weights], f)
