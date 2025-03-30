#!/usr/bin/env bash

cp -r challenge nil-circ
cp gen.py aes.txt flag_enc.txt nil-circ
tar -cvzf handout.tar.gz --exclude='.*' --exclude='target' nil-circ
rm -rf nil-circ
