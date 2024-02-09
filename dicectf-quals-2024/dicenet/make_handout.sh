#!/usr/bin/env bash

cp -r challenge dicenet
tar -cvzf handout.tar.gz --exclude='.*' --exclude='weights.json' dicenet
rm -rf dicenet