#!/usr/bin/env bash

mkdir fairy-ring
cp -r server.py uov.py uov_trapdoor.py keys fairy-ring
tar -cvzf handout.tar.gz --exclude='.*' --exclude='target' fairy-ring
rm -rf fairy-ring
