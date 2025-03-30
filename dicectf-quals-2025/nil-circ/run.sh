#!/bin/sh

./server --circuit aes.txt --key $(cat key.txt)
