Inside of flag/, there is a hidden vim swap file, .flag.txt.swp.
To recover flag.txt, use vim:

vim -r flag.txt

Alternatively, extract the lines in plaintext at the end of the swap file. The lines are separated by null chars and the line order is reversed.