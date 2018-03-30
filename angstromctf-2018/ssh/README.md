The object of this challenge is to recover an RSA private key. From `id_rsa.pub`, we can get values for `n` and `e`. While `id_rsa` is largely redacted, the remaining data codes for the lower bits of `p` and the upper bits of `q`.

From here, one can recover the private key in multiple ways; the most obvious is using Coppersmith's method on the upper bits of `q`. A good Sage script can be found [here](https://github.com/mimoo/RSA-and-LLL-attacks).

All that remains is sshing to the server. It is important to specify the private key file and the port:

```sh
ssh -i id_rsa ctf@web.angstromctf.com -p 3004
```

Once connected, the server prints the flag.