
![Screenshot from 2025-06-19 15-47-04](https://github.com/user-attachments/assets/d8d3ff6c-51c9-455a-b00d-9c4baf974716)

`Date : 12 June 2025`

In this writeup we are going to solve the `beleaf` Reverse Engineering Crackme type challenge which was the part of CSAW 2019. 

This is a beginner level challenge and helpful for the people who are starting in Reverse engineering. 

# Table of Content

1. [Initial Analysis](#Initial-Analysis)
	1. [Checking the security](#checking-the-security)
2. [Reversing with Ghidra](#reversing-with-ghidra)
	1. [Cleaning the code](#cleaning-the-code)
	2. [Understanding the flow](#Understanding-the-flow)
3. [Closing Words](#closing-words)

## Initial Analysis 

```
file beleaf
```

`Output` :

```
beleaf: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6d305eed7c9bebbaa60b67403a6c6f2b36de3ca4, stripped
```

So it is a 64 bit binary which is stripped means debugging information has been removed from the compiled program.

### Checking the security 

**Pwntools** is a Python library designed primarily for **exploit development** and **binary analysis.** It provides a rich set of utilities that simplify low-level tasks.

Install :

```
pip3 install pwntools
```

```
pwn checksec ./beleaf
```


![Screenshot at 2025-06-12 13-50-29](https://github.com/user-attachments/assets/037bdc31-e63d-4b82-9666-c8130ee1a6dd)



`RELRO` : It is a security feature applied to ELF binaries that affects the **Global Offset Table (GOT)** — a table used to resolve addresses of dynamically linked functions like `printf`, `puts`, etc. The GOT is a common target in binary exploitation because function pointers stored there can potentially be overwritten to hijack control flow..

Types of RELRO: :

1. No RELRO : GOT is fully Writeable.
2. Partial RELRO : GOT is still writeable but few fields are marked as read only.
3. Full RELRO : GOT is read only.

Possible Attack : 

If the GOT is writable (No/Partial RELRO), an attacker can overwrite a function pointer in the GOT — for example, replacing the address of `printf` with the address of `system`. This means a later call to `printf("sh")` would actually execute `system("sh")`, giving the attacker shell access.

`Stack Canary` : It is the value pushed by the compiler onto the stack just before the return address to prevent the buffer overflow attack.

- If attacker modifies the return address then while returning it will check for the canary value if it is not found program will crash.

Layout :

```


|---------------------------| 
|  Saved Base Pointer (RBP) | ← Frame pointer from the caller
|---------------------------|
|       Stack Canary        | ← Protects the return address
|---------------------------|
|      Return Address       | ← Where the function will return to
|---------------------------| ← Higher memory address (top of stack)

```

In the layout you can clearly see to modify the return address we will have to modify the stack canary as well.


`NX` : No execute is the permission that defines whether we can execute the code from the stack or not.

If NX is disabled then we can overflow the buffer and inject shellcode and execute it directly from the stack through jump.

`PIE` : Position Independent Executable means the program will run on different memory addresses each time it runs or simply saying addresses are not predefined.


## Reversing with Ghidra 

Let's open the binary in ghidra and look at the main function. 

```
NOTE : As the binary is stripped so you have to look at each function from the  Symbol Tree.
```

![Screenshot at 2025-06-12 14-43-36](https://github.com/user-attachments/assets/2917138e-8c14-41c3-9ea7-dcf8ab651fd5)

### Cleaning the code 

The more clearer the code gets the more easy it becomes for us to reverse the binary. 

`sVar1` is of size_t to which `strlen(local_98)` has been assigned so let's rename it to `input_s_length`. 

`local_98` is a char array where our input will be stored as we can clearly see from the `scanf` function call so rename it to `input.

`in_FS_OFFSET` contains the base address of the thread local storage (Each thread has its own storage block).

`local_10`  stores the Stack Canary so simply rename to stack_canary.

local_b0 is just a loop counter so can be renamed to `i`.

Cleaned Code :

![Screenshot at 2025-06-12 15-11-05](https://github.com/user-attachments/assets/cb59148e-2bf2-406e-839f-04f22d851467)



### Understanding the Flow

First the program will take our input and store it in a variable `Input` then it checks it's length against the length stored in variable `Input_s_length` if the input has characters less than 33 it will exit the program so we have to enter a string having more than 33 characters.

![Screenshot at 2025-06-12 15-11-05](https://github.com/user-attachments/assets/89fabe3f-fe23-4d2a-aca6-1df7080e7d29)


If the string has more than 33 characters it will move to `for` loop which runs length of input string times.

With each run the loop call a `FUN_001007fa` function and converts the char at the specified index into 4 byte integer and passing it as the parameter of the function.


![Screenshot at 2025-06-12 15-21-29](https://github.com/user-attachments/assets/30ebba35-1087-466b-8b82-812cf112c3e5)


As you can in the above snapshot the function is asking for a char argument and we are passing int so it will convert the passed parameter to `char` lol.

Now let's give a detailed look to the function.

what this function doing is it is converting the argument char to int and performing a check with the value stored at `DAT_00301020` (converting that value to int too) which we can see by double clicking on it.

![Screenshot at 2025-06-12 15-25-19](https://github.com/user-attachments/assets/ebb0de86-09bd-4530-9f2b-b29d8f68d49b)


Looks like a table of values so let's rename the function to `ascii_table` .

If the index is not negative and the parameter value is not equal to the value stored in the table the check will be passed and it enters the loop and using the passed value against two conditions :

1. Input Char's associated int value is less than the int value associated to the parameter char value stored  at `DAT_00301020`. if yes then the `i` will be equals to `i * 2 + 1`
2.  Input Char's associated int value is greater than the int value associated to the char value stored  at `DAT_00301020`. if yes then the `i` will be equals to `(i + 1) * 2`

At last this function will return the value of `i` (Index) to the caller. 

which checks the returned value against the value stored at `DAT_003014e0` (Rename it to Index_table) if the value is not equal it will print `Incorrect!` and exit and if it matches then the loop will run for the next input char.

When all the chars in the input string pass the condition it will print correct and the challenge will be solved.

Now in simple words we can say that there are two lookup tables the first one is index_table which contains the index value which is used as a offset to lookup in the another table ascii_table for the correct character. 

**index_table:** 

![Screenshot from 2025-06-18 22-48-39](https://github.com/user-attachments/assets/5e66194c-1abf-4b6d-9ab7-857963c2430a)


First value of the `index_table` is `01h` means the index of the first character is `1` lets see in the `ascii_table` what value is at index `1`.

![Screenshot from 2025-06-18 22-52-44](https://github.com/user-attachments/assets/112aa66f-fd68-45e5-a07e-29e9f52619c0)

we can see the first correct character is `f`.

Now we can repeat the same process and get the whole correct string as :

```
flag{we_beleaf_in_your_re_future}
```

## Closing Words

Thanks for going through this writeup! I hope it helps you get started with reverse engineering challenges. Keep practicing, stay curious, and enjoy the journey. Don’t forget to share this with your friends and fellow hackers — let’s grow the community together!
