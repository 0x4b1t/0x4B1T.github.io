---
title: Flag Hunters
Description : This is an "easy" level reverse engneering challenge from picoCTF 2025 competition.
---

<img width="1400" height="769" alt="picobanner" src="https://github.com/user-attachments/assets/7c6a6f39-c377-4326-9880-ffe3d64bfc74" />

`Date 15 Sep 2025`

This is an "easy" level reverse engneering challenge from picoCTF 2025 competition.

**Description**

Lyrics jump from verses to the refrain kind of like a subroutine call. There's a hidden refrain this program doesn't print by default. Can you get it to print it? There might be something in it for you.

### Table of Content

1.  [Basic Code Review](Basic-Code-Review)
2.  [Reader Function](#reader-function)
3.  [Flag](#flag)
4.  [Conclusion](#conclusion)

### Basic Code Review

Here is the provided python code -

```
import re
import time


# Read in flag from file
flag = open('flag.txt', 'r').read()

secret_intro = \
'''Pico warriors rising, puzzles laid bare,
Solving each challenge with precision and flair.
With unity and skill, flags we deliver,
The ether’s ours to conquer, '''\
+ flag + '\n'


song_flag_hunters = secret_intro +\
'''

[REFRAIN]
We’re flag hunters in the ether, lighting up the grid,
No puzzle too dark, no challenge too hid.
With every exploit we trigger, every byte we decrypt,
We’re chasing that victory, and we’ll never quit.
CROWD (Singalong here!);
RETURN

[VERSE1]
Command line wizards, we’re starting it right,
Spawning shells in the terminal, hacking all night.
Scripts and searches, grep through the void,
Every keystroke, we're a cypher's envoy.
Brute force the lock or craft that regex,
Flag on the horizon, what challenge is next?

REFRAIN;

Echoes in memory, packets in trace,
Digging through the remnants to uncover with haste.
Hex and headers, carving out clues,
Resurrect the hidden, it's forensics we choose.
Disk dumps and packet dumps, follow the trail,
Buried deep in the noise, but we will prevail.

REFRAIN;

Binary sorcerers, let’s tear it apart,
Disassemble the code to reveal the dark heart.
From opcode to logic, tracing each line,
Emulate and break it, this key will be mine.
Debugging the maze, and I see through the deceit,
Patch it up right, and watch the lock release.

REFRAIN;

Ciphertext tumbling, breaking the spin,
Feistel or AES, we’re destined to win.
Frequency, padding, primes on the run,
Vigenère, RSA, cracking them for fun.
Shift the letters, matrices fall,
Decrypt that flag and hear the ether call.

REFRAIN;

SQL injection, XSS flow,
Map the backend out, let the database show.
Inspecting each cookie, fiddler in the fight,
Capturing requests, push the payload just right.
HTML's secrets, backdoors unlocked,
In the world wide labyrinth, we’re never lost.

REFRAIN;

Stack's overflowing, breaking the chain,
ROP gadget wizardry, ride it to fame.
Heap spray in silence, memory's plight,
Race the condition, crash it just right.
Shellcode ready, smashing the frame,
Control the instruction, flags call my name.

REFRAIN;

END;
'''

MAX_LINES = 100

def reader(song, startLabel):
  lip = 0
  start = 0
  refrain = 0
  refrain_return = 0
  finished = False

  # Get list of lyric lines
  song_lines = song.splitlines()
  
  # Find startLabel, refrain and refrain return
  for i in range(0, len(song_lines)):
    if song_lines[i] == startLabel:
      start = i + 1
    elif song_lines[i] == '[REFRAIN]':
      refrain = i + 1
    elif song_lines[i] == 'RETURN':
      refrain_return = i

  # Print lyrics
  line_count = 0
  lip = start
  while not finished and line_count < MAX_LINES:
    line_count += 1
    for line in song_lines[lip].split(';'):
      if line == '' and song_lines[lip] != '':
        continue
      if line == 'REFRAIN':
        song_lines[refrain_return] = 'RETURN ' + str(lip + 1)
        lip = refrain
      elif re.match(r"CROWD.*", line):
        crowd = input('Crowd: ')
        song_lines[lip] = 'Crowd: ' + crowd
        lip += 1
      elif re.match(r"RETURN [0-9]+", line):
        lip = int(line.split()[1])
      elif line == 'END':
        finished = True
      else:
        print(line, flush=True)
        time.sleep(0.5)
        lip += 1

reader(song_flag_hunters, '[VERSE1]')
```

After reading the code line by line we can map this workflow

1.  Reading flag.txt and storing it in the `flag` variable.
2.  A multi line string is concatenated with content of flag and a new line character then the final output is stored in `secret_intro`.
3.  `song_flag_hunters` stores the content of `secret_intro` + the main lyrics of the song.
4.  Now there is the main function `reader`. There are some comments written with the body of the function for better understanding.

In the broder view we can say this function is first  spliting the multiline strings into seprate line and then putting each line as a element in a list named song_lines and then a loop starts which is searching for the start of the song which is marked as `[VERSE 1]` and then refrain and refrain_return. After getting index of all the three main components if starts printing the lyrics of the song from `[VERSE 1]` till the `[END]`.

In the Next Section we can get a deeper look in this function.

#### Reader Function 

Reader function  takes two arguments 

1. song - variable that stores whole lyrics of the song.
2. startLabel - String that marks the start of the song.

In this script we are providing the `song_flag_hunters` as the first argument and `[VERSE 1]` as second.

Now after entering in the function it takes the first argument and runs a `splitlines()` function on it which split the mutli lines  in seprate lines and append them in a list. Here the name of the list is `song_lines`.

Now we have a for loop -

```python
  for i in range(0, len(song_lines)):
    if song_lines[i] == startLabel:
      start = i + 1
    elif song_lines[i] == '[REFRAIN]':
      refrain = i + 1
    elif song_lines[i] == 'RETURN':
      refrain_return = i
```

This loop runs from 0 till the length of the list `song_lines` with each iteration it is matching the element with -

1. startLabel : Here it is `[VERSE 1]`
	- If matched then it will store the value of i + 1 in start variable which is initialised as 0.
2. [REFRAIN]
	  - If matched then it will store the value of i + 1 in refrain variable which is initialised as 0.
3. [RETURN]
	- If matched then it will store the value of i + 1 in refrain_return variable which is initialised as 0.

After the execution of this loop the value will be -

-	start = 12
- refrain = 5
- refrain_return = 10

Now we have while loop -

```python
# Print lyrics
  line_count = 0
  lip = start
  while not finished and line_count < MAX_LINES:
    line_count += 1
    for line in song_lines[lip].split(';'):
      if line == '' and song_lines[lip] != '':
        continue
      if line == 'REFRAIN':
        song_lines[refrain_return] = 'RETURN ' + str(lip + 1)
        lip = refrain
      elif re.match(r"CROWD.*", line):
        crowd = input('Crowd: ')
        song_lines[lip] = 'Crowd: ' + crowd
        lip += 1
      elif re.match(r"RETURN [0-9]+", line):
        lip = int(line.split()[1])
      elif line == 'END':
        finished = True
      else:
        print(line, flush=True)
        time.sleep(0.5)
        lip += 1
```

Condition for the while loop is varible `finished` value should be false (after not operation it will be turn to true) and line_count < MAX_LINES from the code we can see MAX_LINES is initialised to 100 and line_count is initialised to 0 so the max time the loop can run is set to 100.

Inside the while loop we have one for loop inside which we have a if else ladder so let's have a closer look.

```
for line in song_lines[lip].split(';'):
```

Here for loop is iterating over each element of the `song_list` and the index is stored in the variable `lip` which is initialised as the value stored in the `start` variable. further it split the line if it encounters the char `;`.

Heere is the functioning of the else-if ladder -

```python
 if line == '' and song_lines[lip] != '':
	continue
```

if the element is emprty then it just continue.

```
if line == 'REFRAIN':
        song_lines[refrain_return] = 'RETURN ' + str(lip + 1)
        lip = refrain
```

If the element is string `REFRAIN` then replace the value at `song_lines[refrain_return]` with string `RETURN` concatenated value of lip+1 type casted to string so the final value would be `'13'` and then the lip will be equals to refrain which is `5`.

After this the loop will start from the song_lines[5]

```
      elif re.match(r"CROWD.*", line):
        crowd = input('Crowd: ')
        song_lines[lip] = 'Crowd: ' + crowd
        lip += 1
```

Now this is the part of focus of the code.  It matches the regex `CROW . *`  and when macthed it will display a prompt `Crowd:` whose input will go into `crowd` variable which is then stored at the `song_lines[lip]` after concatenating with `Crowd:` then the lip variable is incremented. After this the loop wil start executing from the element that comes next to the string we input.

```
 elif re.match(r"RETURN [0-9]+", line):
        lip = int(line.split()[1])
```

This 2 lines also plays a major role it matches the expression `RETURN <any number>` for example `RETURN 9` then after match found it set the value of the lip to the value following `RETURN` here in the example it is 9.

Now if we look at the variable `song_flag_hunters` we can see the first part is the content of `secret_intro` which is 

```
'''Pico warriors rising, puzzles laid bare,
Solving each challenge with precision and flair.
With unity and skill, flags we deliver,
The ether’s ours to conquer, '''\
+ flag + '\n'
```

so to print the flag we need to make the iterate from the index 0. To achieve this we need to provide add the string `'RETURN 0'` which is done in this way - 

- When prompted `Crowd:` we can enter `data;RETURN 0`

After this  when the loop encounter this line of the lyrics it will split it into two `data` and `RETURN 0` and then when it read the `RETURN 0` it will set the lip to 0.

### Flag 

Now we can easily get the flag simply uisng `data;RETURN 0`


```bash
kris3c@0x4B1T-ubuntu:~$ nc verbal-sleep.picoctf.net 60056


Command line wizards, we’re starting it right,
Spawning shells in the terminal, hacking all night.
Scripts and searches, grep through the void,
Every keystroke, we're a cypher's envoy.
Brute force the lock or craft that regex,
Flag on the horizon, what challenge is next?

We’re flag hunters in the ether, lighting up the grid,
No puzzle too dark, no challenge too hid.
With every exploit we trigger, every byte we decrypt,
We’re chasing that victory, and we’ll never quit.
Crowd: data;RETURN 0

Echoes in memory, packets in trace,
Digging through the remnants to uncover with haste.
Hex and headers, carving out clues,
Resurrect the hidden, it's forensics we choose.
Disk dumps and packet dumps, follow the trail,
Buried deep in the noise, but we will prevail.

We’re flag hunters in the ether, lighting up the grid,
No puzzle too dark, no challenge too hid.
With every exploit we trigger, every byte we decrypt,
We’re chasing that victory, and we’ll never quit.
Crowd: data
Pico warriors rising, puzzles laid bare,
Solving each challenge with precision and flair.
With unity and skill, flags we deliver,
The ether’s ours to conquer, picoCTF{REDACATED}
```

### Conclusion 

This challenge cleverly disguised control flow manipulation within a song parser. By understanding how the reader() function interprets user input, we were able to inject RETURN 0 to redirect execution to the hidden flag at the start of the lyrics. A simple input exploit revealed the flag, demonstrating how even creative, non-standard code structures can be vulnerable to manipulation.
