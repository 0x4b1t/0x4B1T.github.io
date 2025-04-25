---
title: Bakery
order: 4
---

This was a web-based challenge featured in the KPMG Recruitment CTF 2023.

`Date : 22 Dec 2023 Friday`

Hey Hackers, I forgot to capture screenshots while i was solving the challenge but i will provide as much as possible context to create the whole scenario with words. <<


### Table of Content 

1. [Background](#background)
2. [Recon](#recon)
3. [Exploitation](#exploitation---preg_replace-bypass)
4. [Conclusion](#conclusion )

### Background 

KPMG team is expert in giving useless descriptions for the challenges but still according to the description : 

`This is KPMG Backery` 

### Recon

**Nmap**

By running Nmap against the server as expected there is no intersting port open just "80" and "443".

**Directory Busting - Gobuster**

Nothing interesting returned bu the gobuster only the /js directory having a single file with non-juicy information.

**Analysing the Application**

I Tried to create a diagram so that it will be easy to imagine the application x00

![visual](https://github.com/kris3c/kris3c.github.io/assets/128035061/879964d6-2aac-4255-afa4-d8afd4d1caed)


* There is a Clickable "Bakery" Button.
* A Search Box.
* An area where our searched query will be displayed.

**Bakery Button**

When we click on the button it will take us to a page where two lines of code is revealed 

```
$pattern = "/script/i";
$payload = preg_replace($pattern, '', $payload);
```

From the above code we can easily understand its a PHP code that is using the preg_replace function to replace the "Script" keyword blank space ' '.

Let's Try to Enter the Script keyword in the Search box 

Yaah Our understanding was accurate script is filtered.

### Exploitation - preg_replace bypass

As the application is filtering the "Script" keyword we will try to bypass it and execute the XSS attack.

In the Exposed code /i flag is used with the keyword that means application will filter the word in-case-sensitive in simple words making the word upper or lower will not work for us.

**Test case**

When I am entering any word concatenated with the "script" keyword application only filters the "script" keyword  and the other word remains the same : 

Example : scriptscri -> scri

I think you got the idea !!! YESS we can just create a long word having script concatenate with the half of the script itself what i mean to say is 

* script+scrip+script+t
* So when the application filters the word it will became ~~script~~scrip~~script~~t (script)
* After further analysing the application i saw that there is not even a single cookie in the application.
* so lets retrieve cookie using the DOM.

Payload : <scriptscripscriptt>alert(document.cookie)</scriptscripscriptt>

There is a cookie disclosing the path of a file and upon accessing the file we got the flag.

### Conclusion 

In this writeup we understood how we can bypass the PHP function preg_replace() and execute the XSS attack.   


