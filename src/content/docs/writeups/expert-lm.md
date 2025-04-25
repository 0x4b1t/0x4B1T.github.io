---
title : Such and eXpert ML model 
order : 2
---

This was a web-based challenge featured in the KPMG Recruitment CTF 2023.

`Date : 22 Dec 2023 Friday`

### Table of Content 

1. [Background](#Background)
2. [Recon](#Recon)
3. [Exploitation](#exploitation---xxe-attack)
4. [Conclusion](#conclusion)

### Background 

Description of the challenge is too straight forward but useless it says 


![WhatsApp Image 2023-12-22 at 1 14 54 PM](https://github.com/kris3c/kris3c.github.io/assets/128035061/d2cb63d3-b7a4-4915-ae3b-8b3e2684b2aa)

### Recon 

Initial Recon is must in CTF challenges jumping directly on the Application will give a strong headache as a gift.

**Nmap**

```
nmap -Pn kicyber-{}-challenge-1.chals.io --vv -sV  
```

Servers are really slow :/

![Screenshot from 2023-12-22 17-53-14](https://github.com/kris3c/kris3c.github.io/assets/128035061/a6171fcb-b4bb-42e5-bed1-46a9042eb19e)

Tried accessing port 23 that is telnet but no sucess.

After Opening the URL in the browser I just got pranked!

![Screenshot 2023-12-22 at 17-38-35 Prank](https://github.com/kris3c/kris3c.github.io/assets/128035061/b8f48ef3-0e18-41d6-afbe-5c119bbe139a)

But "Where's the Camera?"

**Directory Busting - Gobuster**

![Screenshot from 2023-12-22 18-00-14](https://github.com/kris3c/kris3c.github.io/assets/128035061/18f47a6f-6290-4fd3-94e0-098df83eb5db)

So there are mainly three endpoints with 200 Status code 

**/img - endpoint**

![Screenshot from 2023-12-22 18-03-29](https://github.com/kris3c/kris3c.github.io/assets/128035061/f370cd58-47e7-45aa-a099-e6b1a2ec84b0)

This indicates there is somewhere an endpoint through which we can register an account.

**robots.txt - endpoint**

![Screenshot from 2023-12-22 18-05-29](https://github.com/kris3c/kris3c.github.io/assets/128035061/4e9cbca7-397c-4830-bcbf-92d4a6758c53)

but wait! when scrolling downside of the robots.txt 

![Screenshot from 2023-12-22 18-08-09](https://github.com/kris3c/kris3c.github.io/assets/128035061/e2c4f49b-b666-44e2-abfb-eedd1449a555)

we got the endpoint 

### Exploitation - XXE Attack

When accessing the "/complexpage.html" endpoint we get a simple registration form

![Screenshot from 2023-12-22 18-14-15](https://github.com/kris3c/kris3c.github.io/assets/128035061/f2061b95-08eb-4aec-ba16-0cbba209a6f5)

Let's enter details and Intercept request and response in Burpsuite

**Request :**

![Screenshot from 2023-12-22 18-10-58](https://github.com/kris3c/kris3c.github.io/assets/128035061/2788caa4-e034-4e07-9d80-371129382605)


**Response :**

![Screenshot from 2023-12-22 18-16-48](https://github.com/kris3c/kris3c.github.io/assets/128035061/ff2f6291-67e4-4289-a604-8a690a2fd38a)


As it is XML version 1 and the value of "Email" is returned in the response let's try XXE Attack 

Those who don't know about the XXE Attack :

- XXE is a vulnerability present in the processing of the XML data. 
- In XML there are tags just like html but here the tags are user defined that represent some data that is also specified by the user.
- XXE stands for XML External Entity injection in which attacker uses external entity to retrieve data from the sever.
- External Entities are the tags who's values are stored in another location also in the files present on the server.

Now we just need to create a tag which will retrieve its values from a file present on the server and when we use that tag in our code content of that file will be returned.

```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```

using the xxe tag 

```
&xxe;
```

![Screenshot from 2023-12-22 18-28-07](https://github.com/kris3c/kris3c.github.io/assets/128035061/ee31e138-dc0f-4851-930c-b901c65ee90f)


so reading the flag present at "/etc/flag "

![Screenshot from 2023-12-22 18-29-16](https://github.com/kris3c/kris3c.github.io/assets/128035061/5f043db5-acac-4bda-92cf-8eb8a3eaf22e)


### Conclusion 

In this Writeup we have learned how we can exploit an XXE Vulnerabilty and retrive sensitive files from ther server filesystem.
