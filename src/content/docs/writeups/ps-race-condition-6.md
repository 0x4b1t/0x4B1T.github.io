---
title: "Lab 6 - Exploiting time-sensitive vulnerabilities"
---

In this challenge we are not going to exploit race condition but broken forget password logic to reset the password of the user `carlos` then login as `carlos` and delete the user `carlos`.

`Date: 4 September 2026`

## Table of Content 
1. [Initial Recon](#initial-recon)
2. [Exploitation](#exploitation)
3. [Conclusion](#conclusion)

## Initial Recon 

When we visit the login page we are presented with this :

![581c69d177b4fbb8901accbcab2fe5c7.png](/581c69d177b4fbb8901accbcab2fe5c7.png)

![b0693f22fb74f78f393108df2bc501e1.png](/b0693f22fb74f78f393108df2bc501e1.png)

Forgot Password ask us for username or email let's normally enter our username `wiener` and intercept the request in burp.

It send the password reset link to our registered mail id.

```
https://0a5200e304317ef7808ad0db007a00cf.web-security-academy.net/forgot-password?user=wiener&token=f16df8d148aea36e4c88ce58273ce4909dd30d62
```

This is the link we got to reset the password having a field token 

Let's try to send the password request link two times using groups in repeater.

> But make sure both the request have different session token and csrf token

To get this we can send the forgot password request third time to repeater and then change the method to get and endpoint to `/forgot-password` removing the cookie : 

![027151d95f23dba933358ed521c28bc4.png](/027151d95f23dba933358ed521c28bc4.png)

Now sending both the request in parallel 

![1f5309a63136044412a9d826112e2a80.png](/1f5309a63136044412a9d826112e2a80.png)

Visiting the email client : 

![abf5c6792393b5d7f00de5e8aad9f3f6.png](/abf5c6792393b5d7f00de5e8aad9f3f6.png)

We can see we recieved two password reset link with same token because the response time for both request were : 

![Screenshot From 2026-09-03 21-38-20.png](/Screenshot%20From%202026-09-03%2021-38-20.png)

## Exploitation 

After the initial recon phase exploitation part is pretty straight forward. 

We will again send two request one for `wiener` and one for `carlos` both the request will be sent in parallel so getting same timestamp so the token will be.

![e4873f20fa02555ab88c3fb8f8cfc973.png](/e4873f20fa02555ab88c3fb8f8cfc973.png)

Copy the link and change username to `carlos` :

![690acdd4bebbbe880b954295300b00a1.png](/690acdd4bebbbe880b954295300b00a1.png)

We can reset the password now.

![89b4118972fa8567395b13255edf5da5.png](/89b4118972fa8567395b13255edf5da5.png)

As carlos we can complete the task. 

![05dbc66a474d9191a461970a9e77b760.png](/05dbc66a474d9191a461970a9e77b760.png)

YAA!! Solved the challenge

## Conclusion

The challenge was successfully solved by exploiting a broken password-reset logic where reset tokens were generated based on the request timestamp. By sending password-reset requests for wiener and carlos simultaneously, we obtained the same token and used it to reset carlos's password. We then logged in as carlos and deleted the account.
