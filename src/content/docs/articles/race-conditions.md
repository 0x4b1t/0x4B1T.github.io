---
title: "Race Conditions - PortSwigger"
---

In this article, we will cover the topic of Race Conditions, including both the theory and practical lab exercises. The original theory and lab material can be found on the [PortSwigger - Race Conditions](https://portswigger.net/web-security/race-conditions)

## Table of Contents

1. [Limit Overrun Race Conditions](#limit-overrun-race-conditions)
2. [Detecting and Exploiting Limit Overrun Race Conditions with Turbo Intruder](#detecting-and-exploiting-limit-overrun-race-conditions-with-turbo-intruder)
3. [Hidden Multi-Step Sequences](#hidden-multi-step-sequences)
4. [Methodology](#methodology)
5. [Multi-Endpoint Race Condition](#multi-endpoint-race-condition)
6. [Deal with Delay](#deal-with-delay)
7. [Single Endpoint Race Condition](#single-endpoint-race-condition)
8. [Session-Based Locking Mechanisms](#session-based-locking-mechanisms)
9. [Partial Construction Race Conditions](#partial-construction-race-conditions)
10. [Time-Sensitive Attacks](#time-sensitive-attacks)

Race condiiton is a type of vulnerability that occurs when two concurrent request are processed by the application at the same causing collision which result in unintended behaviour of the application which can be exploited by the attacker.

Time window in which the race condition occurs is called `race window`.

## Limit Overrun Race Conditions

Problem : We can use a single discount code more than once.

Instead of sending a single request we send two request concurrently so a race window occurs and discount applies two times.

Limit Overrun are subtype of so called "time-of-check to time-of-use" flaws

Time of check -> Whether the code is used or not
Time of use -> using the code

Gap between both can cause a `race window`

[Lab 1 - Limit overrun race conditions](https://0x4b1t.github.io/writeups/ps-race-condition-1/)


## Detecting and exploiting limit overrun race conditions with Turbo Intruder

Turbo Intruder is a Burpsuite extension that can be used for the purpose of exploiting one packet race condition flaw. 

There are some script that are already available to exploit different types of flaw which includes this flaw too.

[Lab 2 - Bypassing rate limits via race conditions](https://0x4b1t.github.io/writeups/ps-race-condition-2/)


## Hidden multi-step sequences

There are some request in the web application that can seens to be single step but in background they are multi step known as `sub state`.

In this case we can send two parallel request to the application bypassing some mid sub states.

Example of sub-states:

```
POST /forgot-password
        │
        ▼
┌─────────────────────┐
│ Find user           │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Generate token      │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Save token          │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Send email          │
└─────────────────────┘
```

## Methodology 

There is a three step methodology for hidden multi step sequence : 

1. Predict : Identify security-critical endpoints and determine whether multiple requests could interact with the same underlying state or record.
2. Probe : Establish the endpoint's normal behavior, then send potentially colliding requests in parallel and look for unexpected differences in responses or application behavior.
3. Prove : Reduce the requests to the minimum required set, reproduce the behavior consistently, and demonstrate the security impact.

Example : 

Suppose we have a login like - 

/Login -> MFA -> Login Sucessfull

In code : 

```python
session['userid'] = user.userid

if user.mfa_enabled:
    session['enforce_mfa'] = True
```
 
we have a endpoint `/admin` so if we try to do - 

/login -> MFA -> logged in -> /admin -> it will fail.

but we can see there is a race window between login and MFA so what if we send request in parallel to login and /admin

```
/login ---
         | -> GET /admin (user id: victim) MFA not enforced
/admin ---
```

## Multi Endpoint Race Condition 

Instead of race conditioning the same endpoint we can send parallel request to different endpoints.

We can understand with an example of shopping application.

Suppose there are two request :

```
POST /makePayment
POST /addToCart
```

The normal Workflow is - 

```
/addToCart
     ↓
Basket = pending
     ↓
/makePayment
     ↓
Payment validated
     ↓
Basket = confirmed
```

`/makePayment` might internally take some time which can open a race window allowing us to send request to another endpoint in that window.

```
              /makePayment
                   │
                   ▼
            Payment validated
                   │
                   │
                   │ ← RACE WINDOW
                   │
                   ├──────────────┐
                   │              │
                   │         /addToCart
                   │              │
                   │              ▼
                   │       Add expensive item
                   │
                   ▼
            Basket confirmed
```

But there might be delay in the request execution that can make our attack fail.

Types of Delay :

1. Network Latency : Time required to travel through the network.
2. Network Jitter : Req 1 > 80ms , req2 > 85ms (variation in delay)
3. Internal Endpoint latency : In how much time the serevr processed the request /addtocart > 20ms , /makePayment > 500ms

## Deal with Delay 

1. To deal with this delay we can do `Connection Warming`
> Instead of sending the actual request we can send the dummy request to test the delay first or to avoid the delay in our race request.
>we can simply understand it as the server need to setup the connection in the initial request so if send our race condition request in that step it will make our attack fail because of latency so to avoid this delay we use a simple reuqest to anything endpoint like homepage.


2. Make the server slow or increase resources usage
> By sending the dummy request using turbo intruder.

[Lab 3 - Multi-endpoint race conditions](https://0x4b1t.github.io/writeups/ps-race-condition-3/)

## Single Endpoint Race Condition 

To better understand this kind of race conditon we can take an example of an application's password reset functionality.

Endpoints : `/reset-user`  and `/reset-token`

Suppose we sent request for our case - 

```
request 1
    |	
/reset-user = hacker
                       --> Race Window -> Request 2
											 |
										/reset-user = victim
										/reset-token = 989
/reset-token = 123
```

In the final state of the application the reset token will be `123` and reset user will be `vicitm`.

[Lab 4 - Single-endpoint race conditions](https://0x4b1t.github.io/writeups/ps-race-condition-4/)


## Session-based locking mechanisms

In some application there is a mechanism installed that locks the request processing based on session. 

so race condition will work only when we send requests in two different session other wise it will lock send the request one by one instead of parallel.

## Partial construction race conditions

In this kind of race conditon some partial construction of some entity takes place that causes the race window to open and can be exploited by the attacker.

Example :

```
Request to create an user
			|
	  User : Victim
			|             -> Race Condition: In this window the API key for
			|				     the user victim is NIL so
			|				     we can access thier account using the API key null.
      API Key : NIL
```

We can do this with password instead of API key but the passwords are hashed so we need to know the hashed version of null.

[Lab 5 - Partial construction race conditions](https://0x4b1t.github.io/writeups/ps-race-condition-5/)

## Time-sensitive attacks

In this kind of attack some special logic in the application is required to create a situation similar to race condition to exploit the behaviour.

For example : Application using timestamp instead of cryptographic hash to generate the token for password reset in this case what is possible is we can send two request in parallel so that both the request gets same time stamp.

[Lab 6 - Exploiting time-sensitive vulnerabilities](https://0x4b1t.github.io/writeups/ps-race-condition-6/)

