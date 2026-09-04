---
title: "Lab 3 - Multi-endpoint race conditions"
---

In this challenge we are tasked with purchasing an item `Lightweight L33t Leather Jacket`  at an unintended price by exploiting the race condition but what type of race condiiton we look at that.

## Table of Content 

1. [Initial Recon](#initial-recon)
2. [Exploitation](#exploitation)
3. [Conclusion](#conclusion)

## Initial Recon

First we have following credentials given so let's login with this :

```
wiener:peter
```


![cf8f34ca9a2ec5f9f58be41bc34e6bcd.png](/cf8f34ca9a2ec5f9f58be41bc34e6bcd.png)


After logging in we can see the targeted product and one more interesting product that is the gift card. 

First let's try to buy the gift card to experiment with the application.

![1452fc6edc611a46efa1be1a3f6a09c2.png](/1452fc6edc611a46efa1be1a3f6a09c2.png)

When we click on the Place order button following request is made : 

![27eca106b0840c9d62e6eb2b3d4cd131.png](/27eca106b0840c9d62e6eb2b3d4cd131.png)

![b9b61a276de67ac450e2aee8c328dc53.png](/b9b61a276de67ac450e2aee8c328dc53.png)

We can see we have brough the gift card successfully making our cart value `$90` now let's buy again the gift card this time capturing the both request the add to card and place order in the burpsuite.

![dca7eee57e60192c21714ed5433b156e.png](/dca7eee57e60192c21714ed5433b156e.png)
![304835d320e7cc3f1dd7772d721dc843.png](/304835d320e7cc3f1dd7772d721dc843.png)

For warm up request we will also send the request to `/` to repeater 

![71c413d56de35d8db44999ce115a2ea9.png](/71c413d56de35d8db44999ce115a2ea9.png)

Right Click on any tab and hover over Add tab to group and click `new tab group` -

![79abaf8d05dddaef285c321d3169a144.png](/79abaf8d05dddaef285c321d3169a144.png)

Create the group with all three request - 

![e7c16f7b21170a443b626450cecb54f9.png](/e7c16f7b21170a443b626450cecb54f9.png)

Now from the drop down near the send button choose send group in sequence single connection to test the response time.


![0f21fca9817ed12f4cd9394241f605c3.png](/0f21fca9817ed12f4cd9394241f605c3.png)

We can see the request for the homepage got response in `512 ms` but other got in `/cart 191ms` and `/cart/checkout 203ms`

So we can here clearly see that there is race without between checkout endpoint as on side of the serevr what it does is - 

```
/cart/checkout -> Check Cart Value -> check Credit available -> place order 
```

So what if we send request to add an expensive item after the check credit value just after the check cart value. It will check the cart value for the cheap amount put place order for our expensive item too.

for this purpose lets add a gift card to the cart :

![48122b4b91ea89d5281333a119eaa0fd.png](/48122b4b91ea89d5281333a119eaa0fd.png)

And then in the tabs we grouped changed the type to send the request in parallel instead of sequence.

![f1948d0173c157873482093bdef1ed66.png](/f1948d0173c157873482093bdef1ed66.png)

Whoop we have solved the challenge sucessfully!!

## Conclusion

The application is vulnerable to a race condition caused by a TOCTOU (Time-of-Check to Time-of-Use) flaw. By sending the cart modification and checkout requests in parallel, we were able to change the cart after the price check but before the order was placed, allowing us to purchase the Lightweight L33t Leather Jacket at an unintended price.
