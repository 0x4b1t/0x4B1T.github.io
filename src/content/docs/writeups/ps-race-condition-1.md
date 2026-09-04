---
title : "Lab 1 - Limit overrun race conditions"
---

The Application is Vulnerable to Race Condition and to complete the lab we need to buy the `Lightweight "l33t" Leather Jacket` at the lowest price.

`Date: 4 September 2026`

### Table of Content 

1. [Initial Recon](#initial-recon)
2. [Exploitation](#exploitation)
3. [Conclusion](#conclusion)

## Initial Recon

We have the following credentials given : 

```
wiener:peter
```

<img width="1225" height="470" alt="2fabd22d3964429e80b2be939044885d" src="https://github.com/user-attachments/assets/dcd3d669-8177-4a91-a21d-00fdb22fb6e2" />



After logging in with that account we can see we have total store credit `$50` so we need to manage to adjust the amount of the `Lightweight "l33t" Leather Jacket` under that strore credit.

<img width="1225" height="258" alt="917fa5803c6d43cb833e1ca58178feae" src="https://github.com/user-attachments/assets/18b7bc9d-68e2-48a4-bd63-52ac6bfd1b84" />


As the Headline says we can grab 20% discount using the discount code `PROMO20`.


### Exploitation 

Adding the product to the cart and applying the code - 


<img width="1225" height="688" alt="48bf3506c1574716bfe518c7bb564ada" src="https://github.com/user-attachments/assets/b66386c6-488b-4f92-80ab-890cb0786d4f" />

We can see we grabbed the discount but it is still not in our budget so what if `we send apply discount request more than one will it apply the coupon twice`  Let's see.


<img width="1595" height="860" alt="8ecd4c566f214ddf9d5324ef84ac8dde" src="https://github.com/user-attachments/assets/23e12d5f-addb-4ea7-a97e-0b56a890eeda" />


Send this POST request to repeater twice.


<img width="1595" height="860" alt="94ebc1d81eef4617acd4ed8cbeeea5a9" src="https://github.com/user-attachments/assets/4ca99478-1705-46ca-8b1a-1a39ff8889e2" />

Right Click on any tab and hover on `Add tab to group` then `new tab group` 


<img width="1595" height="860" alt="e500d13f9b224700997be1a58edf2078" src="https://github.com/user-attachments/assets/852d8bb3-5345-4a7b-bfbe-c10e25174d07" />


Select both the tabs and create the group 

<img width="609" height="658" alt="fb1ac25ee6f1419199c080d5aa74b8ac" src="https://github.com/user-attachments/assets/262efa12-7eb9-417c-be4c-12ab8ace0484" />

Click on the drop down button that is near send button and click on `send group in parallel` and then click `send group (parallel)`


<img width="1226" height="798" alt="6f3461a6b36740179ac2a2d9a2998072" src="https://github.com/user-attachments/assets/286ab7e8-8127-4abf-a783-ec690804d38e" />

From the proxy set interception off and go to the web page again :

<img width="1226" height="798" alt="09448a0dcdb945a9b5e64ca64fbca112" src="https://github.com/user-attachments/assets/487d0858-4c3c-41c5-90ab-289c16aae048" />

Here we can see coupon code is applied twice instead of once because :

Application recieved two request at once to apply the same coupon code and the code mechanism to check whether the used has used the coupon code identified in both the request cases the coupon code has not been used so it applied the coupon code in both cases as response causing race condition.

Now to complete the lab we need to send atleast 15-20 request in group to make the price fall under 50$ for that just send multiple request to repeater and make them in a group and send all request at once. Let's see 

<img width="1226" height="798" alt="30e24bf717ef416d9c056e3aa6cf5cbc" src="https://github.com/user-attachments/assets/d3be4704-0881-4532-affe-c73abff7721b" />


We can see we have managed to decrease the price under $50 and now can place the order :

<img width="1303" height="383" alt="2aacfdb1e6e84a84aa8ea988a606c8d2" src="https://github.com/user-attachments/assets/e9b79352-edef-4e05-b4be-a6c166f08615" />


Challenge Solved!!

## Conclusion

The lab was successfully solved by exploiting a race condition in the coupon redemption process. By sending multiple PROMO20 requests simultaneously, the application applied the discount multiple times, allowing us to bring the jacket's price below our $50 store credit and complete the purchase.
