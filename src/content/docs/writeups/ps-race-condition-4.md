---
title: "Lab 4 - Single-endpoint race conditions"
---

In this lab we are tasked with exploiting race condition to gain access to `carlos@ginandjuice.shop` email and accept the invitiation to become the admin user and delete the user account `carlos`.

## Table of Content 

1. [Initial Recon](#initial-recon)
2. [Exploitation](#exploitation)
3. [Conclusion](#conclusion)

## Initial Recon
First let's login with the given creds :

```
wiener:peter
```

![70f7985e2595a9b0471def979c579122.png](/70f7985e2595a9b0471def979c579122.png)

We also have an access to the email client as we can see - 

![af0a8552f774aa23dc490ef1922a8fa7.png](/af0a8552f774aa23dc490ef1922a8fa7.png)

Let's try to change the email to `carlos@ginandjuice.shop` normally 

![9f25d2c851ff241399f577676ae904bf.png](/9f25d2c851ff241399f577676ae904bf.png)

Here we can see it is sending an confirmation mail to the mail id `carlos@ginandjuice.shop normally` so what we have to do is somehow manage to get the confirmation link to out mail id for the `carlos@ginandjuice.shop normally`.

To get more better view of the email let's try again with our own email - ` wiener@exploit-0a55002f03f1e6c480a42f0d01dd0026.exploit-server.net`

![Screenshot From 2026-09-03 17-08-37.png](/Screenshot%20From%202026-09-03%2017-08-37.png)

![60b69f711496acfeb0224d75a5a05b60.png](/60b69f711496acfeb0224d75a5a05b60.png)

This is the email we received from the application. 

After getting the basic mind map we can move to exploitation.

## Exploitation 

Intercept the email chage request for both `carlos` and `wiener` in burpsuite and send it to repeater and for warmup request send the request to homepage too.

![9d091b04998195ca0ce9654f07668322.png](/9d091b04998195ca0ce9654f07668322.png)

Group all three request and send choose to send the request as in parallel from drop down near send button.

Send the reqquest and check the email client : 

![49744b434f22740efe2f21c37f1f5d44.png](/49744b434f22740efe2f21c37f1f5d44.png)

We have recieved the reequest to change the email to carlos. If it does not work in first go try multiple times.

![f3818b75922182eec8c29c546ffaca37.png](/f3818b75922182eec8c29c546ffaca37.png)

Our email has been succesfully changed now we can complete the task by deleting the user `carlos` from admin panel.

![01e2caad04c51ee7360272f3a1d17c70.png](/01e2caad04c51ee7360272f3a1d17c70.png)


Wonderful! We have solved the lab successfully.

## Why it worked 

We are sending two request in parallel 

```
		Request 1
			|
/my-account/change-email
			|	     ->	email to change : wiener@exploit-0a55002f03f1e6c480a42f0d01dd0026.exploit-server.net
			|    							-> Request 2
			|									  |
			|								/my-account/change-email
																	     	  |
                                                            email to change:carlos@ginandjuice.shop
			|
send confirmation mail to mail
specified in the body : wiener@exploit-0a55002f03f1e6c480a42f0d01dd0026.exploit-server.net

```

## Conclusion 

The lab was successfully exploited by abusing a race condition in the email-change functionality. By sending two email-change requests in parallel, we were able to manipulate the application's timing so that the confirmation email for `carlos@ginandjuice.shop` was sent to our controlled email address. We then used the confirmation link to change the account email and gain access to the admin panel, allowing us to delete the carlos user account.
