---
title: "Friendship with Google: Dorks"
description: "Discover how to turn Google into a powerful ally for hacking reconnaissance using smart dorks and search tricks."
---

![1_yv9_F6EfnpkoQOSatgGZkQ](https://github.com/kris3c/kris3c.github.io/assets/128035061/de8d2569-2630-4de2-b5dc-b5ffd0e3bfc0)

`Date : 21 Jun 2024 Friday`

Taking help from our friend Google for recon or information gathering.

Hello amazing hacker, How you are doing i hope you are doing well.
In this article we will see why proffesional hackers always say google is your best friend.

### Table of Content 

1. [Introduction](#introduction)
2. [Why Google?](#why-google)
3. [Google Dorking](#google-dorking)
4. [Usefull Dorks you should know about](#usefull-dorks-you-should-knowabout)
5. [Refrence](#refrence)
6. [Closing words](#closing-words)

### Introduction

As we all know information gathering or recon is very important before actual attacking because during recon you may find many usefull information that are important pieces of puzzle that you need later to find a P1 vulnerability on the target.

### Why Google?

Google is a very powerfull and famous search engine that is used by nearly every person in this world who is holding a digital device. Google supports many filters or Operators that you can use to search about anything very effectively and retrive information that is not easily acessable.

### Google Dorking

Google dorking is also called "Google Hacking". It is a way of doing advance search using custom query that include diffrent search filter or operators called 'dork'.

### Usefull Dorks you should know about

site:eaxmple.com - To get results from specific sites
:- Use , for seprating diffrent strings (sequence of character)
inurl:admin- Searching for pages having specified string in URL.
intitle: - Search for pages having matching string in title like 'index of'.
ext - searching for files having certain extension.
filetype: - searching for certain type of file.
| (OR) - searching with condition. Get result from this site or from this site.
- (Minus) - Excluding results
link: - search for web pages that are linked with specific site.
* (Wildcard) - It takes position for character or set of characters.
" " - searching for pages having matching phrase.

### Examples of combination of operators

Finding subdomains
```bash
site:*.example.com
```
Finding usefull or vulnerable pages
```bash
site:example.com inurl:/app/kibana
```
Compnay resouces hosted by third party
```bash
site:s3.amazon.com example.com
```
Finding pages containing sensitive data
```bash
site:example.com "password,admin,keys,tokens"
```
Searching pages linked with target
```bash
link:*.example.com
```
This are some simple but useful example of google dorks to make the concept more clear. You can make your own dorks for gathering more info about target

### Refrence

You can find more useful dorks on : https://www.exploit-db.com/google-hacking-database

### Closing words

Don't forget to share this articles with your friends to spread knowledge in infosec community.

Thankyou, Happy Hunting :)
