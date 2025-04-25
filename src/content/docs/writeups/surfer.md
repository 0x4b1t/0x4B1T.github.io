---
title : Surfer
order : 5
---


![1](https://github.com/kris3c/kris3c.github.io/assets/128035061/427081e8-1276-40a2-bbed-2644e0779d33)


This is a TryHackMe Web Challenge Room 

`Date : 21 Jun 2024 Friday`

### Table of Contents

- [Introduction](#introduction)
- [Understanding SSRF](#understanding-ssrf)
- [Commencement](#commencement)
  - [Mission Brief](#mission-brief)
- [Progressing Further](#progressing-further)
  - [Exploration of Content and Directory Structure](#exploration-of-content-and-directory-structure)
  - [Investigation of '/backup/chat.txt'](#investigation-of-backupchattxt)
  - [Authentication Attempt](#authentication-attempt)
  - [Navigation Through the Application](#navigation-through-the-application)
  - [Request Interception with Burp Suite](#request-interception-with-burp-suite)
  - [Exploitation and Flag Retrieval](#exploitation-and-flag-retrieval)
- [Closing Remarks](#closing-remarks)


### Introduction:

"Surfer" provides an opportunity to refine your SSRF (Server Side Request Forgery) attack skills.

Explore the room on TryHackMe: [Surfer Room](https://tryhackme.com/room/surfer)

### Understanding SSRF:

SSRF, an acronym for Server Side Request Forgery, represents a critical vulnerability that empowers attackers to manipulate web applications, thereby facilitating unintended connections to specific locations.

### Commencement

Our journey begins with the pursuit of valuable insights, with the room hinting at the existence of functionality designed for internal use.

#### Mission Brief

Uncovering Hidden Functionality
Overcoming Access Control Mechanisms

### Progressing Further

Our investigation proceeds with a meticulous Nmap scan of the web application. Employing a thorough approach with the '-T4' aggressive option, we focus on scanning the top 1024 ports. Our rationale for this choice is rooted in the belief that there may not be any noteworthy ports beyond this range.

```bash
nmap TargetIP -top-ports=1024 -T4
```
![2](https://github.com/kris3c/kris3c.github.io/assets/128035061/6f10e538-84b2-46e0-8f4d-6fab043ba698)

The results indicate that only two ports are active. With this information in hand, we continue to the next phase of our exploration.

#### Exploration of Content and Directory Structure

![3](https://github.com/kris3c/kris3c.github.io/assets/128035061/efa8a940-da3d-4b3f-b4a4-cbc97d81962e)

We opt for the DirBuster tool by OWASP, supplementing our efforts with a medium-sized wordlist located at '/usr/share/dirbuster/wordlists/'. Our objective is to systematically investigate text files, revealing two accessible files of significance:

![4](https://github.com/kris3c/kris3c.github.io/assets/128035061/1c9cce95-ed11-492c-adc1-1de58f14e63c)

**/changelog.txt**: This file houses a log documenting notable changes within the application.
**/robots.txt**: Contained within is a reference to a page, '/backup/chat.txt', which is flagged as unsuitable for crawling.

#### Investigation of '/backup/chat.txt'

![5](https://github.com/kris3c/kris3c.github.io/assets/128035061/394247b0-11ff-4a53-ae79-4cefead2bfa2)

Our attention turns to the contents of '/backup/chat.txt', which reveals an exchange of messages between the system administrator and the developer, Kate. Of particular note is a directive from Kate:

```bash Kate: Additionally, please remember to update your credentials. Avoid using your username as your password. ```

#### Authentication Attempt

Guided by Kate's advice, we proceed to authenticate with the provided credentials, aligning the username and password in accordance with her directive.

Successful Authentication Achieved

#### Navigation Through the Application

As we explore the application further, we encounter a notable feature – the 'Export PDF' option, a subject of prior discussion between Kate and the system administrator.

Moreover, we identify an internal page situated at '/internal/admin.php'. However, an attempt to access this page is met with a restriction, permitting solely local access (from '127.0.0.1').

![6](https://github.com/kris3c/kris3c.github.io/assets/128035061/5a0b93b3-277f-41b0-a405-61e444a56ad4)

#### Request Interception with Burp Suite

To progress, we employ Burp Suite to intercept the request responsible for generating PDFs. This request features a crucial parameter named 'url', specifying the URL of the PDF hosted on the same server. We forward this request to the repeater for in-depth analysis.

![7](https://github.com/kris3c/kris3c.github.io/assets/128035061/0810d031-d8ca-4c8a-9686-bf97570c1477)

The PDF report received informs us that it is generated for the same server that initiated the request, effectively pointing to "localhost."

![8](https://github.com/kris3c/kris3c.github.io/assets/128035061/a9ab33e9-bbf9-4109-8a75-29b3e037a64e)

**Operating Mechanism:**

User triggers the export PDF function.
The frontend initiates a POST request, including the URL, to the server.
The server forwards a request to the specified URL and subsequently receives and transmits the response to the frontend.
At this juncture, we contemplate the possibility of crafting a POST request capable of compelling the server to request a page available locally (on the same server).

#### Exploitation and Flag Retrieval

Implementing a strategic maneuver, we substitute '/server-info.php' with '/internal/admin.php'. This alteration effectively induces the server to initiate a request to '/internal/admin.php' within its local environment, culminating in the retrieval of the coveted flag within the server's response.

Objective Accomplished: The Flag is Secured

#### Closing Remarks

We trust that this walkthrough has equipped you with valuable insights and knowledge. Should you have any questions or seek further clarifications, we encourage you to utilize the comment section. We also invite you to share this knowledge within the information security community, and we look forward to your continued support.
