# SHA2017 Network Challenge: Vod Kanockers (100)

In this challenge, we are given a link to a site: vod.stillhackinganyway.nl

When we surf to the site, all we see is an image:
![Front page of the challenge](https://github.com/AttackZero/ctf_writeups/blob/master/sha_2017/network_100_vod_kanockers/images/first_page.png)

Let's look at the source of the page:
![Source of the front page](https://github.com/AttackZero/ctf_writeups/blob/master/sha_2017/network_100_vod_kanockers/images/first_page_source.png)

This looks interesting:
```html
    <!-- *Knock Knock* 88 156 983 1287 8743 5622 9123 -->
```

This appears to be a port knocking sequence.  Port knocking is a way to open ports on a firewall when the user tries to connect to a set of closed ports in a specific sequence.  The port knocking daemon is the software on the system that listens for the port knock sequence and opens the desired port on the firewall.  The daemon can be configured to leave the port open for a small amount of time to new connections and then close it.  After the pre-defined amount of time has elapsed, the port will be closed again. This could be useful if you only want to open your SSH port when the correct knock sequence is provided.  Otherwise, it would stay closed.  There are better ways to secure your SSH server, so I would not recommend port knocking.  I also would not recommend port knocking as the only means of securing access to a service on a machine.

Port knocking achieves "security" through obscurity.  The security lies in the implementation of the port knocking daemon and keeping the port knock sequence a secret.  Port knocking is vulnerable to replay and man-in-the-middle attacks. The sequence of ports to connect to is pre-determined, so if you can capture the sequence, you can play it again.

Now that we understand a bit more about port knocking, how do we "knock" on each port?  By making a connection to it.  We can use [nmap](https://nmap.org/) to make a connection:
```bash
nmap -Pn <host> --max-retries 0 -p <port to knock>
```
```-Pn``` tells nmap not to ping the box to check that it is up before trying to make the connection.  We are not going to specify a specific port scan type, so nmap will try a full connection.  We will also not let nmap retry, because we need to hit the ports in a specific sequence.

Since we have more than one port to knock on, let's write a little script to automate this.  Automating the port knock sequence is a good idea because timing is very important when port knocking.  If you take too long to complete the sequence, it may not work.

Here is the quick script (available [here](https://github.com/AttackZero/ctf_writeups/blob/master/sha_2017/network_100_vod_kanockers/code/knock.sh)]:
```bash
#!/bin/bash
# Usage: knock.sh <host> <knock sequence>

# The host is the first argument
HOST=$1

# Move the argument list to the left (now the first port to knock becomes the
# first argument)
shift

# For each port in the argument list, connect to it
for PORT in "$@"
do
	nmap -Pn $HOST --max-retries 0 -p $PORT
done
```

The script takes the host we want to connect to as the first argument, and then every argument after that is a port to knock on.

After the sequence is done, we need to figure out what to do next.  We do not know which port will be opened, so we should scan the box to see if any ports open up.  We can do this by running an nmap scan right after the knock sequence is done:
```bash
./knock.sh vod.stillhackinganyway.nl 88 156 983 1287 8743 5622 9123 && nmap -sS vod.stillhackinganyway.nl -T4
```
```
Starting Nmap 7.50 ( https://nmap.org ) at 2017-08-05 07:38 EDT
Nmap scan report for vod.stillhackinganyway.nl (34.249.81.124)
Host is up (0.14s latency).
rDNS record for 34.249.81.124: ec2-34-249-81-124.eu-west-1.compute.amazonaws.com

PORT   STATE  SERVICE
88/tcp closed kerberos-sec

Nmap done: 1 IP address (1 host up) scanned in 0.53 seconds

Starting Nmap 7.50 ( https://nmap.org ) at 2017-08-05 07:38 EDT
Nmap scan report for vod.stillhackinganyway.nl (34.249.81.124)
Host is up (0.14s latency).
rDNS record for 34.249.81.124: ec2-34-249-81-124.eu-west-1.compute.amazonaws.com

PORT    STATE  SERVICE
156/tcp closed sqlsrv

Nmap done: 1 IP address (1 host up) scanned in 0.34 seconds

Starting Nmap 7.50 ( https://nmap.org ) at 2017-08-05 07:38 EDT
Nmap scan report for vod.stillhackinganyway.nl (34.249.81.124)
Host is up (0.13s latency).
rDNS record for 34.249.81.124: ec2-34-249-81-124.eu-west-1.compute.amazonaws.com

PORT    STATE  SERVICE
983/tcp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.35 seconds

Starting Nmap 7.50 ( https://nmap.org ) at 2017-08-05 07:38 EDT
Nmap scan report for vod.stillhackinganyway.nl (34.249.81.124)
Host is up (0.14s latency).
rDNS record for 34.249.81.124: ec2-34-249-81-124.eu-west-1.compute.amazonaws.com

PORT     STATE  SERVICE
1287/tcp closed routematch

Nmap done: 1 IP address (1 host up) scanned in 0.54 seconds

Starting Nmap 7.50 ( https://nmap.org ) at 2017-08-05 07:38 EDT
Nmap scan report for vod.stillhackinganyway.nl (34.249.81.124)
Host is up (0.12s latency).
rDNS record for 34.249.81.124: ec2-34-249-81-124.eu-west-1.compute.amazonaws.com

PORT     STATE  SERVICE
8743/tcp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.35 seconds

Starting Nmap 7.50 ( https://nmap.org ) at 2017-08-05 07:38 EDT
Nmap scan report for vod.stillhackinganyway.nl (34.249.81.124)
Host is up (0.12s latency).
rDNS record for 34.249.81.124: ec2-34-249-81-124.eu-west-1.compute.amazonaws.com

PORT     STATE  SERVICE
5622/tcp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.36 seconds

Starting Nmap 7.50 ( https://nmap.org ) at 2017-08-05 07:38 EDT
Nmap scan report for vod.stillhackinganyway.nl (34.249.81.124)
Host is up (0.13s latency).
rDNS record for 34.249.81.124: ec2-34-249-81-124.eu-west-1.compute.amazonaws.com

PORT     STATE SERVICE
9123/tcp open  grcp

Nmap done: 1 IP address (1 host up) scanned in 0.34 seconds

Starting Nmap 7.50 ( https://nmap.org ) at 2017-08-05 07:38 EDT
Nmap scan report for vod.stillhackinganyway.nl (34.249.81.124)
Host is up (0.14s latency).
rDNS record for 34.249.81.124: ec2-34-249-81-124.eu-west-1.compute.amazonaws.com
Not shown: 997 filtered ports
PORT     STATE  SERVICE
80/tcp   open   http
88/tcp   closed kerberos-sec
1287/tcp closed routematch

Nmap done: 1 IP address (1 host up) scanned in 17.76 seconds
```
So no ports in the 1,000 common ports that nmap scans.  There was an interesting result in our knock sequence though:
```
Starting Nmap 7.50 ( https://nmap.org ) at 2017-08-05 07:38 EDT
Nmap scan report for vod.stillhackinganyway.nl (34.249.81.124)
Host is up (0.13s latency).
rDNS record for 34.249.81.124: ec2-34-249-81-124.eu-west-1.compute.amazonaws.com

PORT     STATE SERVICE
9123/tcp open  grcp
```

Was 9123 open before?   Let's see:

```
Nmap scan report for vod.stillhackinganyway.nl (34.249.81.124)
Host is up (0.13s latency).
rDNS record for 34.249.81.124: ec2-34-249-81-124.eu-west-1.compute.amazonaws.com

PORT     STATE    SERVICE
9123/tcp filtered grcp
```

Interesting.  So it looks like this is the port might be opened when the knock sequence is provided.  Let's try to connect to it right after the knock sequence is done using ```telnet```:

```bash
./knock.sh vod.stillhackinganyway.nl 88 156 983 1287 8743 5622 9123 && telnet vod.stillhackinganyway.nl 9123
```
```
...
<nmap output>
...
Trying 34.249.81.124...
Connected to vod.stillhackinganyway.nl.
Escape character is '^]'.
flag{6283a3856ce4766d88c475668837184b}
Connection closed by foreign host.
```

Looks like we found the flag!
