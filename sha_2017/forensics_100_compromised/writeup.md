# SHA2017 Forensics Challenge: Compromised? (100)

The hint for this challenge is: We think our *system* got compromised, our hosting company uses some strange logtool. Are you able to *dig* into the logfile and find out if we are compromised?

A tgz file is provided which contains an scap file.  I have heard of pcap and pcapng, but never scap.  I did some Googling, and stumbled across a utility called [Sysdig](https://www.sysdig.org/).  I guess that is why the words system and dig were in italics in the challenge.  I have never used (or heard of) sysdig before, so I did some more Googling to find out how it works and what it does.

In short, sysdig is almost like Wireshark but for events happening on your system.  This could be any sort of event from reading memory to opening a file to opening a network connection.  I found this [great reference guide](https://github.com/draios/sysdig/wiki/Sysdig-User-Guide) that helped me analyze the provided scap file.

To start, I installed sysdig in my Kali VM (```apt-get install sysdig```), and started filtering out events.  Because there may be evidence of a compromise, we want to see if we can tell what commands were run.  We will run the following command:

```bash
sysdig -r FOR100.scap -p "%proc.cmdline" | sort | uniq
```

The ```-p``` flag tells sysdig to take the provided format string and print it for each event in the capture.  The format strings provided to sysdig work like [C format strings](http://en.cppreference.com/w/cpp/io/c/fprintf).  Fromt he reference guide above, I found that ```proc.cmdline``` will give us the executable and its arguments.  Since executing a program will involve many system calls, we do not want to print out the command line for each event.  We will pass the output to the ```sort``` command which will put the duplicate lines together.  We will then pass that out to the ```uniq``` command which will give us the unique lines.  Here is what the output of the command looks like:

```
00-header /etc/update-motd.d/00-header
10-help-text /etc/update-motd.d/10-help-text
90-updates-avai /etc/update-motd.d/90-updates-available
91-release-upgr /etc/update-motd.d/91-release-upgrade
97-overlayroot /etc/update-motd.d/97-overlayroot
98-fsck-at-rebo /etc/update-motd.d/98-fsck-at-reboot
98-reboot-requi /etc/update-motd.d/98-reboot-required
accounts-daemon 
acpid 
awk {print $1} /proc/uptime
bash -c chmod +x /tmp/\[crypto\]; /tmp/\[crypto\]
bash -c python /tmp/challenge.py cnKlXI1pPEbuc1Av3eh9vxEpIzUCvQsQLKxKGrlpa8PvdkhfU5yyt9pJw43X9Mqe
bash -c scp -t /tmp/
cat /var/lib/update-notifier/fsck-at-reboot
cat /var/lib/update-notifier/updates-available
chmod +x /tmp/[crypto]
cron -f
[crypto] 
cut -d  -f4
date -d now - 277.55 seconds +%s
date -d now - 286.21 seconds +%s
date -d now - 300.73 seconds +%s
date -d now - 361.22 seconds +%s
date -d now - 384.10 seconds +%s
date +%s
dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
dhclient -1 -v -pf /run/dhclient.enp0s3.pid -lf /var/lib/dhcp/dhclient.enp0s3.leases -I -df /var/lib/dhcp/dhclient6.enp0s3.leases enp0s3
egrep /bin/egrep overlayroot|/media/root-ro|/media/root-rw /proc/mounts
env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d
expr 1500799784 + 86400
gdbus 
gdbus --no-debug
gmain 
grep -E overlayroot|/media/root-ro|/media/root-rw /proc/mounts
in:imuxsock -n
iscsid 
ls 
lsb_release -Es /usr/bin/lsb_release -sd
<NA> 
polkitd --no-debug
python /tmp/challenge.py cnKlXI1pPEbuc1Av3eh9vxEpIzUCvQsQLKxKGrlpa8PvdkhfU5yyt9pJw43X9Mqe
release-upgrade -e /usr/lib/ubuntu-release-upgrader/release-upgrade-motd
rpcbind -f -w
rs:main -n
run-parts --lsbsysinit /etc/update-motd.d
scp -t /tmp/
screen -R test
sh 
sh -c /bin/sh
sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
snapd 
sort -r
sshd   
sshd    
sshd -D
sshd -D -R
stat -c %Y /var/lib/ubuntu-release-upgrader/release-upgrade-available
stat -c %Y /var/lib/update-notifier/fsck-at-reboot
sysdig -s 8192 -z -w /mnt/challenge.scap.gz
systemd 
systemd-journal 
systemd-logind 
systemd-timesyn 
systemd-udevd 
uname -m
uname -o
uname -r
update-motd-fsc /usr/lib/update-notifier/update-motd-fsck-at-reboot
update-motd-reb -e /usr/lib/update-notifier/update-motd-reboot-required
```

The line that got my attention was:
```bash
python /tmp/challenge.py cnKlXI1pPEbuc1Av3eh9vxEpIzUCvQsQLKxKGrlpa8PvdkhfU5yyt9pJw43X9Mqe
```

During execution, the python interpreter will load the python script into memory (probably using a read syscall).  We can see when challenge.py is read using sysdig filters:
```bash
sysdig -r FOR100.scap fd.name=/tmp/challenge.py and evt.type=read
```

```fd.name``` is the full path to the file descriptor we are interested in.  If we only had the script name, we could use ```fd.filename```.  We want to see when the file was read, so we will filter on read events using ```evt.type=read```.  Here is the output:

```
179009 06:28:59.160750068 0 python (1697) > read fd=3(<f>/tmp/challenge.py) size=178 
179010 06:28:59.160762914 0 python (1697) < read res=178 data=from Crypto.Cipher import AES.import base64.import sys.obj = AES.new('n0t_jus... 
179011 06:28:59.160765116 0 python (1697) > read fd=3(<f>/tmp/challenge.py) size=4096 
179012 06:28:59.160765844 0 python (1697) < read res=22 data=64decode(ciphertext)). 
179027 06:28:59.160780891 0 python (1697) > read fd=3(<f>/tmp/challenge.py) size=4096 
179028 06:28:59.160781860 0 python (1697) < read res=200 data=from Crypto.Cipher import AES.import base64.import sys.obj = AES.new('n0t_jus... 
179033 06:28:59.160968746 0 python (1697) > read fd=3(<f>/tmp/challenge.py) size=4096 
179034 06:28:59.160970507 0 python (1697) < read res=200 data=from Crypto.Cipher import AES.import base64.import sys.obj = AES.new('n0t_jus... 
179035 06:28:59.161006982 0 python (1697) > read fd=3(<f>/tmp/challenge.py) size=4096 
179036 06:28:59.161007705 0 python (1697) < read res=0 data= 
211549 06:29:21.996784541 0 python (1730) > read fd=3(<f>/tmp/challenge.py) size=178 
211550 06:29:21.996786107 0 python (1730) < read res=178 data=from Crypto.Cipher import AES.import base64.import sys.obj = AES.new('n0t_jus... 
211551 06:29:21.996787932 0 python (1730) > read fd=3(<f>/tmp/challenge.py) size=4096 
211552 06:29:21.996788416 0 python (1730) < read res=22 data=64decode(ciphertext)). 
211567 06:29:21.996802295 0 python (1730) > read fd=3(<f>/tmp/challenge.py) size=4096 
211568 06:29:21.996803215 0 python (1730) < read res=200 data=from Crypto.Cipher import AES.import base64.import sys.obj = AES.new('n0t_jus... 
211573 06:29:21.996986489 0 python (1730) > read fd=3(<f>/tmp/challenge.py) size=4096 
211574 06:29:21.996988124 0 python (1730) < read res=200 data=from Crypto.Cipher import AES.import base64.import sys.obj = AES.new('n0t_jus... 
211575 06:29:21.997023392 0 python (1730) > read fd=3(<f>/tmp/challenge.py) size=4096 
211576 06:29:21.997024166 0 python (1730) < read res=0 data=
```

Looks like the script gets read in, but we cannot see the full data.  We need to get sysdig to print the raw argument data to the read syscall:

```bash
sysdig -r FOR100.scap fd.name=/tmp/challenge.py and evt.type=read -p "%evt.rawarg.data"
```

```evt.rawarg.data``` isolates the data argument to the read syscall.  Let's see what the command gives us:

```python
...
from Crypto.Cipher import AES
import base64
import sys
obj = AES.new('n0t_just_t00ling', AES.MODE_CBC, '7215f7c61c2edd24')
ciphertext = sys.argv[1]
message = obj.decrypt(base64.b64decode(ciphertext))
...
```

So it looks like the script takes the ciphertext that is provided by the first argument on the command line to the script, base64 decodes it, then decrypts it using the parameters in line 4.  
I will add one line to the end to print the decrypted message.

```python
from Crypto.Cipher import AES
import base64
import sys
obj = AES.new('n0t_just_t00ling', AES.MODE_CBC, '7215f7c61c2edd24')
ciphertext = sys.argv[1]
message = obj.decrypt(base64.b64decode(ciphertext))
print(message)
```

The final script is available [here](https://github.com/AttackZero/ctf_writeups/blob/master/sha_2017/forensics_100_compromised/code/challenge_decrypt.py).  It requires the pycrypto library to be installed.  We will run the script with the string we found previously:

```bash
python challenge_decrypt.py cnKlXI1pPEbuc1Av3eh9vxEpIzUCvQsQLKxKGrlpa8PvdkhfU5yyt9pJw43X9Mqe
Congrats! flag{1da3207f50d82e95c6c0eb803cdc5daf}
```

And there is our flag.

# Conclusion
Sysdig looks like a neat tool.  This is one of the reasons I really like doing CTFs: I get exposure to tools I probably would never have heard of otherwise.
