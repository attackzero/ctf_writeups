# SHA2017 Web Challenge: Bon Appetit (100)

This challenge has us look at a website to assess it for vulnerabilities.  The page we get a link to is: http://bonappetit.stillhackinganyway.nl/

After poking around the site, the URL starts to look interesting, and we see pages like http://bonappetit.stillhackinganyway.nl/?page=home

Sometimes, when sites call pages this way, they may be vulnerable to [local file inclusion / LFI](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/).  Essentially, LFI is a vulnerability that allows an attacker to include files on a webpage that reside on the file system of the server.

On the backend, the URL we saw may have code in it like this:
```php
$page = $_GET['page']
include($page . '.php');
```

When we surf to http://bonappetit.stillhackinganyway.nl/?page=home, the value of $page is home, and home.php will be included (loaded).

Very simple LFI vulnerabilities can be exploited by using a directory traversal. Something like:

http://bonappetit.stillhackinganyway.nl/?page=../../../etc/passwd

Unfortunately, for us it is not that simple.  However, there is another trick we can use: PHP filters.

## PHP Filters
PHP filters allow the application to validate or sanitize data before using it.  We can specify them using ```php://filter```.  It only has one required argument (resource).  If we do not specify any additional actions, the file will be read in.  We can test to see if the server is vulnerable with something like this:
```http://bonappetit.stillhackinganyway.nl/?page=php://filter/resource=/etc/passwd```

![PHP Filter Test](https://github.com/AttackZero/ctf_writeups/blob/master/sha_2017/web_100_bon_appetit/images/resource_etc_password.png)

## Leveraging Filters
Awesome.  Now we need to figure out how to leverage this.  I looked at the headers that server provided by using the Developer Tools in Firefox, and the header had Apache in it.  That means the server probably makes use of .htaccess files which allows the administrator of an Apache server to set access controls on files.  Let's see if we can find anything interesting in the .htaccess file:

![htaccess](https://github.com/AttackZero/ctf_writeups/blob/master/sha_2017/web_100_bon_appetit/images/htaccess.png)

I had some help with this one.  I had originally looked at htaccess without the view-source, and it did not reveal anything.  A group of us were working on it, and a teammate (reiku) showed me that little trick.

We can see that there is a FilesMatch directive for a file called "suP3r_S3kr1t_Fl4G".  Let's try to access it:

![flag](https://github.com/AttackZero/ctf_writeups/blob/master/sha_2017/web_100_bon_appetit/images/htaccess.png)

And there is the flag :) - flag{82d8173445ea865974fc0569c5c7cf7f}
