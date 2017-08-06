# SHA2017 Forensics Challenge: WannaFly (100)

This challenge was clearly inspired by all of the ransomware that has been cropping up lately.

THe hint is: "My daughter Kimberly her computer got hacked. Now she lost all her favorite images. Can you please help me recover those images?"

You are given a file with an img extension.  It is probably a disk image.

```bash
file kimberly.img
kimberly.img: Linux rev 1.0 ext4 filesystem data, UUID=56e89f54-c4da-4c5e-a3c6-67398d341788 (needs journal recovery) (extents) (large files) (huge files)
```

Let's mount it and see what we get:
```bash
mkdir kimberly
mount -t ext4 kimberly.img kimberly
cd kimberly
ls -al
drwxr-xr-x 12 1001 1001  1024 Aug  5 14:33 .
drwxr-xr-x  7 root root  4096 Aug  5 14:27 ..
-rwxr-xr-x  1 1001 1001  6835 Jun 20 12:13 ...
-rw-------  1 1001 1001    69 Jan 18  2017 .bash_history
drwx------  2 1001 1001  1024 Jan 18  2017 .cache
drwxrwxr-x  2 1001 1001  1024 Jan 18  2017 Desktop
drwxrwxr-x  2 1001 1001  1024 Jan 18  2017 Documents
drwxrwxr-x  2 1001 1001  1024 Jan 18  2017 Downloads
drwx------  2 root root 12288 Jan 18  2017 lost+found
drwxrwxr-x  2 1001 1001  1024 Jan 18  2017 Music
drwxrwxr-x  2 1001 1001  1024 Jun 20 11:04 Pictures
drwxrwxr-x  2 1001 1001  1024 Jan 18  2017 Public
drwxrwxr-x  2 1001 1001  1024 Jan 18  2017 Templates
drwxrwxr-x  2 1001 1001  1024 Jan 18  2017 Videos
```
The ```...``` file is interesting.  ```.``` means the current directory, ```..``` means the directory above this one, but ```...``` probably a means of hiding a file in plain sight.  Most people will see ```...``` and not notice it.

Let's see what it is:
```bash
file ...
...: Python script, ASCII text executable, with very long lines
```

So it is a Python script.  It is a bit long to reproduce here, but there are some interesting
snippets that give us an idea about what is going on:

```python
def get_iv():
    iv = ""
    random.seed(int(time()))
    for i in range(0,16):
        iv += random.choice(string.letters + string.digits)
    return iv

def encrypt(m, p):
    iv=get_iv()
    aes = AES.new(p, AES.MODE_CFB, iv)
    return base64.b64encode(aes.encrypt(m))

def encrypt_image(img):
    data = open(img, 'r').read()
    encrypted_img = encrypt(data, sys.argv[1])
    blurred_img = open('/tmp/sha.png', 'r').read()
    stat = os.stat(img)
    with open(img, 'r+') as of:
        of.write('\0' * stat.st_size)
        of.flush()
    open(img, 'w').write(blurred_img + "\n" + encrypted_img)
```

If we look in the Pictures folder from our mounted image, we will see PNG files that look like this:
![Blurred PNG](https://github.com/AttackZero/ctf_writeups/blob/master/sha_2017/forensics_100_wannafly/images/blurred_image.png)

So it appears that this what is happening:

* An image is read in
* It is blurred and the message is added to it
* The encrypted version of the base64 encoded bytes of the image is appended to the end of the blurred image after a newline

In order to decrypt the images, we need to know:

* How the files were encrypted (which algorithm is used): We can see it is AES CFB
* The initialization vector (IV) used.  This appears to be created with "random" letters and numbers from a-z, A-Z, and 0-9.  Fortunately, the seed is the time when the IV is created.  This means if we can determine the seed, we can recreate the IV because the same seed will always produce the same random numbers (assuming we use Python's random number generator because that is what was used to create the IV).
* The key used to encrypt.  It looks like this is the first argument to the program, so if we can find a record of the program being run, we might be able to find this.

## Finding the IV
We can see that the random number generator used to create the IV is seeded with the time when the IV is created.  Since computers are fast, we can reasonably assume that the time when the IV was created is around the time that each encrypted image was modified (since the encrypted version of each image was appended to the end of the original image).  If we do not get the exact time, we can try times around the modified time.  For now, we will use the modified time of the image.

## Finding the key
The key is not in the script we found, but for the encryption to happen, the script would have had to been executed at some point.  In the directory listing, there was a .bash_history file.  Assuming it was not tampered with, it might have a clue:
```bash
cat .bash_history

unset HISTFIL
ls -la
pwd
chmod +x ...
./... Hb8jnSKzaNQr5f7p
ls -Rla
```

Ahh.  So the attacker meant to ```unset HISTFILE``` which would have disabled recording of the commands.  Fortunately for us, he or she made a typo, and we get to see the commands.  We can see that ```...``` was executed with the key: ```Hb8jnSKzaNQr5f7p```.

## Putting It All Together
Now that we have all of the pieces we need, we can decrypt the images (hopefully).  The sequence is:

* Read the encrypted image in and find the end of it.  Since it is a PNG, the end will be marked by an IEND chunk.  The IEND chunk contains 4 bytes of data (a CRC of the chunk).
* Read the base64 encoded original image from IEND + 5 bytes (IEND + 4 bytes for CRC + 1 byte for the new line).  Base64 decode these bytes to get the encrypted image bytes.
* Use the modified time of the encrypted image to generate the IV.  The IV is 16 bytes of "random" letters and numbers from upper and lowercase letters as well as numbers.
* Use the key we found and the IV we generated to decrypt the encrypted image bytes

I have written a script to do this, available [here](https://github.com/AttackZero/ctf_writeups/blob/master/sha_2017/forensics_100_wannafly/code/image_decryptor.py).  It takes the folder with the encrypted images, the folder to output decrypted images to, and the key as inputs.

After we run it and start looking through the images, we can see that we got real PNG files which is great.  There is one in particular that contains the flag:
![Flag](https://github.com/AttackZero/ctf_writeups/blob/master/sha_2017/forensics_100_wannafly/images/flag.png)

```
flag{ed70550afe72e2a8fed444c5850d6f9b}
```
