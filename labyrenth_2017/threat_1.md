# Labyrenth Threat Challenge 1: DNS
In this challenge, we are presented a pcap file with a number of DNS queries and responses.

We are given the following hint:
> Just because it's protocol compliant doesn't mean it is a good idea.

There looks to be something unusual in each of the queries:
![Interesting Strings in DNS](https://github.com/attackzero/ctf_writeups/labyrenth2017/images/threat1_packets.png)

We can write a script to concatenate these interesting strings using scapy to extract the raw payloads from
each packet.

All of the interesting strings fall between character c0 plus one character and 03 (End of text).  We
can use a regular expression to capture the string between those bounds.

The script is available [here](https://github.com/attackzero/ctf_writeups/labyrenth2017/code/threat1.py)

```python
import scapy.all
import re

# The interesting strings in the raw payloads come between \xc0 and \x03
interesting_string_re = re.compile(r'.*\xc0.(?P<string>.*)\x03.*')

# Read PCAP file
challenge_pcap = scapy.all.rdpcap('challenge.pcap')

# Get a list of the interesting things in the raw payloads
interesting_strings = []

for packet in challenge_pcap:
    # Only look at DNS Query packets
    if packet.haslayer(scapy.all.DNSQR):
        # Get the raw payload since that has the strings that look interesting
        raw_payload = str(packet.getlayer(scapy.all.Raw))
        if interesting_string_re.match(raw_payload):
            # The regex grabs the part of the payload we want in the capture group called string
            interesting_strings.append(interesting_string_re.match(raw_payload).groupdict()['string'])

# Join the strings together
print('Concatenated strings:')
print(''.join(interesting_strings))
```

Here is what we get:
```
Concatenated strings:
UEsDBBQAAAAIAOCIr0qMVwGeKQAAACoAAAAIABwAZmlsZS5kYXRVVAkAA3QYGlmBGBpZdXgLAAEE6AMAAAToAwAAC3D0q3bMyQnIz8wrSS0q9sxz8QsOzsgvzUkBCzklJmeXJxalFNdyAQBQSwECHgMUAAAACADgiK9KjFcBnikAAAAqAAAACAAYAAAAAAABAAAAtIEAAAAAZmlsZS5kYXRVVAUAA3QYGll1eAsAAQToAwAABOgDAABQSwUGAAAA
```

This looks like base64 because of the alphabet.  We can base64 decode it by adding a few lines to the script:
```python
import scapy.all
import re
import base64

# The interesting strings in the raw payloads come between \xc0 and \x03
interesting_string_re = re.compile(r'.*\xc0.(?P<string>.*)\x03.*')

# Read PCAP file
challenge_pcap = scapy.all.rdpcap('challenge.pcap')

# Get a list of the interesting things in the raw payloads
interesting_strings = []

for packet in challenge_pcap:
    # Only look at DNS Query Packets
    if packet.haslayer(scapy.all.DNSQR):
        # Get the raw payload since that has the strings that look interesting
        raw_payload = str(packet.getlayer(scapy.all.Raw))
        if interesting_string_re.match(raw_payload):
            # The regex grabs the part of the payload we want in the capture group called string
            interesting_strings.append(interesting_string_re.match(raw_payload).groupdict()['string'])

# Join the strings together
print('Concatenated strings:')
print(''.join(interesting_strings))

# Looks like Base64, so let's decode it
print('Base64 Decoded:')
contents = base64.b64decode(''.join(interesting_strings))

# What does the base64 decoded string look like?
print(contents)
```

This is what we get:
```
Base64 Decoded:
PK���J�W�)file.datUT	tY�Yux
                                           ��
                                                  p��v��	���+I-*��s�
                                                                           ��/�I
                                                                                 9%&g�'��rPK���J�W�)��file.datUTtYux
                                                                                                                                 ��PK
```
There are some unprintable characters in here, but the ```PK``` at the beginning makes me think this is a zip file.
We can write the bytes out to a file and try to work with it:
```python
with open('contents.zip', 'wb') as contents_file:
    contents_file.write(contents)
```

```
unzip contents.zip
Archive:  contents.zip
  End-of-central-directory signature not found.  Either this file is not
  a zipfile, or it constitutes one disk of a multi-part archive.  In the
  latter case the central directory and zipfile comment will be found on
  the last disk(s) of this archive.
unzip:  cannot find zipfile directory in one of contents.zip or
        contents.zip.zip, and cannot find contents.zip.ZIP, period.
```
That is no good.  This must not be a zip file.  It could be a JAR (Java Archive).  JARs look a lot like
zip files.  Let's try to unarchive it using jar:
```
$ jar xvf contents.zip
 inflated: file.dat
```
Looks like we got something:
```
$ cat file.dat
PAN{AllPointersInDNSShouldPointBackwards}
```
And there is the key.  Awesome!
