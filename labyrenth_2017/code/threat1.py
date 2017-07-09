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

# Looks like a zip file (starts with PK)
with open('contents.zip', 'wb') as contents_file:
    contents_file.write(contents)
