# HackIT 2017 Forensics Challenge: USB ducker (100)

For this challenge, we are given a PCAP.  Unfortunately,
this PCAP is not Ethernet traffic: it is USB.  I have never worked with a USB packet capture, so I took some time to understand the structure of the packets and figure out where to begin.

Since Wireshark does not have built in parsers for USB data, the interesting data in this packet capture will be in the "Leftover Capture Data" field.  I made this field display as a column by choosing a packet (any packet will do), right-clicking "Leftover Capture Data" in the middle pane, and choosing Apply As Column.  I also made "Packet Data Length" a field.

This is what Wireshark looks like now:
![Wireshark View](https://github.com/AttackZero/ctf_writeups/blob/master/hackit_2017/forensics100/images/wireshark_column.png)

If we look closely at that packet, we can see that the interface class of the device is 0xffff which is vendor specific.  [This page](http://www.usb.org/developers/defined_class) lists all of the USB interface classes.  The contents of the data did not immediately jump out at me, and I wanted to see if there was anything in the file that was easier to work with.  So I made a note of the device and looked to see what else was in the capture.

The next device I came across was 1.2.0.  If we look further down, we can see that this device looks to be a USB hub:
![Device 2](https://github.com/AttackZero/ctf_writeups/blob/master/hackit_2017/forensics100/images/device2.png)

When a USB device wants to communicate with the host, it has to wait until the host polls it (or asks it if it has anything to communicate).  When the host polls it, and the device has something to send, it will send an interrupt and the data it wants to send.  These are the URB_INTERRUPT in packets we see in Wireshark.  "in" means that the direction of the communication is from device to host.  Device 1.2.0 does not seem to be communicating in this way, so we will look for another device.

A little further down, we see device 1.3.0.  If we look at the response to the Get Descriptor Device command from the host, we see that this is a keyboard:
![Device 3](https://github.com/AttackZero/ctf_writeups/blob/master/hackit_2017/forensics100/images/keyboard1.png)

That might be the device we are looking for.  We can also see that it uses 8 bytes to communicate.  If we look a few packets down, we can see that it is indeed communicating as a Human Interface Device (HID) which usually indicates a keyboard or mouse:

![Device 3 HID](https://github.com/AttackZero/ctf_writeups/blob/master/hackit_2017/forensics100/images/keyboard_hid.png)

Going further down the capture, we start to see the data:
![Device 3 Data](https://github.com/AttackZero/ctf_writeups/blob/master/hackit_2017/forensics100/images/keyboard_data.png)

Under the Packet Data Length column, you can see 8 which is what we expected because that is how many bytes the device told the host it would send.  The left over capture data contains the 8 bytes.  I used tshark to extract it so I could run a script over it:

```bash
tshark -r task.pcap -Y "usb.device_address==3 && usb.transfer_type==0x01" -T fields -e usb.capdata > dev3.txt
```

```task.pcap``` is the name of the file, ```-Y``` specifies filters on the packets.  I only want to get packets for USB Device 3 (1.3.0).  I also only want the interrupts we saw.  They are transfer_type 0x01.  I got this information by looking at the packets I wanted and figuring out which fields they have in common.  I want to extract fields, and the field I want to extract is usb.capdata which corresponds to the leftover data field.

Here is a snippet of the data:
```
...
00:00:05:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:28:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:20:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:34:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:52:00:00:00:00:00
...
02:00:00:00:00:00:00:00
02:00:20:00:00:00:00:00
```

The only thing that changes is the value in the third position and sometimes the value in the first position (it is either 00 or 02).  Initially, I thought these hexadecimal values may correspond to characters on the ASCII table, but when I extracted them and mapped them to ASCII (removing the 00 bytes), I did not get anything I recognized:
```
\x1a(\x0e(\t(\x05( 4R/R\x0fR R/\x1a!Q7\x05Q\x04\nQ/\x08Q\x06\x0c7/R/\tR/\x0eR\x11!R\r\x180Q3Q Q\x18Q".R2R\x1cR#R64Q\x13Q\x05Q$Q"$R\x07R\'R\rR\x13\x17Q\x0cQ\x04Q/Q\x0e&R.R\x15R\x10R0.Q\'Q\x07Q7Q\x0f\x06R%R-R/R\r"Q\x18Q\x16Q&Q%\x1fR\'R\x11R4R3&Q\x0bQ!Q0Q\x1c!R4R\x0eR3R.\x13Q\tQ\x08Q!Q\x1e0R\x1eR-R\x0eR\x16$Q\x16Q\x1fQ\x06Q"\x14R!R7R\x1eR 6Q\x16Q\'Q\x06Q\x1d R\x08R0R-R\x0c
```
I did some digging, and I stumbled across a document that describes [HID in detail (PDF)](http://www.usb.org/developers/hidpage/Hut1_12v2.pdf).  Page 54 is especially interesting.  Here is a snippet of the table:
![HID Table](https://github.com/AttackZero/ctf_writeups/blob/master/hackit_2017/forensics100/images/hid_table.png)

I wrote a script to take the lines of the file I got from tshark and try to recreate the keystrokes.  I noticed while writing the script that up and down arrows were pressed (code 52 and 51 respectively), so I tried to emulate that by creating multiple lines in my output and switching between them when the arrows were pressed.  I did the same thing for the enter key (code 28).  For lines that started with 02, I took that to mean that the shift key was pressed.  I could not find the codes for shift (E2 or E5) in the data, so I figured that since 02 was not as common as 00, that means that shift may have been pressed.

The code is available [here](https://github.com/AttackZero/ctf_writeups/blob/master/hackit_2017/forensics100/code/keymapper.py), and this is the output I got:

```
w{w$ju},'pt]=j%;9+ps&#,i
k#>bn$:6pjim0{u'h;fks!s-
flag{k3yb0ard_sn4ke_2.0}
b[[e[fu~7d[=>*(0]'$1c$ce
3'ci.[%=%&k(lc*2y4!}%qz3
```

The flag is on the third line: ```flag{k3yb0ard_sn4ke_2.0}```

# Conclusion
This was an interesting challenge.  While I am not a USB protocol expert, it was fun to pick this one apart.

# References
[USB in a Nutshell](http://www.beyondlogic.org/usbnutshell/usb4.shtml#Interrupt)
