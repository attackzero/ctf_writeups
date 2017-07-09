# LabREynth 2017 Binary Challenge 1 — MyFirstMalware.exe
There are three files included with the sample: config.jpg, notdroids.jpg, and MyFirstMalware.exe. I usually start with basic static analysis. Static analysis is the process of looking at how the files exist on disk before running them. You can sometimes get clues from the human readable strings in the files or things about the files themselves. I like to use a hex editor to look at the bytes in files because files are not always what they seem on the surface. The hex editor I like for Windows is HxD. On Linux, I like hexdump.

Let’s take a look at the JPEGs. Here is config.jpg
![Config.jpg in a hex editor](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_config.jpg)
and here is notdroids.jpg:
![notdroids.jpg in a hex editor](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_notdroids.jpg)
These do not look like normal JPEGs to me. They look encrypted, and the binary probably decrypts them and does something with them. Maybe there are clues in the binary:
![MyFirstMalware.exe in a hex editor](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_exe.jpg)
The header is unencrypted (which makes sense, otherwise Windows would not know what to do with it). However, most of the binary is encrypted. There is probably stub code that decrypts it in memory. Right now, I am more interested in how it works so I can do further analysis. The best way to do this is to run it. You do not want to run unknown software on your main computer, so I have spun up a Windows 7 VM. If the malware destroys the VM, I can blow it away and start with a clean VM.

There are a number of tools to do dynamic analysis. We are not going to talk about all of them in this post, but I want to show you my thought process so that you get an idea of how to approach these puzzles (CTF puzzles or real life puzzles). Tools come and go, and every tool has its limitations, so it is best to have a number of tools in your toolbox because you never know what you will need.

To get an idea of how the malware works, I am going to see how it interacts with the system. I am going to use two tools from the [Sysinternals Suite](https://technet.microsoft.com/en-us/sysinternals/bb842062.aspx) for this: Process Explorer and Process Monitor (procmon). Process Explorer will allow us to watch processes spawn and die. Process Monitor will allow us to watch what Windows API calls a process makes. This can be useful to see how the program interacts with the registry and file system. Here is what Process Explorer looks like:

![ProcessExplorer](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_procexp.png)

Pink entries are system binaries, and blue entries are user processes. Green means something (a handle, process, whatever) was created, and red means something was killed. I have changed a few of the default settings. First, I have changed the amount of time that Process Explorer highlights a change to 5 seconds so that I can see the changes more easily. You can see the highlights in the screenshot above. The default highlight duration is 1 second. If you want to change this, you can use Difference Highlight Duration under the Options Menu. The second change I made was to display the handles of a running process in the bottom pane. You can hit Ctrl-H to show handles.

The second tool is procmon:

![Procmon](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_procmon.png)

You can see svchost is interacting with the registry quite a bit. You have to be careful with procmon. If your system is busy, you can run out of memory because all events are stored in memory. Also, if your system is really busy, then it will be hard to isolate the events you care about. To help solve both problems, we will employ filters.

Under the Filter menu, there is a Filter option. You can also hit the funnel icon in the toolbar:
![Procmon Filters](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_procmon_filter.png)

We are going to be examining MyFirstMalware.exe, so we will include the process name “MyFirstMalware.exe” You can filter on all kinds of properties like PID, parent PID, and path. Hit Add then hit OK.

Now that we are back at the main screen, we will try running the malware.

![MyFirstMalware.exe in Procmon](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_procmon_exe.png)

Lots going on there. Here is what it looks like in Process Explorer:

![MyFirstMalware.exe in Process Explorer](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_procexp_exe.png)

It is PID 3800 in this case. We will wait to see if it finishes. In the mean time, we can look at the various properties in Process Explorer to see if we can glean anything additional. There are all kinds of tabs to check out. The TCP/IP tab will show open network connection, and the Strings tab shows the strings in binary both on disk and in memory. With malware, what is on disk may not be what is in memory. Malware typically uses techniques like packing, encryption, and obfuscation to hide from people who want to see what their code is doing. Here is a look at the strings in memory:
![Strings in Process Explorer](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_procexp_strings.png)
I will save them to a file in case they come in handy later. There was nothing in the TCP/IP tab, so this specific process does not use the network, but it may spawn something that does.
Going back to Process Monitor, there is something interesting:
![MyFirstMalware.exe looking for notdroids.jpg](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_procmon_exe2.png)
The process tries to open the notdroids.jpg file on the root of the C:\ drive. When it does not find it, it quits. So, maybe we should copy notdroids.jpg to the root of our C:\ drive and see if the malware behaves any differently.
![notdroids.jpg is there now](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_procmon_exe3.png)
We can see that the process was able to open notdroids.jog and a lot more happened this time. We can see some encryption libraries were loaded (cryptsp.dll and rsaenh.dll). Cryptsp is the [Cryptographic Service Provider API](https://msdn.microsoft.com/en-us/library/windows/desktop/bb931357(v=vs.85).aspx), and rsaenh is the [Enhanced Cryptographic Provider (PDF)](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140sp/140sp1330.pdf).

That follows what we hypothesized before about MyFirstMalware utilizing encryption. Scrolling further down, we can see that the contents of notdroids.jpg are read into memory:
![notdroids.jpg in memory](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_notdroids_memory.png)
Next we can see that ping.exe is launched:
![ping.exe](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_ping.png)

Further down, we can see that MyFirstMalware does a directory listing of C:\Windows\SysWOW64\:
![Dir listing](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_dirlist.png)

Then ping.exe is closed:
![ping.exe done](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_ping_closed.png)

The next event of note is that the process exits:
![Malware is all done](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_exe_closed.png)

The next step would be to fire up Wireshark and see if we can see ICMP traffic since that is what ping.exe would normally generate.

![Firing up Wireshark](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_wireshark.png)

I put on a few display filters to filter out some noisy protocols, and there was no ICMP in here or anything that looked abnormal. Maybe something else is going on. Let’s see if we can debug the process and see what is going on.

Unfortunately, some malware can see that a debugger has attached to it and will not run. Hopefully that is not the case here. I am going to use OllyDbg 2.0 (Olly) for this example. You could use other tools like IDA or Binary Ninja which do more than Olly. Despite that, Olly should be enough for our needs. When we load up MyFirstMalware in Olly, we get a screen that looks like this:
![Here comes Olly!](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_olly1.png)

This looks really intimidating when you first open it. I am no OllyDbg expert, but that is why I do challenges like these. I want to get exposure to different tools. For now, we are going to do a relatively simple task. We are going to see if we can see how the ping.exe is created. Maybe there are some clues as to why we are not seeing packets on the wire.

To get started, we want to set a breakpoint (pause execution) when the code calls *CreateProcess* from the Windows API. We saw in Process Monitor that ping.exe was created, and it was likely done using that call. In order to do that in Olly, hit Ctrl-G (Follow Expression):
![Following an expression](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_olly_follow_exp.png)

When we start typing *CreateProcess*, we can see a few options. We will choose *kernel32.CreateProcessW*. *CreateProcessW* takes a Unicode string as opposed to *CreateProcessA* which takes an ANSI string. I am going to guess that this code was compiled with Unicode support. If not, we can always go back and choose to follow *CreateProcessA* (or we can follow both). Click on *kernel32.CreateProcessW* and then click Follow Label (the button changes). It will jump to the first call of *CreateProcessW*. Press F2 to create a breakpoint there.

![Our first breakpoint](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_olly_bp1.png)

We can repeat this process for subsequent calls, but there are no other calls to *CreateProcessW* that we can see right now.

You can repeat the process for *CreateProcessA* if you like.

Right now, Olly loaded up the executable and is waiting for us to do something. Hit the Play button or hit F9.

When the program calls *CreateProcessW*, Olly will pause execution so we can take a look at the current state of the program.

![Awesome! Olly stopped at the call to CreateProcessW!](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_olly_bp2.png)

If we look at the bottom right pane, we can see something interesting:
![Suspended Process](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_suspended.png)

This pane shows the parameters to the function call. The CreationFlags parameter is interesting. When a process is created with this call, it can be started with different options outlined [here](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684863(v=vs.85).aspx). For CREATE_SUSPENDED, the details tell us “The primary thread of the new process is created in a suspended state, and does not run until the [ResumeThread](https://msdn.microsoft.com/en-us/library/windows/desktop/ms685086(v=vs.85).aspx) function is called.”

Why would the malware do this? This is likely an example of a technique called Process Hollowing. The full details are beyond the scope of this post, but I will give you a high level overview. If you are interested, there are links in the Further Reading section.

The idea behind process hollowing is that you replace the contents of a process’ memory with something else. It is as if you hollowed out a potato and filled it with yummy things. In this case, the potato is a legitimate looking process, and the yummy things are malicious code bytes. If you saw ping.exe, running out of C:\Windows\System32 or C:\Windows\SysWOW64 you might not think anything of it because that appears to be legitimate. If some random process was running out of a strange folder, that might raise alarms. 

In addition, many virus scanners do not compare the image of an executable on disk versus what is in memory. If it sees C:\Windows\System32\ping.exe running, the virus scanner assumes that is what is running in memory and does not question it.

So how does a malicious program hollow out a process? It makes a few tell tale API calls. We have already seen the first one (*CreateProcess* with the CREATE_SUSPENDED flag set). Other calls include:

* *NtUnmapViewOfSection*: Unmap the memory occupied by the newly spawned process so that there is nothing in the newly spawned process.
* *VirtualAllocEx / VirtualAlloc*: Allocate enough memory to put the bad code in
* *WriteProcessMemory*: Write the malicious code into the vacant memory space
* *GetThreadContext*: Get the details of the new process so that the original process can modify the entry point of the newly spawned / hollow process. When the malware resumes the hollowed out process with its malicious code in it, Windows will be expecting the code to start at a certain place. The malware needs to adjust this for the new code it has just put in. GetThreadContext allows the malware to get those details so that it can edit them.
* *SetThreadContext*: Change the entry point of the hollowed out process to correspond with the malicious code now living inside of it.
* *ResumeThread*: Run the hollowed out process that now contains malicious code.

We want to see if we can see the code that gets written into the process so that maybe we can isolate it and examine it further. So, we will need to set a breakpoint before *WriteProcessMemory*. We will follow the same procedure as we did for *CreateProcessW*. Once you have set that break point, hit F9 to resume execution.

If we step out into Process Explorer, we can see the suspended ping.exe process:
![Process Explorer](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_procexp_ping.png)

So, we have hit the break point at *WriteProcessMemory*:
![Breakpoint](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_olly_bp3.png)

In the bottom right, we can see the memory address of the buffer that contains the bytes that will be written into ping.exe’s memory space:

![Buffer being written to ping.exe](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_olly_mem_1.png)

We can also see some interesting artifacts such as C:\notdroids.jpg which is the likely encrypted file we saw before and a string starting with 7Z which may be the decryption key.

If we right click that line and choose Follow in Dump, we can look at the memory in the lower left pane:

![notdroids decryption](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_olly_dump1.png)

That looks like an executable. We can see bytes 4D 5A (MZ) which start Windows executables. This function call is copying 1,024 bytes (from address 0x002AE950 to 0x002AED50). You can copy the bytes from Olly (highlight the bytes you want, then right click, choose Edit, then Binary Copy) or from HxD. We are going to use HxD to recreate the memory that is being dumped into the ping.exe process space to see how it is building everything.

In HxD, hit the memory chip in the toolbar or choose Extras > Open RAM. Then, pick the executable that is writing the memory (MyFirstMalware.exe in this case):

![HxD Process Chooser](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_hxd_proc.png)

Then go to the address we identified in Olly (0x002AE950), choose Edit > Select Block and tell HxD how much memory you want to select (400 hex, 1024 bytes in this case):

![HxD Memory Block Size](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_hxd_memblock.png)

Right click the selected block, choose Copy, then make a new file and paste it in:

![HxD Memory Block](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_hxd_mem.png)

After this is done, resume execution in Olly (hit F9), then it will hit the break point on the next call to *WriteProcessMemory*:

![Next Call to WriteProcessMemory](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_olly_wpm2.png)

So, now we do the same thing but with a different offset and a larger number of bytes. After this, you should have 57,344 bytes (1,024 from the first call, 56,320 from this call). You can see that the malware is copying sections of the program one at a time.

If you keep doing this, eventually you will get to the last call:
![Finally done dumping memory](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_olly_wpm_all.png)

At this point, you will have 88,068 bytes in your HxD file. You can save that as a new executable (I chose notdroids.exe), and we can figure out what is going on with that executable as well.

If we load up Process Monitor and filter on notdroids.exe, we can see that it is looking for config.jpg (the other “JPEG” file that was supplied with the malware):

![Back to Procmon](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_procmon_config.png)

We will put config.jpg in the root of C:\ and try again. We can see that it found the file this time and invoked the Crypto Service Provider library right after it read it:

![Trying that again](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_procmon_config2.png)

This means that config.jpg is probably encrypted like we thought. If we look through the rest of the calls, notdroids.exe exits soon after, so it is probably not doing process hollowing (since no new processes are called). It would be interesting to find out what is in the decrypted version of config.jpg which is likely in memory.

If we look further down, we can see the call to *ReadFile* where config.jpg is actually read:

![ReadFile Call](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_procmon_config3.png)

If we right click on that and choose, Stack, we can see the address of the call (0x75F83F27). We want to jump to the point where that function returns (the next call in the stack, the call below *ReadFile*). This call is at 0x01133AA5. We can jump to this point in memory and see what is going on (Ctrl-G):

![Following ReadFile](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_olly_follow2.png)

Here is that spot in memory:
![ReadFile in Memory](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_olly_bp4.png)

We will set a break point at 0x01133AA5 and run to it (hit F9). A few calls down from there, we can see an interesting one at 0x0113ACB to *ADVAPI32.CryptDecrypt*:

![CryptDecrypt](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_cryptdecrypt.png)

If we make our way down there by using F8 to step through each instruction until we make it to 0x01133AD1 (after *CyrptDecypt* has executed), we can see something very interesting in the stack:

![What is that in the stack?](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_key_stack.png)

That is the key were were looking for! If we right click and Follow in Dump, the key is revealed:
![Woot!](https://github.com/AttackZero/ctf_writeups/blob/master/labyrenth_2017/images/binary_1_key_dump.png)

**PAN{93A0A2414CD35A7620A7FD23ECEF187F08FBC5728229614B18EEDEE81ED59393}**

And that completes this challenge. :)

# Conclusion
This challenge was really engaging. This was my second time using Olly, so even though I had to rely on Google, I learned a lot.

# Links to Tools
[Sysinternals Suite](https://technet.microsoft.com/en-us/sysinternals/bb842062.aspx)
[HxD](https://mh-nexus.de/en/hxd/)
[Wireshark](https://www.wireshark.org/)

# Further Reading
[Process Hollowing Meets Cuckoo Sandbox](http://journeyintoir.blogspot.com/2015/02/process-hollowing-meets-cuckoo-sandbox.html)
[Following Process Hollowing in OllyDbg](http://blog.airbuscybersecurity.com/post/2016/06/Following-Process-Hollowing-in-OllyDbg)
