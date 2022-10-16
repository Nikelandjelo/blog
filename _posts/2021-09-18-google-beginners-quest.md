---
layout: post
title: "Google CTF: Beginners Quest 2021"
date: 2021-09-18
desc: "Google CTF: Beginners Quest 2021"
keywords: "CTF, Google, Beginners, Quest"
categories: [Ctf]
tags: [CTF, Google, BeginnersQuest]
icon: icon-google-alt
---

# Intro <a name="intro"></a>
So, I missed the <a href="https://capturetheflag.withgoogle.com/" target="_blink">Google CTF</a>, but I decided to give the Beginners Quest a go. So far, I got to challenge 10, with 6 and 8 currently unsolved (Future lesson: If the CTF has a "quest" in its name, you will need to solve the challenges in a set order...).<br />
Every challenge, if there’s a need - contains an attachment - an archive file with its SHA256 hash as a filename.
<br />
So, this is the map of the CTF:
<img alt="MAP" src="/static/assets/img/blog/ctfs/2021-googlebq/map.png" width="100%" />
<br />
And there is the order of all the challenges I got to, including the codes for each level:

```
1   =   2NFXHZYW
|
2   =   RWL9MHYX
|\
3/4 =   NKPNJRCH --+
|                  |
5   =   W92NLMRM ------+
                   |   |
6   =   YJLHPXHJ <-+   |
                       |
7/8 =   XXMWWHFM <-----+
|
10 =    LKCMP2KK
```
<br />

# Challenge 1 <a name="clng1"></a>
Task:
```
Novosibirsk - Chemical plant

You have now investigated the chemical plant. Nothing seemed to be out of the ordinary, even though the workers acted somewhat passive, but that’s not a good enough to track. It seems like you have a new voice mail from the boss: "Hello there, AGENT! It seems like the corporation that owns the plant was informed by an anonymous source that you would arrive, and therefore they were prepared for your visit, but your colleague AGENT X has a lead in Moscow, we’ve already booked you a flight. FIRST CLASS of course. In fact if you look out of the window, you should be able to see a black car arriving now, and it will carry you to the airport. Good luck!"

https://cctv-web.2021.ctfcompetition.com/
```
Our first task is taking us to this URL with a password prompt. If we check the source code, we can see that the authentication is on the client level. Great, so now we have to play with this JS.


<img alt="clng1" src="/static/assets/img/blog/ctfs/2021-googlebq/C1-1.png" width="100%" />


If we have a look closely, we can see that the page we are trying to access has the same name as the password, so we can't just delete the authentication script to bypass the password. However, the algorithm for checking the password is quite easy to reverse.


<img alt="clng1" src="/static/assets/img/blog/ctfs/2021-googlebq/C1-2.png" width="50%" />


If we want to play around, we can always get this piece of code and brute force the password.

```js
const v = "GoodPassword";
const p = Array.from(v).map(a => 0xCafe + a.charCodeAt(0));
console.log(p);

if(p[0] === 52037 &&
   p[6] === 52081 &&
   p[5] === 52063 &&
   p[1] === 52077 &&
   p[9] === 52077 &&
   p[10] === 52080 &&
   p[4] === 52046 &&
   p[3] === 52066 &&
   p[8] === 52085 &&
   p[7] === 52081 &&
   p[2] === 52077 &&
   p[11] === 52066) {
   console.log();
    }
else {
   console.log("Wrong password!");
}
```

However, it will be much easier and faster if we just write a script to get the password for us. So the way the authentication works is:<br />
- Get the password from the password field.<br />
- Makes an array for the password where every character of the password is added with the hex value `CAFE`.<br />
- Every item from the array is being compared with a specific value.<br />
So, what we need to do is put the comparison values in the order in a list, subtract the value `CAFE` and get our password.

```py
pas = (52037, 52077, 52077, 52066, 52046, 52063, 52081, 52081, 52085, 52077, 52080, 52066)

password = ''
for i in pas:
    password+=chr(i-0xcafe) #51966 = 0xcafe

print(password)
```
`GoodPassword`
<img alt="clng1" src="/static/assets/img/blog/ctfs/2021-googlebq/C1-3.png" width="100%" />
<br />
`Flag: CTF{IJustHopeThisIsNotOnShodan}`
<br />

# Challenge 2 <a name="clng2"></a>
Task:
```
Moscow - Apartment

It’s a cold day, and the snow is falling horizontally. It pierces your sight. You better use those extra pairs of socks that you were strangely given by the driver. Someone is waving on the other side of the street. You walk over to her. "Hi AGENT, I’m AGENT X, we’ve found the apartment of a person that we suspect got something to do with the mission. Come along!."

Challenge: Logic Lock (misc)
It turned out suspect's appartment has an electronic lock. After analyzing the PCB and looking up the chips you come to the conclusion that it's just a set of logic gates!
```
<img alt="Lock" src="/static/assets/img/blog/ctfs/2021-googlebq/logic-lock.png" width="100%" />
This challenge doesn't even deserve an explanation. In a nutshell, follow the logical operation. The goal is to get a signal or a 1 at the end. If you need help with logical operations, <a href="https://www.computerhope.com/jargon/l/logioper.htm" target="_blink">this article</a> might be helpful.
<img alt="Diagram" src="/static/assets/img/blog/ctfs/2021-googlebq/C2-2.png" width="100%" />
`Flag: CTF{BCFIJ}`
<br />

# Challenge 3 <a name="clng3"></a>
Task:
```
Moscow - Streets

The person drives into a narrow back alley and despite the danger you try to continue on and give chase. It is impossible to see who they are, clothed all in black and a helmet covering the face. You need to intercept them somehow.

Challenge: High Speed Chase (misc)
You chase them through city streets until you reach the high way. The traffic is pretty rough for a car and you see them gaining ground - should have hotwired a motorbike as well! Too late for that. You look around your car to spot anything useful, and you notice this is actually one of the new self driving cars. You turn on the autopilot, pull out your laptop, connect it to the system, and enter the not-so-hidden developer's mode. It's time to re-program the autopilot to be a bit more useful in a chase! To make it easier, you replace the in-car LiDAR feed with a feed from an overhead sattelite - you also display it on the the entertainment system. Now all that's left to do, is to write a better controlCar function!

https://high-speed-chase-web.2021.ctfcompetition.com/
```
<img alt="clng3" src="/static/assets/img/blog/ctfs/2021-googlebq/C3-2.png" width="100%" />
The link for this task is getting us to a page with a car game. There is a text field and hints on how to make a function next to it.<br />
According to the hints:

```
Car Self-Driving Interface

You need to re-implement the controlCar function.

To implement it in JavaScript use the editor on the left.

When implemented, controlCar function will be called several times per second during the chase to allow for course corrections.

The controlCar function takes a single parameter – scanArray – which is an array containing 17 integers denoting distance from your car to the nearest obstacle:

[indexes 0-7]: on the left side of the car (index 7 is the measurement at the left headlight),
[index 8]: at the center of the car,
[indexes 9-16]: on the right side of the car (index 9 is the measurement at the right headlight).
See also this image (it's not precise, but will give you an idea what you are looking at).

All measurements are parallel to each other.

A negative measurement might appear if the obstacle is very close behind our car.

The controlCar must return an integer denoting where the car should drive:

-1 (or any other negative value): drive more to the left,
0: continue straight / straighten up the car,
1 (or any other positive value): drive more to the right.
```
Furthermore, this picture is included:


<img alt="clng3" src="/static/assets/img/blog/ctfs/2021-googlebq/task3explained.png" width="100%" />


Digging into the source, we can find the function that is taking our code and executing it:


<img alt="clng3" src="/static/assets/img/blog/ctfs/2021-googlebq/C3-1.png" width="50%" />


So it seems this is a coding challenge, and we are expected to make the things work instead of breaking them.<br />
If that's the case, we can just start thinking of a solution.
The hint is clear on how everything is working. By using <code>alert(scanArray)</code>, we can make sure that the array is working as explained in the description. So to get to the end, we need to either avoid the closest object or try to chaise the furthest one.<br />
The solution I got to (with the worse JS skills ever) I am trying to avoid the closest objects. So the source contains two "if" statements - one checking if there is an object on the left and one that checks if there is an object on the right. If any of the statements return true, another "if" statement is triggered, which checks if there are two lines taken on the same side or just one. In the end, a return function returns the value, which will take the car away from the closes object.


<img alt="clng3" src="/static/assets/img/blog/ctfs/2021-googlebq/C3-end.gif" width="100%" />


```js
if(scanArray[9]<12 && scanArray[10]<12){
  if (scanArray[15]>10 || scanArray[13]>10) return 1;
  else return -1;
}
if(scanArray[6]<12 && scanArray[7]<12){
  if (scanArray[2]>10 || scanArray[4]>10) return -1;
  else return 1;
}
return 0;
```

There is another solution that works with the opposite logic. (The car is chasing the furthest object)[Credits to Ben!]

```js
if (scanArray.indexOf(Math.max(...scanArray)) + 1> 8) {
return 1} 
else if (scanArray.indexOf(Math.max(...scanArray)) + 1< 8) {
return -1}
```
`Flag: CTF{cbe138a2cd7bd97ab726ebd67e3b7126707f3e7f}`
<br />

# Challenge 4 <a name="clng4"></a>
Task:
```
Secret Location - Base

"Welcome back AGENT. It seems like you've got a marvelous lead that perhaps gives a clue about where you should head to next. Visit the lab, and talk to that Dr. Klostermann, or is it Cloysterman?, he will know how to decrypt the device.. you would think". ... Dr Klostermann: "Welcome to the technical department AGENT, I’m Dr. Klostermann, and this is my assistant, Konstantin. Let’s not waste any time, is that the device that you’re holding in your hand? Konstantin, start the basic procedure."

Challenge: Electronics Research Lab (hw)
Welcome back AGENT. It seems like you got a lead that perhaps gives a clue about where the next journey on your quest goes. Visit the lab, and talk to Dr. Klostermann, he will know how to decrypt the device Note: If you solved the challenge before but could not submit the flag, please try again, we had the wrong flag in our database.
```
```c
#include <stdbool.h>

#include "hardware/gpio.h"
#include "hardware/structs/sio.h"
#include "pico/stdlib.h"

int main(void)
{
	for (int i = 0; i < 8; i++) {
		gpio_init(i);
		gpio_set_dir(i, GPIO_OUT);
	}
	gpio_put_all(0);

	for (;;) {
		gpio_set_mask(67);
		gpio_clr_mask(0);
		sleep_us(100);
		gpio_set_mask(20);
		gpio_clr_mask(3);
		sleep_us(100);
		gpio_set_mask(2);
		gpio_clr_mask(16);
		sleep_us(100);
		gpio_set_mask(57);
		gpio_clr_mask(4);
		sleep_us(100);
[clip]
```
<img alt="clng4" src="/static/assets/img/blog/ctfs/2021-googlebq/C4-set_mask.png" width="70%" />
<img alt="clng4" src="/static/assets/img/blog/ctfs/2021-googlebq/C4-clr_mask.png" width="70%" />
<img alt="clng4" src="/static/assets/img/blog/ctfs/2021-googlebq/C4-put_all.png" width="70%" />
<img alt="clng4" src="/static/assets/img/blog/ctfs/2021-googlebq/C4-mask-to-bin.png" width="100%" />
<img alt="clng4" src="/static/assets/img/blog/ctfs/2021-googlebq/C4-end.png" width="100%" />

```py
flag = [67, 0, 20, 3, 2, 16, 57, 4, 0, 25, 5, 2, 18, 65, 1, 2, 64, 17, 2, 0, 1, 6, 18, 65, 1, 0, 4, 2, 0, 0, 64, 16, 16, 64, 2, 4, 0, 3, 9, 0, 0, 1, 0, 8, 8, 0, 65, 24, 22, 64, 0, 0, 0, 5, 0, 2, 65, 16, 22, 65, 1, 6, 4, 0, 66, 21, 1, 0, 0, 2, 24, 65, 67, 24, 24, 67, 2, 8, 65, 18, 16, 64, 2, 0, 68, 19, 19, 64, 72, 2, 2, 117]
res = 0
h = 0
for f in flag:
	res = res ^ f
	if h == 0: h+=1
	else:
		h-=1
		print(chr(res), end="")
```
`Flag: CTF{be65dfa2355e5309808a7720a615bca8c82a13d7}`
<br />

# Challenge 5 <a name="clng5"></a>
Task:
```
Istanbul - Bazaar

It’s a hot day, and your skin is cracking and dry. It’s difficult to make your way through the crowded bazaar. A high pitch voice pierces through the soundscape from a salesman that’s trying to sell colorful fabrics and then from another corner comes delicious smells. You spot a hand waving - it’s your contact that you’ve been waiting to meet. "Take a seat, my friend, I’m Gökhan, have you been to Istanbul before? No, really? I’m sure that you will have a great time, I’ve ordered tea for the two of us. Show me the amulet, will you?. Wow, this is really something from my younger days, this is as mysterious as it is beautiful and belongs to “The cloaked brotherhood”. They are very dangerous, and eventhough your quest is urgent, I would advise you to not continue looking for the owner of this. Go home, and forget about it." In the blink of an eye, four tough guys show up, and you start to run together with Gökhan through the crowded marketplace and then up on a rooftop. The tough guys are closing in, but the two of you climb down from the rooftop, run around a corner and are able to hide in two crates.

Challenge: Twisted robot (misc)
We found this old robo caller. It basically generates random phone numbers to spam. We found the last list of numbers in generated and also some weird file... Maybe it's got to do with these new beta features they were testing?
```
```py
import random

# Gots to get that formatting right when send it to our call center
def formatNumber(n):
    n = str(n)
    return f'{n[:3]}-{n[3:6]}-{n[6:]}'

# This generates random phone numbers because it's easy to find a lot of people!
# Our number generator is not great so we had to hack it a bit to make sure we can
# reach folks in Philly (area code 215)
def generateRandomNumbers():
    arr = []
    for i in range(624):
        arr.append(formatNumber(random.getrandbits(32) + (1<<31)))
    return arr

def encodeSecret(s):
    key = [random.getrandbits(8) for i in range(len(s))]
    return bytes([a^b for a,b in zip(key,list(s.encode()))])


def menu():
    print("""\n\nWelcome to the RoboCaller!! What would you like to do?
1: generate a new list of numbers
2: encrypt a super secret (in beta)
3: decrypt a super secret (coming soon!!)
4: exit""")
    choice = ''
    while choice not in ['1','2','3']:
        choice = input('>')
        if choice == '1':
            open('robo_numbers_list.txt','w').write('\n'.join(generateRandomNumbers()))
            print("...done! list saved under 'robo_numbers_list.txt'")
        elif choice == '2':
            secret = input('give me your secret and I\'ll save it as "secret.enc"')
            open('secret.enc','wb').write(encodeSecret(secret))
        elif choice == '3':
            print("stay tuned for this awesome feature\n\n")
        elif choice == '4':
            print("Thank you for using RoboCaller1337!")
    return

def main():
    while True:
        menu()

if __name__ == "__main__":
    main()
```
```py
from randcrack import RandCrack
rc = RandCrack()

def formatNumber(n):
    return f'{n[:3]}{n[4:7]}{n[8:]}'


numbers = open('robo_numbers_list.txt', 'r')
numbers = numbers.readlines()
numbs=[]

for n in numbers:
    numbs.append(int(formatNumber(n))-(1<<31))


#Feeding RandCrack
for n in numbs:
    rc.submit(n)

cipher = open('secret.enc', 'rb')
cipher = cipher.read()
cipher = list(cipher)


flag=""
for c in cipher:
    ans = (c^rc.predict_getrandbits(8))
    flag+=chr(ans)


print(flag)
```
`Flag: CTF{n3v3r_3ver_ev3r_use_r4nd0m}`
<br />

# Challenge 7 <a name="clng7"></a>
Task:
```
Buenos Aires - Conference
 
You are showing the invitation so that you can enter the conference. There are hundreds of important looking people at the conference. You take a glass of champagne from a tray, and try to look important yourself. After being busy with trying to look important for a few minutes, you approach the person that you are here to get classified information from. He introduces himself as Dr. Nowak Wasilewski. Nowak asks who you are, and if you can prove your knowledge through a test that he has designed by himself.

Challenge: ReadySetAction (crypto)
Apparently this script was used to encrypt super secret messages. Maybe there is something interesting in it? NOTE: this challenge was previously broken, redownload to get the correct file.
```
```py
from Crypto.Util.number import *

flag = b"REDACTED"

p = getPrime(1024)
q = getPrime(1024)
n = p*q

m = bytes_to_long(flag)

c = pow(m,3,n)

print(c)
print(n)
#15478048932253023588842854432571029804744949209594765981036255304813254166907810390192307350179797882093083784426352342087386691689161026226569013804504365566204100805862352164561719654280948792015789195399733700259059935680481573899984998394415788262265875692091207614378805150701529546742392550951341185298005693491963903543935069284550225309898331197615201102487312122192298599020216776805409980803971858120342903012970709061841713605643921523217733499022158425449427449899738610289476607420350484142468536513735888550288469210058284022654492024363192602734200593501660208945967931790414578623472262181672206606709
#21034814455172467787319632067588541051616978031477984909593707891829600195022041640200088624987623056713604514239406145871910044808006741636513624835862657042742260288941962019533183418661144639940608960169440421588092324928046033370735375447302576018460809597788053566456538713152022888984084306297869362373871810139948930387868426850576062496427583397660227337178607544043400076287217521751017970956067448273578322298078706011759257235310210160153287198740097954054080553667336498134630979908988858940173520975701311654172499116958019179004876438417238730801165613806576140914402525031242813240005791376093215124477
```
```py
import gmpy2
from Crypto.Util.number import *
gmpy2.get_context().precision = 1000 + 3

c = 15478048932253023588842854432571029804744949209594765981036255304813254166907810390192307350179797882093083784426352342087386691689161026226569013804504365566204100805862352164561719654280948792015789195399733700259059935680481573899984998394415788262265875692091207614378805150701529546742392550951341185298005693491963903543935069284550225309898331197615201102487312122192298599020216776805409980803971858120342903012970709061841713605643921523217733499022158425449427449899738610289476607420350484142468536513735888550288469210058284022654492024363192602734200593501660208945967931790414578623472262181672206606709
n = 21034814455172467787319632067588541051616978031477984909593707891829600195022041640200088624987623056713604514239406145871910044808006741636513624835862657042742260288941962019533183418661144639940608960169440421588092324928046033370735375447302576018460809597788053566456538713152022888984084306297869362373871810139948930387868426850576062496427583397660227337178607544043400076287217521751017970956067448273578322298078706011759257235310210160153287198740097954054080553667336498134630979908988858940173520975701311654172499116958019179004876438417238730801165613806576140914402525031242813240005791376093215124477
k = 0

pot = k * n + c
s = gmpy2.iroot(pot,3)

while s[1] != True:
    k += 1
    pot = k * n + c
    s = gmpy2.iroot(pot,3)

m = gmpy2.root(pot,3)
print("K: ", k, end="\n\n")
print(long_to_bytes(m))
```
`Flag: CTF{34sy_RS4_1s_e4sy_us3}`
<br />