---
layout: post
author: nIIk
title: "I love Arch..."
date: 2024-03-24 00:00
keywords: "linux, arch"
categories: [Linux]
tags: [debugging, linux]
---

## Don't we all love broken dependencies?!?!?

After a sweet update at the end of my day, I was a good boy and I restarted my system just to be prompted with a frozen screen. Lucy enough, I got TTY. After some debugging I realised that `libmount.so.1` was at version 2.39, whereas `libgio.`so.0` requires version 2.40...

So now what???

At this point, I was looking up the packages at https://archlinux.org/packages/ and I was planning on downgrading GLIB to the previous version. Now, unfortunately, I had cleared the cache, so I needed to download the package in order to install it. However, `libmount` is used by NetworkManager, meaning I had no Internet. `libmount` is also used for mounting external drives, so no USB with the package either.

Sooo, I decided I should do the things from `chroot`, so I booted in an external Arch and mounted the drive. When I went to find the link for the package tho, I saw that there has been recently pushed an update for `util-linux`... Around half an hour after the GLIB update...

![GLIB](blog/linux/1/glib.png)

![util-linux](blog/linux/1/utli-linux.png)

I ran `pacman -Syu` from the `chroot` terminal, restarted my machine, and everything was running just fine again...

In a nutshell, anyone who updated their system in this half an hour window got screwed up...