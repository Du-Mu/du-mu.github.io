---
title: Fedora-and-Nvidia-driver-installing
date: 2022-10-15
tags: 
- Linux

categories:
- Linux

toc: true # 是否启用内容索引
sidebar: none # 是否启用sidebar侧边栏，none：不启用
---



## 背景

最近一直在折腾自己的windows的配置，包括外观还有各种环境的配置，感觉自己做的颇为臃肿了，所以打算配一个Fedora的双系统，从头开始规划，配置作为自己的主力办公系统。

就我个人而言，我在之前有过一段时间的Ubuntu的虚拟机的使用，对于Red Hat系的linux发行版没有什么使用经验，同时，对于双系统，引导启动没有过多的概念，此为前提。

## 问题的出现

在初步了解了一些双系统的知识后，我开始了自己的Fedora安装之旅。

- 首先在windows下创建一个空闲的硬盘分区
- 利用Fedora提供的官方工具Fedora Media Writer制作了一个Fedora的启动U盘
- 开机时进入BIOS，选择从引导盘启动

一切都很顺利，然而在我在Grub中选择Start Fedora时，在一段时间运行后，还没有进入安装时，Fedora就直接终止了，黑屏一段时间后，就直接返回了Grub界面，这让我有些懵了。

## 问题的定位

在问题出现后，第一反应，肯定是直接搜索看有没有跟我相同的问题出现，于是我分别在Google 和ask Fedora论坛上同时搜索了这个问题，但是没有找到相关结果，难道要在ask fedora上提问吗？这个得到回答的周期对我来说可能太长了，我还是尽可能想自己尽快找出结果。

那么思路就很清晰了，首先排除偶然因素：

于是我重新制作了一个启动盘，在此尝试了一下，然而还是闪退，既然问题是稳定出现的，我开始真正定位问题：

考虑在这个安装环节中，我都是同大多人一样的步骤，那么我开始回顾在这个安装过程中有哪些环节可以出问题：

- iso文件
- linux发行版特性
- U盘

于是我开始尝试更换发行版，包括Fedora37和ubuntu22，然而还是稳定出现了闪退问题。那iso文件问题或者linux发行版问题可以排除了。

接下来再换了一个U盘，然而还是闪退。

到这里，似乎已经进入死胡同了，难道是电脑的问题？我不可能为此换一个电脑啊，似乎这不是我能解决的问题了，因为我对引导启动过程只是一知半解，想debug也无从下手。

这个时候我看着Grub的界面，开始了思考和尝试:

> --------------------------------------------Grub--------------------------------------------------
>
> *start Fedora
>
> test this media & start Fedora
>
> troubleshouting----->

在第一个和第二个选项都已经尝试过后，我自然的进入第三个选项troubleshouting上了，出乎意料的，在troubleshouting后，我发现我进入了Fedora的安装界面，虽然分辨率堪忧，但是有了进展和区别，总是好的。

于是我重新回到Grub界面，按e键分别查看前三个选项的启动命令行，分析差别。

一个显而易见的差别映入我的眼帘，“nomodeset”参数，这个参数在troubleshouting中有，然而在前两个选项中没有，这会是troubleshouting能成功启动的原因吗？

于是我在e键跟进了第一个选项，添加了nomedeset参数，ctrl+x键执行，成功进入安装界面，虽然依旧是分辨率堪忧。

于是再次Google nomedeset的作用，发现是暂且不加载显卡模块。看见显卡二字，以及自己电脑上绿色的Nvidia商标，再联想到linus著名的f**k nvidia之喷，我大概确定了了，是显卡的问题。





## 解决问题

既然确定了是显卡的问题，那么转换搜索思路，以Nvidia为关键词再在ask fedora搜索，于是找到了[这个](https://ask.fedoraproject.org/t/kde-fails-to-boot-on-certain-nvidia-graphics-cards-in-uefi-mode/22065)

>## Problem
>
>On systems with certain Nvidia graphics cards, Fedora 36 KDE fails to boot in UEFI mode. This includes both the Live installer image and the installed system.
>
>It only happens in combination with Wayland display protocol, but the KDE login screen it configured to use Wayland by default, so this happens every time, unless the settings are changed in the installed system.
>
>## Cause
>
>Not yet known. In general, Nvidia’s attitude towards Linux.
>
>## Related Issues
>
>Bugzilla report: [2077359 – KDE on X11 with native graphics hangs with Nvidia GPU and UEFI 53](https://bugzilla.redhat.com/show_bug.cgi?id=2077359)
>
>## Workarounds
>
>You have the following options:
>A) Switch your system to BIOS mode instead of UEFI and install Fedora that way.
>B) Boot the install in *Safe graphics mode* (available under the *Troubleshooting* boot menu). After system install, either install the closed-source nvidia driver (if you intended to do so), or set KDE to always use X11 instead of Wayland, including the login screen. Then edit the grub config files to remove the *nomodeset* keyword (triggering safe graphics mode) and rebuild the installed grub bootloader config.
>C) Install Fedora Workstation (GNOME) instead of KDE.
>D) Switch your graphics card to a more Linux-friendly vendor (AMD, Intel). You might already have an integrated graphics card in your CPU which you can use instead of the Nvidia external one.

那么基本确定了解决思路：

nomodeset先install fedora，然后进入fedora安装Nvidia显卡驱动，然后再重新启动。

当然，在安装驱动过程中也遇到了一些问题，网络上对于驱动安装基本有三种主流的方法：

- 在dnf添加两个源，用dnf安装
- 用Nvidia官方的脚本安装
- 在dnf添加一个module，用dnf安装(由于我是第一次使用red hat系的发行版，对dnf不是很熟，不是很能理解和第一个的区别)



尝试了一下后，发现第一第二种都出现了一些莫名其妙的问题，最后在第三种方法下完美完成。

## 一些感想

//突然没灵感，待写