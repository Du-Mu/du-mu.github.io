---
title: vim+tmux+zsh+Terminal-self-discipline-of-pwner
date: 2022-4-16
tags: 
- Pwn
- CTF

categories:
- CTF

toc: true # 是否启用内容索引
sidebar: none # 是否启用sidebar侧边栏，none：不启用
---





## vim+tmux+zsh+Terminal 你的pwn效率进阶方案

作为一个Pwner，需要频繁的接触命令行，特别是最近接触到了arm架构的pwn，需要一个窗口运行qemu，一个窗口跑脚本，一个窗口跑gdb，需要在几个窗口之间切换，同时我本身用sublime Text需要平凡切屏微调脚本，所以决定配置vim+tmux+zsh+terminal，实现一个兼顾美观和效率的pwn setup

本文主要基于ubuntu20系统



## Terminal

terminal是一个终端模拟器，其实终端模拟器是什么无所谓，只是terminal我看着比较美观，再加上我的ubuntu桌面是gnome桌面，自带gnome terminal，所以我就使用terminal,  对于colors部分，背景改成灰/黑色，不透明度调到20%-30%，不影响terminal内文字的观看，同时能够看到后面的背景就行。



## zsh配置方案

因为后面一些配置，在有了zsh后方便一些，所以先配置zsh

#### 安装

- 安装zsh

  ```bash
  sudo apt-get install zsh
  ```

- 替换为默认shell

  ```bash
  sudo chsh -s /bin/zsh
  ```

  - tips: 这个命令需要重启shell(or 系统，我记不清了，先关了再开终端试一下，没有生效再重启系统吧)才能生效，所以不要像我一样以为这个命令失效了，反复发呆

- 安装oh-my-zsh
  oh-my-zsh是github上的一个开源项目，可以便捷进行zsh的插件、主题管理
  You can find [official document](https://github.com/ohmyzsh/ohmyzsh) here

  - 官方文件提供的安装方案如下
    使用curl连接。
    如果你没有配置代理或者改hosts的话，你大概率是安装不了的，可以使用一下国内镜像:

    ```bash
    sh -c "$(curl -fsSL https://gitee.com/mirrors/oh-my-zsh/raw/master/tools/install.sh)"
    ```

    需要先安装curl。由于我本人没有尝试过这个镜像，我本人是通过改hosts安装的，raw.fithubsercontent.con好像还没有完全屏蔽，改hosts仍然可行，如果安装失败的话，可以私我

- 改配置文件
  这个阶段，可以把文件管理器改为显示隐藏文件
  如果你上一步安装完成，在主文件夹(也就是桌面软件的home目录，一般用~表示)会出现一个.zshrc的文件，这是zsh的配置文件，要用sudo vim写入，安装oh-my-zsh后

  ```bash
  sudo vim ~/.zshrc
  ```

  打开后应该有大量注释后文本，帮助你修改配置文本
  

​		我就把ZSH_THEME改成了ys，如果有需要，可以加一些插件，改一些style，因为oh-my-zsh		自带了相当多插件，怎么引入可以查看官方文档

​		可以使用alias命令为命令添加别名，方便使用
​			

- 使配置文件生效

  ```bash
  source ~/.zshrc
  ```

  zsh命令行使用此命令，使配置文件生效

#### 使用

zsh自带了许多非常好用的功能，自动补全，智能高亮，这里我就不教怎么使用了，可以参考
[为什么说 zsh 是 shell 中的极品？ - 知乎 (zhihu.com)](https://www.zhihu.com/question/21418449)





## tmux

tmux是一个终端复用软件，多用于用于分屏，在shell 键入tmux就进入了tmux，具体使用快捷键和命令请百度，此处不教怎么使用
一个tips是tmux中的ctrl+b是一个进入命令模式的键，类似于vim的esc，所以很多快捷键写的ctrl+B+xx，意思是先按下ctrl+b，再按其他键



#### 配置

依旧在主文件目录下新建一个 .tmux.conf配置文件

具体配置可以参考: https://github.com/YashdalfTheGray/dotfiles/blob/master/macos/.tmux.conf

最后这一部分就是加入插件的，自动帮你完成了插件安装

复制这个配置就行，然后在shell进入tmux
键入:

```bash
tmux source-file ~/.tmux.conf
```



## vim

如果说其他插件只是影响美观的，vim不装插件真的是跟装插件是两种软件，

首先确认你安装了较新版本的vim

#### 插件安装

安装[vim-plug](https://github.com/junegunn/vim-plug#installation)

本人亲测官网安装命令路径不咋好用，一个是不挂代理连不上，一个式官网linux的安装路径无效，我们来手动安装。

- 首先复制官网的plug.vim文件
- （如果没有）在本地主文件夹新建一个.vim文件夹，里面兴建一个autoload文件夹，将plug.vim放入
- 再在.vim中新建一个plug目录

#### 配置

主文件夹新建.vimrc文件

配置文件参考https://github.com/YashdalfTheGray/dotfiles/blob/master/macos/.vimrc

将此处改为~/.vim/plug

打开vim，按esc命令进入命令模式, 输入:  ，再用source命令导入.vimrc

再在命令模式输入:PlugInstall，插件安装完成，reload，整体配置成功，具体使用网上资料很多，不再赘述