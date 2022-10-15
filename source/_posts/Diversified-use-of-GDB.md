---
title: Diversified-use-of-GDB
date: 2022-4-20
tags: 
- Pwn
- CTF

categories:
- CTF

toc: true # 是否启用内容索引
sidebar: none # 是否启用sidebar侧边栏，none：不启用
---





| 命令名称    | 命令缩写  | 命令说明                                         |
| ------------- | ----------- | -------------------------------------------------- |
| run         | r         | 运行一个待调试的程序                             |
| continue    | c         | 让暂停的程序继续运行                             |
| next        | n         | 运行到下一行                                     |
| step        | s         | 单步执行，遇到函数会进入                         |
| until       | u         | 运行到指定行停下来                               |
| finish      | fi        | 结束当前调用函数，回到上一层调用函数处           |
| return      | return    | 结束当前调用函数并返回指定值，到上一层函数调用处 |
| jump        | j         | 将当前程序执行流跳转到指定行或地址               |
| print       | p         | 打印变量或寄存器值                               |
| backtrace   | bt        | 查看当前线程的调用堆栈                           |
| frame       | f         | 切换到当前调用线程的指定堆栈                     |
| thread      | thread    | 切换到指定线程                                   |
| break       | b         | 添加断点                                         |
| tbreak      | tb        | 添加临时断点                                     |
| delete      | d         | 删除断点                                         |
| enable      | enable    | 启用某个断点                                     |
| disable     | disable   | 禁用某个断点                                     |
| watch       | watch     | 监视某一个变量或内存地址的值是否发生变化         |
| list        | l         | 显示源码                                         |
| info        | i         | 查看断点 / 线程等信息                            |
| ptype       | ptype     | 查看变量类型                                     |
| disassemble | dis       | 查看汇编代码                                     |
| set args    | set args  | 设置程序启动命令行参数                           |
| show args   | show args | 查看设置的命令行参数                             |

## 调试无符号程序
1. run
   先将程序运行
2. b \* \_\_libc\_start\_main
   因为没有main函数的符号，所以只能在libc库中的start函数下断点
3. 可以愉快的调试了

## 调试带参数的程序
set args \[arg1\] \[arg2\] ···

通过此命令设置命令行参数

## 分屏调试
- 安装tmux
- 使用[[tmux]]分屏
- [[ps]]获取进程pid
- gdb启动
- attach 进程
#### 错误解决
- Operation not permitted
  ubuntu特性：
  系统为安全考虑，默认阻止一个进程检查和修改另一个进程，除非前者是后者的父进程。
  阻止操作由 **ptrace_scope** 实现，当 **ptrace_scope** = 1 时，gdb 在调试运行中的进程时，会产生如上报错

- 解决： 
  查看 ptrace_scope ：cat /proc/sys/kernel/yama/ptrace_scope
  修改 ptrace_scope ：vi /etc/sysctl.d/10-ptrace.conf（修改为 kernel.yama.ptrace_scope = 0）
  生效 ：sysctl -p /etc/sysctl.d/10-ptrace.conf （不行就重启）
  重启 ：reboot


## gdb attach 其他架构进程
- pwntools 将程序开在本地架构其他端口上
	  sh = process(["qemu-aarch64", "-g", "1234", "./arm"])
- 脚本中pause()等待attch
- gdb-multiarch  打开调试程序
- target  remote localhost : 1234
	  attach到对应端口的程序上

## gdb 调试与程序输出的分离
- 先在一个终端窗口使用tty命令，得到其文件描述符
- 再在另一个窗口使用gdb 启动要调试的程序
- gdb中用tty "文件描述符" 将输出重定向
- run