---
title: Source-Code-Analysis-of-AFL-[1]-code-instrumentation
date: 2022-7-1
tags: 
- Pwn
- Fuzz

categories:
- Fuzz

toc: true # 是否启用内容索引
sidebar: none # 是否启用sidebar侧边栏，none：不启用zh
---







AFL源代码阅读[1]， 主要包含对afl-gcc.c 和afl-as.c的流程分析，也即插桩的过程。而插桩后进程间通信的过程相对复杂，将在后面单独分析。

# 0x1 文件依赖结构

基本文件结构: 

- **afl-as.c、afl-as.h、afl-gcc.c** :普通的代码插桩
- **afl-fuzz.c** 
  fuzzer实现代码 核心
- llvm_mode 
  llvm模式进行插桩，仅clang适用
- qemu_mode 
  qemu模式插桩，针对二进制文件
- libdislocator 
  简单的内存检测工具
- libtokencap 
  语法关键字提取并生成字典文件
- afl-analyze.c 
  对测试样例的字典进行分析
- afl_cmin 
  对fuzzing用到的语料库进行精简操作
- afl_tmin.c 
  对fuzzing中用到的测试用例进行最小化操作
- afl-gotcpu.c 
  统计cpu占用率
- afl-plot 
  绘制报告图标
- afl-showmap.c 
  打印目标程序fuzz后的tuple信息
- afl-whatsup 
  并行fuzz结果统计
- alloc-inl.h 
  定义带检测功能的内存分配和释放操作
- Hash.h 
  hash函数的实现和定义
- test-instr.c 
  测试的目标程序
- dos
  相关说明文档
- experimental 
  一些新特性的试验研究



# 0x2 基本模块分析

## (1)代码插桩

基本流程: afl-gcc  -->  afl-as 

### afl-gcc.c

#### 0x1.基础变量

| name                       | meaning                            |
| -------------------------- | ---------------------------------- |
| static u8*  as_path        | *Path to the AFL 'as' wrapper*     |
| static u8** cc_params      | *Parameters passed to the real CC* |
| static u32  cc_par_cnt = 1 | *Param count, including argv0*     |
| static u8  be_quiet        | *Quiet mode*                       |
| static u8 clang_mode       | *Invoked as afl-clang?*            |



#### 0x2.main函数核心流程

a.检查是否是静默模式

```c
if (isatty(2) && !getenv("AFL_QUIET")) {

SAYF(cCYA "afl-cc " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

} else be_quiet = 1;
```

b. 检查参数是否完备

```c
if (argc < 2) {

SAYF("\n"
     "This is a helper application for afl-fuzz. It serves as a drop-in replacement\n"
     "for gcc or clang, letting you recompile third-party code with the required\n"
     "runtime instrumentation. A common use pattern would be one of the following:\n\n"

     "  CC=%s/afl-gcc ./configure\n"
     "  CXX=%s/afl-g++ ./configure\n\n"

     "You can specify custom next-stage toolchain via AFL_CC, AFL_CXX, and AFL_AS.\n"
     "Setting AFL_HARDEN enables hardening optimizations in the compiled code.\n\n",
     BIN_PATH, BIN_PATH);

exit(1);

}
```

c. 找到as路径

```c
find_as(argv[0]);
```

d. 对于参数进行编辑

```c
edit_params(argc, argv);
```

e. 调用

```c
execvp(cc_params[0], (char**)cc_params);
```

#### 0x3.edit_params()

edit_params()被调用于编辑各种参数.  最后传递给真正的编译器(gcc / clang)，对于as的路径进行处理，使之调用到as的封装, afl-as。

//主要是一些细节方面的，之后遇到了再来仔细查看

#### 0x4. find_as()

通过环境变量AFL_PATH找到封装的as的路径

//同样主要是细节方面

### afl-as.c

#### 0x1. 基础变量

| NAME                         | MEANING                               |
| ---------------------------- | ------------------------------------- |
| static u8** as_params        | *Parameters passed to the real 'as'*  |
| static u8*  input_file       | *Originally specified input file*     |
| static u8*  modified_file    | *Instrumented file for the real 'as'* |
| static u32  inst_ratio = 100 | *Instrumentation probability (%)*     |



#### 0x2. main函数主要逻辑

a. 同上，对各种模式的判断(这里和上面都对于APPLE都有不同，因为没接触过apple，暂且记下)

```c
clang_mode = !!getenv(CLANG_ENV_VAR);

if (isatty(2) && !getenv("AFL_QUIET")) {

SAYF(cCYA "afl-as " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

} else be_quiet = 1;
```



b. 获取随机数种子

```c
gettimeofday(&tv, &tz);

rand_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();

srandom(rand_seed);
```

c. 编辑参数

```c
edit_params(argc, argv);
```

d. 根据各种环境变量进行相关配置

```c
  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || inst_ratio > 100) 
      FATAL("Bad value of AFL_INST_RATIO (must be between 0 and 100)");

  }
// 代码插桩率的设置

  if (getenv(AS_LOOP_ENV_VAR))
    FATAL("Endless loop when calling 'as' (remove '.' from your PATH)");

  setenv(AS_LOOP_ENV_VAR, "1", 1);

  /* When compiling with ASAN, we don't have a particularly elegant way to skip
     ASAN-specific branches. But we can probabilistically compensate for
     that... */

  if (getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) {
    sanitizer = 1;
    inst_ratio /= 3;
  }
```

e. 代码插桩

```c
if (!just_version) add_instrumentation();
```

f. 调用as

```c
  if (!(pid = fork())) {

    execvp(as_params[0], (char**)as_params);
    FATAL("Oops, failed to execute '%s' - check your PATH", as_params[0]);

  }

  if (pid < 0) PFATAL("fork() failed");

  if (waitpid(pid, &status, 0) <= 0) PFATAL("waitpid() failed");

  if (!getenv("AFL_KEEP_ASSEMBLY")) unlink(modified_file);

  exit(WEXITSTATUS(status));
```



#### 0x3. add_instrumentation()代码插桩

##### a. 主要流程

a-1. 打开输入文件和更改后的输出文件

```c
  if (input_file) {

    inf = fopen(input_file, "r");
    if (!inf) PFATAL("Unable to read '%s'", input_file);

  } else inf = stdin;

  outfd = open(modified_file, O_WRONLY | O_EXCL | O_CREAT, 0600);

  if (outfd < 0) PFATAL("Unable to write to '%s'", modified_file);

  outf = fdopen(outfd, "w");

  if (!outf) PFATAL("fdopen() failed");  
```

a-2. 读取每一行到line数组

```c
  while (fgets(line, MAX_LINE, inf)) {//这个括号匹配到最后

    /* In some cases, we want to defer writing the instrumentation trampoline
       until after all the labels, macros, comments, etc. If we're in this
       mode, and if the line starts with a tab followed by a character, dump
       the trampoline now. */

    if (!pass_thru && !skip_intel && !skip_app && !skip_csect && instr_ok &&
        instrument_next && line[0] == '\t' && isalpha(line[1])) {

      fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32,
              R(MAP_SIZE));
// 这里是defered mode插桩执行语句
      instrument_next = 0;
      ins_lines++;

    }
    fputs(line, outf);
```



a-3. 对于插桩的核心处理，定位有跳转语句， 设置flag

```c
    if (pass_thru) continue;

    /* All right, this is where the actual fun begins. For one, we only want to
       instrument the .text section. So, let's keep track of that in processed
       files - and let's set instr_ok accordingly. */

    if (line[0] == '\t' && line[1] == '.') {

      /* OpenBSD puts jump tables directly inline with the code, which is
         a bit annoying. They use a specific format of p2align directives
         around them, so we use that as a signal. */
// 匹配文件中声明的段
      if (!clang_mode && instr_ok && !strncmp(line + 2, "p2align ", 8) &&
          isdigit(line[10]) && line[11] == '\n') skip_next_label = 1;

      if (!strncmp(line + 2, "text\n", 5) ||
          !strncmp(line + 2, "section\t.text", 13) ||
          !strncmp(line + 2, "section\t__TEXT,__text", 21) ||
          !strncmp(line + 2, "section __TEXT,__text", 21)) {
        instr_ok = 1;
        continue; 
        // 尝试匹配.text，匹配成功设置标志位为1(即可以插桩)
        // 进入下一次迭代
      }

      if (!strncmp(line + 2, "section\t", 8) ||
          !strncmp(line + 2, "section ", 8) ||
          !strncmp(line + 2, "bss\n", 4) ||
          !strncmp(line + 2, "data\n", 5)) {
        instr_ok = 0;
        continue;
      }

    }

    /* Detect off-flavor assembly (rare, happens in gdb). When this is
       encountered, we set skip_csect until the opposite directive is
       seen, and we do not instrument. */

    if (strstr(line, ".code")) {

      if (strstr(line, ".code32")) skip_csect = use_64bit;
      if (strstr(line, ".code64")) skip_csect = !use_64bit;

    }

    /* Detect syntax changes, as could happen with hand-written assembly.
       Skip Intel blocks, resume instrumentation when back to AT&T. */

    if (strstr(line, ".intel_syntax")) skip_intel = 1;
    if (strstr(line, ".att_syntax")) skip_intel = 0;

    /* Detect and skip ad-hoc __asm__ blocks, likewise skipping them. */

    if (line[0] == '#' || line[1] == '#') {

      if (strstr(line, "#APP")) skip_app = 1;
      if (strstr(line, "#NO_APP")) skip_app = 0;

    }

    /* If we're in the right mood for instrumenting, check for function
       names or conditional labels. This is a bit messy, but in essence,
       we want to catch:

         ^main:      - function entry point (always instrumented)
         ^.L0:       - GCC branch label
         ^.LBB0_0:   - clang branch label (but only in clang mode)
         ^\tjnz foo  - conditional branches

       ...but not:

         ^# BB#0:    - clang comments
         ^ # BB#0:   - ditto
         ^.Ltmp0:    - clang non-branch labels
         ^.LC0       - GCC non-branch labels
         ^.LBB0_0:   - ditto (when in GCC mode)
         ^\tjmp foo  - non-conditional jumps

       Additionally, clang and GCC on MacOS X follow a different convention
       with no leading dots on labels, hence the weird maze of #ifdefs
       later on.

     */

    if (skip_intel || skip_app || skip_csect || !instr_ok ||
        line[0] == '#' || line[0] == ' ') continue;

    /* Conditional branch instruction (jnz, etc). We append the instrumentation
       right after the branch (to instrument the not-taken path) and at the
       branch destination label (handled later on). */

    if (line[0] == '\t') {

      if (line[1] == 'j' && line[2] != 'm' && R(100) < inst_ratio) {

        fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32,
                R(MAP_SIZE));

        ins_lines++;

      }
// 捕捉跳转标志，调用随机数函数，选择是否进行插桩
      continue;

    }

    /* Label of some sort. This may be a branch destination, but we need to
       tread carefully and account for several different formatting
       conventions. */

#ifdef __APPLE__

    /* Apple: L<whatever><digit>: */

    if ((colon_pos = strstr(line, ":"))) {

      if (line[0] == 'L' && isdigit(*(colon_pos - 1))) {

#else

    /* Everybody else: .L<whatever>: */

    if (strstr(line, ":")) {

      if (line[0] == '.') {

#endif /* __APPLE__ */

        /* .L0: or LBB0_0: style jump destination */

#ifdef __APPLE__

        /* Apple: L<num> / LBB<num> */

        if ((isdigit(line[1]) || (clang_mode && !strncmp(line, "LBB", 3)))
            && R(100) < inst_ratio) {

#else

        /* Apple: .L<num> / .LBB<num> */

        if ((isdigit(line[2]) || (clang_mode && !strncmp(line + 1, "LBB", 3)))
            && R(100) < inst_ratio) {

#endif /* __APPLE__ */

          /* An optimization is possible here by adding the code only if the
             label is mentioned in the code in contexts other than call / jmp.
             That said, this complicates the code by requiring two-pass
             processing (messy with stdin), and results in a speed gain
             typically under 10%, because compilers are generally pretty good
             about not generating spurious intra-function jumps.

             We use deferred output chiefly to avoid disrupting
             .Lfunc_begin0-style exception handling calculations (a problem on
             MacOS X). */

          if (!skip_next_label) instrument_next = 1; else skip_next_label = 0;

        }

      } else {

        /* Function label (always instrumented, deferred mode). */

        instrument_next = 1;
    
      }

    }

  }
```

##### b. trampoline插桩代码

这些部分的声明在afl-as.h

###### b-1 .bss段变量

- `__afl_area_ptr`：共享内存地址；
- `__afl_prev_loc`：上一个插桩位置（id为R(100)随机数的值）；
- `__afl_fork_pid`：由fork产生的子进程的pid；
- `__afl_temp`：缓冲区；
- `__afl_setup_failure`：标志位，如果置位则直接退出；
- `__afl_global_area_ptr`：全局指针。

###### b-1.trampoline_fmt_64/32

```assembly
static const u8* trampoline_fmt_32 =

  "\n"
  "/* --- AFL TRAMPOLINE (32-BIT) --- */\n"
  "\n"
  ".align 4\n"
  "\n"
  "leal -16(%%esp), %%esp\n"
  "movl %%edi,  0(%%esp)\n"
  "movl %%edx,  4(%%esp)\n"
  "movl %%ecx,  8(%%esp)\n"
  "movl %%eax, 12(%%esp)\n"
  "movl $0x%08x, %%ecx\n"  //想ecx存入随机桩代码
  "call __afl_maybe_log\n" //调用__afl_maybe_log
  "movl 12(%%esp), %%eax\n"
  "movl  8(%%esp), %%ecx\n"
  "movl  4(%%esp), %%edx\n"
  "movl  0(%%esp), %%edi\n"
  "leal 16(%%esp), %%esp\n"
  "\n"
  "/* --- END --- */\n"
  "\n";

static const u8* trampoline_fmt_64 =

  "\n"
  "/* --- AFL TRAMPOLINE (64-BIT) --- */\n"
  "\n"
  ".align 4\n"
  "\n"
  "leaq -(128+24)(%%rsp), %%rsp\n"
  "movq %%rdx,  0(%%rsp)\n"
  "movq %%rcx,  8(%%rsp)\n"
  "movq %%rax, 16(%%rsp)\n"
  "movq $0x%08x, %%rcx\n"
  "call __afl_maybe_log\n"
  "movq 16(%%rsp), %%rax\n"
  "movq  8(%%rsp), %%rcx\n"
  "movq  0(%%rsp), %%rdx\n"
  "leaq (128+24)(%%rsp), %%rsp\n"
  "\n"
  "/* --- END --- */\n"
  "\n";

```

主要功能: 

- 保存 `rdx`、 `rcx` 、`rax` 寄存器
- 将 `rcx` 的值设置为 `fprintf()` 函数将要打印的变量内容
- 调用 `__afl_maybe_log` 函数
- 恢复寄存器

###### b-2. __afl_maybe_log

```c
  "__afl_maybe_log:\n"
  "\n"
  "  lahf\n"   // 对于标志位的处理
  "  seto %al\n" 
  "\n"
  "  /* Check if SHM region is already mapped. */\n"
  "\n"
  "  movl  __afl_area_ptr, %edx\n"
  "  testl %edx, %edx\n"    //判断__afl_area_ptr是否为NULL
  "  je    __afl_setup\n"	//为NULL则跳转设置
  "\n"
```

