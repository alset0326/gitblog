Title: How2Patchkit
Date: 2018-04-04 16:53:30.515707
Modified: 2018-04-04 16:53:30.515707
Category: pwn
Tags: patch,pwn
Slug: install-patchkit
Authors: Alset0326
Summary: How to use patchkit on osx

[TOC]

# 0. Install

Only work on python2. Install by venv.

```sh
git clone https://github.com/lunixbochs/patchkit.git
cd patchkit
virtualenv venv
source venv/bin/activate
pip2 install keystone-engine
pip2 install capstone
pip2 install unicorn
echo $(python -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")/capstone | xargs -n 1 cp `find . -name libcapstone.dylib`
echo $(python -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")/keystone | xargs -n 1 cp `find . -name libkeystone.dylib`
# find . -name libcapstone.dylib | xargs -I {} cp {} . # latest release
# export LIBCAPSTONE_PATH=$PWD # latest release
# find . -name libkeystone.dylib | xargs -I {} cp {} . # may not used
python2 -c "import capstone, keystone, unicorn; capstone.CS_ARCH_X86, unicorn.UC_ARCH_X86, keystone.KS_ARCH_X86; print 'works.'"
```

# 1. API

```python
# addr = search(data)
# addr = inject(*compile arg*) # 嵌入新代码
# hook(addr, new_addr) # 容易出错且不安全的hook
# patch(addr, *compile arg*) # 代码覆盖，需谨慎计算指令长度(原指令不会执行)
# insert(addr, *compile arg*) # 指令插入，在addr的位置插入指令(原指令仍会执行)
#
# *compile arg* is any of the following:
#   raw='data'
#   hex='0bfe'
#   asm='nop'
#   jmp=0xaddr
#   c='void func() { int a; a = 1; }' (only supported on inject, not patch)
#   sym=xxx
#   call=0xaa
```

