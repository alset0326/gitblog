Title: Print Function in PWN
Date: 2018-04-24 15:17:41.501745
Modified: 2018-04-24 15:17:41.501745
Category: pwn
Tags: linux,pwn,print
Slug: print-function-in-pwn
Authors: Alset0326
Summary: Summary for print function in pwn

# read

```c
ssize_t read(int fildes, void *buf, size_t nbyte);
```

不一定读满`nbyte`，读到换行符`\n`就停止（`\n`会被读入）。

rop到read的时候可以忽略第三个参数。

# gets

```c
char * gets(char *str);
```

读到换行符`\n`为止，可以读入`\x00`。

# scanf

```c
int scanf(const char *format, ...);
```

读到换行符`\n`为止，可以读入`\x00`，注意格式参数。