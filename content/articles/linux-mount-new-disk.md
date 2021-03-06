Title: Linux Mount New Disk
Date: 2018-03-16 16:20:47.645128
Modified: 2018-03-16 16:20:47.645128
Category: linux
Tags: linux
Slug: linux-mount-new-disk
Authors: Alset0326
Summary: How to mount new disk on Linux

## 1. Check new disk status

[root@db1 /]# `fdisk -l`

Disk /dev/sda: 10.7 GB, 10737418240 bytes

255 heads, 63 sectors/track, 1305 cylinders

Units = cylinders of 16065 * 512 = 8225280 bytes

   Device Boot      Start         End      Blocks   Id  System

/dev/sda1   *         151        1305     9277537+  83  Linux

/dev/sda2               1         150     1204843+  82  Linux swap

Partition table entries are not in disk order

**Disk /dev/sdb: 5368 MB, 5368709120 bytes**

255 heads, 63 sectors/track, 652 cylinders

Units = cylinders of 16065 * 512 = 8225280 bytes

   Device Boot      Start         End      Blocks   Id  System

### new disk `/dev/sdb` occured.

## 2. Partition `/dev/sdb` with `frisk` 

[root@db1 /]# `fdisk /dev/sdb`

Command (m for help): n

Command action

   e   extended

   p   primary partition (1-4)

**p**

Partition number (1-4): **1**

First cylinder (1-652, default 1):

Using default value 1

Last cylinder or +size or +sizeM or +sizeK (1-652, default 652):

Using default value 652

Command (m for help): **w**

The partition table has been altered!

Calling ioctl() to re-read partition table.

Syncing disks.

### Check the partition again. A new partition occurred, `/dev/sdb1`. The number 1 is we assigned above.

[root@db1 /]# `fdisk -l`

Disk /dev/sda: 10.7 GB, 10737418240 bytes

255 heads, 63 sectors/track, 1305 cylinders

Units = cylinders of 16065 * 512 = 8225280 bytes

   Device Boot      Start         End      Blocks   Id  System

/dev/sda1   *         151        1305     9277537+  83  Linux

/dev/sda2               1         150     1204843+  82  Linux swap

Partition table entries are not in disk order

Disk /dev/sdb: 5368 MB, 5368709120 bytes

255 heads, 63 sectors/track, 652 cylinders

Units = cylinders of 16065 * 512 = 8225280 bytes 

   Device Boot      Start         End      Blocks   Id  System

**/dev/sdb1               1         652     5237158+  83  Linux**

[root@db1 /]#

### If we cannot see partitions in `/proc/partitions`, Use command parprobe to refresh

[root@web1 ~]`# cat /proc/partitions  major minor  #blocks  name`
   8     0  175825944 sda    8     1    1020096 sda1    8     2   30716280 sda2    8     3    8193150 sda3 [root@web1 ~]# partprobe /dev/sda 

[root@web1 ~]`# cat /proc/partitions  major minor  #blocks  name`
   8     0  175825944 sda    8     1    1020096 sda1    8     2   30716280 sda2    8     3    8193150 sda3    8     4  135893835 sda4 [root@web1 ~]# 

## 3. Format partition

[root@db1 /]# `mkfs -t ext4 /dev/sdb1`

mke2fs 1.35 (28-Feb-2004)

Filesystem label=

OS type: Linux

Block size=4096 (log=2)

Fragment size=4096 (log=2)

655360 inodes, 1309289 blocks

65464 blocks (5.00%) reserved for the super user

First data block=0

Maximum filesystem blocks=1342177280

40 block groups

32768 blocks per group, 32768 fragments per group

16384 inodes per group

Superblock backups stored on blocks:

​        32768, 98304, 163840, 229376, 294912, 819200, 884736



Writing inode tables: done

Creating journal (8192 blocks): done

Writing superblocks and filesystem accounting information: done

 

This filesystem will be automatically checked every 30 mounts or

180 days, whichever comes first.  Use tune2fs -c or -i to override.

## 4. mkdir and mount

[root@db1 /]# `ls`

backup  dev   initrd      media  opt   sbin     sys       usr

bin     etc   lib         misc   proc  selinux  tftpboot  var

boot    home  lost+found  mnt    root  srv      tmp

[root@db1 /]# `mkdir /u01`

[root@db1 /]# `ls`

backup  dev   initrd      media  opt   sbin     sys       u01

bin     etc   lib         misc   proc  selinux  tftpboot  usr

boot    home  lost+found  mnt    root  srv      tmp       var

[root@db1 /]# `mount /dev/sdb1 /u01`

## 5. Check if mount successful

[root@db1 /]# `df -k`

Filesystem           1K-blocks      Used Available Use% Mounted on

/dev/sda1              9131772   7066884   1601012  82% /

none                    454256         0    454256   0% /dev/shm

**/dev/sdb1              5154852     43040   4849956   1% /backup**

## 6. set startup on boot


[root@db1 /]# `vi /etc/fstab`

\# This file is edited by fstab-sync - see 'man fstab-sync' for details

LABEL=/                 /                       ext3    defaults        1 1

none                    /dev/pts                devpts  gid=5,mode=620  0 0

none                    /dev/shm                tmpfs   defaults        0 0

none                    /proc                   proc    defaults        0 0

none                    /sys                    sysfs   defaults        0 0

LABEL=SWAP-sda2         swap                    swap    defaults        0 0

**/dev/sdb1               /u01                 ext3    defaults        0 0**

/dev/hdc                /media/cdrom            auto    pamconsole,exec,noauto,m

anaged 0 0

/dev/fd0                /media/floppy           auto    pamconsole,exec,noauto,m

anaged 0 0

 

