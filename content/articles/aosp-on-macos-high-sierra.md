Title: AOSP on macos high Sierra
Date: 2018-03-08 08:50:53.066376
Modified: 2018-03-08 08:50:53.066376
Category: android
Tags: aosp,android
Slug: aosp-on-macos-high-sierra
Authors: Alset0326
Summary: AOSP issues on macos high Sierra

## bison error

> https://juejin.im/post/5a3d2104f265da4311206809

On macos high sierra bison needs a patch. Or may cause errors like

```
[  0% 391/82033] //external/selinux/checkpolicy:checkpolicy yacc policy_parse.y [darwin]
FAILED: out/soong/.intermediates/external/selinux/checkpolicy/checkpolicy/darwin_x86_64/gen/yacc/external/selinux/checkpolicy/policy_parse.c out/soong/.intermediates/external/selinux/checkpolicy/checkpolicy/darwin_x86_64/gen/yacc/external/selinux/checkpolicy/policy_parse.h
BISON_PKGDATADIR=external/bison/data prebuilts/misc/darwin-x86/bison/bison -d  --defines=out/soong/.intermediates/external/selinux/checkpolicy/checkpolicy/darwin_x86_64/gen/yacc/external/selinux/checkpolicy/policy_parse.h -o out/soong/.intermediates/external/selinux/checkpolicy/checkpolicy/darwin_x86_64/gen/yacc/external/selinux/checkpolicy/policy_parse.c external/selinux/checkpolicy/policy_parse.y
ninja: build stopped: subcommand failed.
08:09:51 ninja failed with: exit status 1
```

solusion:

```
//https://groups.google.com/forum/#!topic/android-building/D1-c5lZ9Oco

I was able to fix this issue with the following steps:

Patch bison fix for High Sierra and build bison:

cd /Volumes/AOSP/external/bison

git cherry-pick c0c852bd6fe462b148475476d9124fd740eba160

mm

Replace prebuilt bison binary with patched binary

cp /Volumes/AOSP/out/host/darwin-x86/bin/bison /Volumes/AOSP/prebuilts/misc/darwin-x86/bison/
```

## jack error

```bash
Internal unknown error (415), try 'jack-diagnose' or see Jack server log
```

download and compile curl 7.55.1