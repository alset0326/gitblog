Title: Set up kivy and buildozer environment
Date: 2018-03-08 09:23:39.347317
Modified: 2018-03-08 09:23:39.347317
Category: android
Tags: android,python
Slug: set-up-kivy-and-buildozer-environment
Authors: Alset0326
Summary: Tutorial for setting up environment for kivy and buildozer

After so many trys, I found that buildozer doesn't  support python3. So, fxxk it.

This tutorial is on ubuntu Desktop 17.10. Server version is not worked eithor because you cannot exec SDK manager to modify proxy.

Let's use python2 from the beginning.

## 0. make sure python2 installed

```
sudo apt install python python-dev python-pip
```

## 1. install cython

```
sudo -H pip install cython==0.25 # other versions may go wrong
```

## 2. install kivy

```
# Install necessary system packages
sudo apt install -y \
python-pip \
build-essential \
git \
ffmpeg \
libsdl2-dev \
libsdl2-image-dev \
libsdl2-mixer-dev \
libsdl2-ttf-dev \
libportmidi-dev \
libswscale-dev \
libavformat-dev \
libavcodec-dev \
zlib1g-dev

# Install gstreamer for audio, video (optional)
sudo apt install -y \
libgstreamer1.0 \
gstreamer1.0-plugins-base \
gstreamer1.0-plugins-good

# Note: Depending on your Linux version, you may receive error messages related to the “ffmpeg” package. In this scenario, use “libav-tools ” in place of “ffmpeg ” (above), or use a PPA (as shown below):
sudo add-apt-repository ppa:mc3man/trusty-media
sudo apt update
sudo apt install ffmpeg

sudo -H pip install kivy
```

## 3. install buildozer

```
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install build-essential ccache git libncurses5:i386 libstdc++6:i386 libgtk2.0-0:i386 libpangox-1.0-0:i386 libpangoxft-1.0-0:i386 libidn11:i386 default-jdk unzip zlib1g-dev zlib1g:i386
sudo -H pip install buildozer
```

## 4. install python-for-android

```
sudo -H pip install python-for-android
sudo apt install -y build-essential ccache git zlib1g-dev libncurses5:i386 libstdc++6:i386 zlib1g:i386 unzip ant ccache autoconf libtool
sudo apt install pkg-config
```

## 5. mkdir and coding

```
mkdir kivyproject
cd kivyproject
cat >main.py <EOF
from kivy.app import App
from kivy.uix.button import Label

class HelloApp(App):
def build(self):
return Label(text='Hello World')

if __name__=="__main__":
HelloApp().run()
EOF
python main.py
```

## 6. init buildozer project

```
buildozer init
```

## 7. build android project

```
buildozer android debug
```

## 8. Error `# Aidl not installed` occured

```
run ~/.buildozer/android/platform/android-sdk-20/tools/android
set proxy
close
```

## 9. build again

```
export ANDROIDSDK=$HOME/.buildozer/android/platform/android-sdk-20
export ANDROIDNDK=$HOME/.buildozer/android/platform/android-ndk-r9c
export ANDROIDAPI=19
export ANDROIDNDKVER=r9c
buildozer android debug
```

## 10. release build

set keystore

```
export P4A_RELEASE_KEYSTORE='absulote path of the keystore'
export P4A_RELEASE_KEYSTORE_PASSWD=
export P4A_RELEASE_KEYALIAS=
export P4A_RELEASE_KEYALIAS_PASSWD=
buildozer android release
```



## 11. fix bug

`cdef` error. Just modify it!

`getaddrinfo()` error. Don't use `proxychains` to run buildozer at last.

`X Error of failed request:  BadWindow (invalid Window parameter)` error. `multisamples` set to 0 in `~/.kivy/config.ini` , in Ubuntu 17.10.