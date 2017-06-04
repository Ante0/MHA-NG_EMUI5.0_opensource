#!/bin/bash
#######################################################################
##
## description : generate config.h of libffmpeg.so
## 
#######################################################################

PREBUILT=../../../prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.9
PLATFORM=../../../out/target/product/hi3650
FF_CONFIG_OPTIONS="
    --target-os=linux
    --arch=arm 
    --enable-demuxers 
    --enable-decoders 
    --enable-decoder=flac    
    --disable-decoder=mjpeg	 
    --disable-stripping 
    --disable-ffmpeg 
    --disable-ffplay 
    --disable-ffserver 
    --disable-ffprobe 
    --disable-encoders 
    --disable-muxers 
    --enable-muxer=spdif
    --disable-devices 
    --enable-parsers
    --disable-bsfs
    --disable-protocols
    --enable-protocol=file 
    --enable-protocol=http
    --enable-protocol=https
    --disable-filters 
    --disable-avdevice 
    --enable-cross-compile 
    --cross-prefix=arm-eabi- 
    --disable-asm 
    --enable-neon 
    --enable-armv5te 
    --disable-postproc
    --disable-logging
"

FF_CONFIG_OPTIONS=`echo $FF_CONFIG_OPTIONS`

./configure ${FF_CONFIG_OPTIONS} \
    --extra-cflags="-fPIC -DANDROID -I../../../bionic/libc/include/ -I../../../bionic/libc/arch-arm/include -I../../../bionic/libc/kernel/common -I../../../bionic/libc/kernel/arch-arm" \
    --extra-ldflags="-Wl,-T,$PREBUILT/arm-linux-androideabi/lib/ldscripts/armelf_linux_eabi.x \
                     -Wl,-rpath-link=$PLATFORM/system/lib -L$PLATFORM/system/lib -nostdlib \
                     $PREBUILT/lib/gcc/arm-linux-androideabi/4.9.x-google/crtbegin.o \
                     $PREBUILT/lib/gcc/arm-linux-androideabi/4.9.x-google/crtend.o -lc -lm -ldl"

tmp_file=".tmpfile"
## remove invalid restrict define
sed 's/#define av_restrict restrict/#define av_restrict/' ./config.h >$tmp_file
mv $tmp_file ./config.h

## replace original FFMPEG_CONFIGURATION define with $FF_CONFIG_OPTIONS
sed '/^#define FFMPEG_CONFIGURATION/d' ./config.h >$tmp_file
mv $tmp_file ./config.h
total_line=`wc -l ./config.h | cut -d' ' -f 1`
tail_line=`expr $total_line - 3`
head -3 config.h > $tmp_file
echo "#define FFMPEG_CONFIGURATION \"${FF_CONFIG_OPTIONS}\"" >> $tmp_file
tail -$tail_line config.h >> $tmp_file
mv $tmp_file ./config.h

rm -f config.err

## rm BUILD_ROOT information
sed '/^BUILD_ROOT=/d' ./config.mak > $tmp_file
rm -f ./config.mak
mv $tmp_file ./config.mak

## rm amr-eabi-gcc
sed '/^CC=arm-eabi-gcc/d' ./config.mak > $tmp_file
rm -f ./config.mak
mv $tmp_file ./config.mak

## rm amr-eabi-gcc
sed '/^AS=arm-eabi-gcc/d' ./config.mak > $tmp_file
rm -f ./config.mak
mv $tmp_file ./config.mak


## rm amr-eabi-gcc
sed '/^LD=arm-eabi-gcc/d' ./config.mak > $tmp_file
rm -f ./config.mak
mv $tmp_file ./config.mak

## rm amr-eabi-gcc
sed '/^DEPCC=arm-eabi-gcc/d' ./config.mak > $tmp_file
rm -f ./config.mak
mv $tmp_file ./config.mak

sed -i 's/restrict restrict/restrict /g' config.h
sed -i 's/HAVE_LRINT 0/HAVE_LRINT 1/g' config.h
sed -i 's/HAVE_LRINTF 0/HAVE_LRINTF 1/g' config.h
sed -i 's/HAVE_ROUND 0/HAVE_ROUND 1/g' config.h
sed -i 's/HAVE_ROUNDF 0/HAVE_ROUNDF 1/g' config.h
sed -i 's/HAVE_TRUNC 0/HAVE_TRUNC 1/g' config.h
sed -i 's/HAVE_TRUNCF 0/HAVE_TRUNCF 1/g' config.h
sed -i 's/HAVE_CBRT 0/HAVE_CBRT 1/g' config.h
sed -i 's/HAVE_CBRTF 0/HAVE_CBRTF 1/g' config.h
sed -i 's/HAVE_ISINF 0/HAVE_ISINF 1/g' config.h
sed -i 's/HAVE_ISNAN 0/HAVE_ISNAN 1/g' config.h
sed -i 's/HAVE_SINF 0/HAVE_SINF 1/g' config.h
sed -i 's/HAVE_RINT 0/HAVE_RINT 1/g' config.h
sed -i 's/HAVE_COPYSIGN 0/HAVE_COPYSIGN 1/g' config.h
sed -i 's/HAVE_ERF 0/HAVE_ERF 1/g' config.h
sed -i 's/HAVE_ISFINITE 0/HAVE_ISFINITE 1/g' config.h
sed -i 's/HAVE_HYPOT 0/HAVE_HYPOT 1/g' config.h
sed -i 's/HAVE_GMTIME_R 0/HAVE_GMTIME_R 1/g' config.h
sed -i 's/HAVE_LOCALTIME_R 0/HAVE_LOCALTIME_R 1/g' config.h

sed -i '/getenv(x)/d' config.h
sed -i 's/HAVE_UNISTD_H 0/HAVE_UNISTD_H 1/g' config.h
sed -i 's/HAVE_MALLOC_H 0/HAVE_MALLOC_H 1/g' config.h
sed -i 's/HAVE_DOS_PATHS 0/HAVE_DOS_PATHS 1/g' config.h
sed -i 's/CONFIG_MJPEG_DECODER 0/CONFIG_MJPEG_DECODER 1/g' config.h

sed -i 's/HAVE_ARPA_INET_H 0/HAVE_ARPA_INET_H 1/g' config.h
sed -i 's/HAVE_POLL_H 0/HAVE_POLL_H 1/g' config.h
sed -i 's/HAVE_SOCKLEN_T 0/HAVE_SOCKLEN_T 1/g' config.h
sed -i 's/HAVE_STRUCT_ADDRINFO 0/HAVE_STRUCT_ADDRINFO 1/g' config.h
sed -i 's/HAVE_STRUCT_SOCKADDR_IN6 0/HAVE_STRUCT_SOCKADDR_IN6 1/g' config.h
sed -i 's/HAVE_STRUCT_SOCKADDR_STORAGE 0/HAVE_STRUCT_SOCKADDR_STORAGE 1/g' config.h
sed -i 's/CONFIG_NETWORK 0/CONFIG_NETWORK 1/g' config.h
sed -i 's/CONFIG_HTTP_PROTOCOL 0/CONFIG_HTTP_PROTOCOL 1/g' config.h
sed -i 's/CONFIG_HTTPPROXY_PROTOCOL 0/CONFIG_HTTPPROXY_PROTOCOL 1/g' config.h
sed -i 's/CONFIG_HTTPS_PROTOCOL 0/CONFIG_HTTPS_PROTOCOL 1/g' config.h
sed -i 's/CONFIG_TCP_PROTOCOL 0/CONFIG_TCP_PROTOCOL 1/g' config.h
sed -i 's/HAVE_STRUCT_ADDRINFO 0/HAVE_STRUCT_ADDRINFO 1/g' config.h

sed -i 's/!HAVE_ARPA_INET_H=yes/HAVE_ARPA_INET_H=yes/g' config.mak
sed -i 's/!HAVE_POLL_H=yes/HAVE_POLL_H=yes/g' config.mak
sed -i 's/!HAVE_SOCKLEN_T=yes/HAVE_SOCKLEN_T=yes/g' config.mak
sed -i 's/!HAVE_STRUCT_SOCKADDR_IN6=yes/HAVE_STRUCT_SOCKADDR_IN6=yes/g' config.mak
sed -i 's/!HAVE_STRUCT_SOCKADDR_STORAGE=yes/HAVE_STRUCT_SOCKADDR_STORAGE=yes/g' config.mak
sed -i 's/!CONFIG_NETWORK=yes/CONFIG_NETWORK=yes/g' config.mak
sed -i 's/!CONFIG_HTTP_PROTOCOL=yes/CONFIG_HTTP_PROTOCOL=yes/g' config.mak
sed -i 's/!CONFIG_HTTPPROXY_PROTOCOL=yes/CONFIG_HTTPPROXY_PROTOCOL=yes/g' config.mak
sed -i 's/!CONFIG_HTTPS_PROTOCOL=yes/CONFIG_HTTPS_PROTOCOL=yes/g' config.mak
sed -i 's/!CONFIG_TCP_PROTOCOL=yes/CONFIG_TCP_PROTOCOL=yes/g' config.mak
sed -i 's/!HAVE_STRUCT_ADDRINFO=yes/HAVE_STRUCT_ADDRINFO=yes/g' config.mak


sed -i 's/HAVE_PTHREADS 0/HAVE_PTHREADS 1/g' config.h
sed -i 's/HAVE_THREADS 0/HAVE_THREADS 1/g' config.h
sed -i 's/!HAVE_PTHREADS=yes/HAVE_PTHREADS=yes/g' config.mak
sed -i 's/!HAVE_THREADS=yes/HAVE_THREADS=yes/g' config.mak

## other work need to be done manually
cat <<!EOF
#####################################################
                    ****NOTICE**** 
You need to modify the file config.mak and delete 
all full path string in macro:
SRC_PATH, SRC_PATH_BARE, BUILD_ROOT, LDFLAGS.
Please refer to the old version of config.mak to 
check how to modify it.
#####################################################
!EOF
