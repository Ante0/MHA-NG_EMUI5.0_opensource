# MHA-NG_EMUI5.0_opensource
Huawei Mate 9 Kernel source (hi3660)

Steps taken from Readme_kernel.txt with some added steps:

1. How to Build
- get Toolchain
From android git server, codesourcery and etc ..
- aarch64-linux-android-4.9 
git clone https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9

- edit Makefile

edit CROSS_COMPILE to right toolchain path(You downloaded).

- Ex)   export PATH=$PATH:$(android platform directory you downloaded)/aarch64-linux-android-4.9/bin
- Ex)   export CROSS_COMPILE=aarch64-linux-android-
- Alternetively add path and cross_compile to ~/.bashrc

- Prepare:

$ mkdir ../out

$ make ARCH=arm64 O=../out merge_hi3660_defconfig

*Optional to set governor and other kernel settings*

$ make ARCH=arm64 O=../out menuconfig

- To compile:

$ make ARCH=arm64 O=../out -j8

2. Output files

Kernel : out/arch/arm64/boot/Image.gz
module : out/drivers/*/*.ko

3. How to Clean

$ make ARCH=arm64 distclean

$ rm -rf out
