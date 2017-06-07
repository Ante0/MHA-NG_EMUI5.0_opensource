#!/bin/sh
cd ~/Android/Kernel/Huawei/hi3660/
rm -rf out
mkdir out
cd ~/Android/Kernel/Huawei/hi3660/kernel
make mrproper
make CROSS_COMPILE=aarch64-linux-android- ARCH=arm64 O=~/Android/Kernel/Huawei/hi3660/out merge_hi3660_defconfig
make CROSS_COMPILE=aarch64-linux-android- ARCH=arm64 O=~/Android/Kernel/Huawei/hi3660/out kconfig
make CROSS_COMPILE=aarch64-linux-android- ARCH=arm64 O=~/Android/Kernel/Huawei/hi3660/out -j8
