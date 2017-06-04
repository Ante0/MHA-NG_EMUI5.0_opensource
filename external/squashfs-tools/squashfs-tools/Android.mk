# Copyright (C) 2015 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

# squashfs-tools depends on Linux Kernel specific headers (e.g. sysinfo.h).
LOCAL_MODULE_HOST_OS := linux darwin

# The LOCAL_MODULE name is referenced by the code. Don't change it.
LOCAL_MODULE := mksquashfs

LOCAL_SRC_FILES := \
    mksquashfs.c \
    read_fs.c \
    action.c \
    swap.c \
    pseudo.c \
    compressor.c \
    sort.c \
    progressbar.c \
    read_file.c \
    info.c \
    restore.c \
    process_fragments.c \
    caches-queues-lists.c \
    xattr.c \
    read_xattrs.c \
    gzip_wrapper.c \
    android.c \
    lz4_wrapper.c

LOCAL_CFLAGS := -I -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_GNU_SOURCE -Wall \
                -DCOMP_DEFAULT="\"lz4\"" -DGZIP_SUPPORT -DLZ4_SUPPORT -DXATTR_SUPPORT -DXATTR_DEFAULT

LOCAL_LDLIBS := -lpthread -lm -lz

LOCAL_SHARED_LIBRARIES := libcutils libselinux
LOCAL_STATIC_LIBRARIES := liblz4

include $(BUILD_HOST_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE = unsquashfs
LOCAL_LDLIBS := -lpthread -lm -lz
LOCAL_SHARED_LIBRARIES := libcutils libselinux
LOCAL_STATIC_LIBRARIES := liblz4
LOCAL_MODULE_TAGS := optional

unsquashfs_files = unsquashfs.c unsquash-1.c unsquash-2.c unsquash-3.c \
		  	unsquash-4.c swap.c compressor.c unsquashfs_info.c \
			unsquashfs_xattr.c read_xattrs.c \
			gzip_wrapper.c android.c lz4_wrapper.c

LOCAL_CFLAGS := -I -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_GNU_SOURCE -Wall \
                -DCOMP_DEFAULT="\"lz4\"" -DGZIP_SUPPORT -DLZ4_SUPPORT -DXATTR_SUPPORT -DXATTR_DEFAULT \
		-DSQUASHFS_TRACE

LOCAL_SRC_FILES := $(unsquashfs_files) $(swap_files) \
                   $(read_file_files) \
                   $(read_xattrs_files) $(gzip_wrapper_files) $(android_files) \
                   $(lz4_wrapper_files)

include $(BUILD_HOST_EXECUTABLE)
