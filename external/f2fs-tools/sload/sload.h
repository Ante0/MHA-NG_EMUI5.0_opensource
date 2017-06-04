/**
 * sload.h
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef _SLOAD_H_
#define _SLOAD_H_

#include "f2fs.h"

#define BLOCK_SZ		4096

struct dentry {
    char *path;
    char *full_path;
    const char *filename;
    char *link;
    unsigned long size;
    u8 file_type;
    u16 mode;
    u16 uid;
    u16 gid;
    u32 *inode;
    u32 mtime;
    char *secon;
    uint64_t capabilities;
    nid_t ino;
};

/* checkpoint.c */
extern int f2fs_do_mount(struct f2fs_sb_info *sbi);
extern void f2fs_do_umount(struct f2fs_sb_info *sbi);
extern int f2fs_do_checkpoint(struct f2fs_sb_info *sbi);

extern int f2fs_mkdir(struct f2fs_sb_info *sbi, nid_t pino, umode_t mode,
                const char *name, int len, u16 uid, u16 gid, u32 mtime);
extern int f2fs_create(struct f2fs_sb_info *sbi, nid_t pino, umode_t mode,
                const char *name, int len, u16 uid, u16 gid, u32 mtime);
extern int f2fs_write(struct f2fs_sb_info *sbi, nid_t ino, void * buffer,
				u64 count, pgoff_t offset);
extern int f2fs_setxattr(struct f2fs_sb_info *sbi, nid_t ino, int index,
				const char *name, const void *value, size_t size, int flags);
extern int f2fs_symlink(struct f2fs_sb_info *sbi, nid_t pino, umode_t mode,
				const char *name, int len, u16 uid, u16 gid,
				u32 mtime, const char *symname);

extern int inode_set_selinux(struct f2fs_sb_info *sbi, u32 inode_num, const char *secon);

#endif /* _SLOAD_H_*/
