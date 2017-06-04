/*
 * sload.c
 *
 */
#include <stdio.h>

#include <f2fs_fs.h>
#include "sload.h"
#include <libgen.h>
#include <dirent.h>
#include "node.h"

#include <selinux/label.h>
#include <private/android_filesystem_config.h>

static struct f2fs_sb_info sbi_global;

static int filter_dot(const struct dirent *d)
{
	return (strcmp(d->d_name, "..") && strcmp(d->d_name, "."));
}

/* Make new files in this dir_ino*/
static int f2fs_make_directory(struct f2fs_sb_info *sbi,
				int dir_ino, int entries, struct dentry *dentries, int dirs)
{
	int i=0;

	if (dir_ino < 3)
		dir_ino = 3;

	for (i = 0; i < entries; i++) {
		if (dentries[i].file_type == F2FS_FT_DIR)
			dentries[i].ino = f2fs_mkdir(sbi, dir_ino, dentries[i].mode,
							dentries[i].filename, strlen(dentries[i].filename),
							dentries[i].uid, dentries[i].gid,
							dentries[i].mtime);
		else if (dentries[i].file_type == F2FS_FT_REG_FILE)
			dentries[i].ino = f2fs_create(sbi, dir_ino, dentries[i].mode,
							dentries[i].filename, strlen(dentries[i].filename),
							dentries[i].uid, dentries[i].gid,
							dentries[i].mtime);
		else if (dentries[i].file_type == F2FS_FT_SYMLINK)
			dentries[i].ino = f2fs_symlink(sbi, dir_ino, dentries[i].mode,
							dentries[i].filename, strlen(dentries[i].filename),
							dentries[i].uid, dentries[i].gid,
							dentries[i].mtime, dentries[i].link);
		ASSERT((int)dentries[i].ino > 0);
	}
	return dir_ino;
}

static int f2fs_make_file(struct f2fs_sb_info *sbi, int dir_ino, struct dentry *dentry)
{
	int fd, n;
	pgoff_t off = 0;
	char buffer[4096];
	nid_t ino = dentry->ino;

	fd = open(dentry->full_path, O_RDONLY);
	if (fd < 0) {
		MSG(0, "Fail to open %s\n", dentry->full_path);
		return -1;
	}

	while ((n = read(fd, buffer, 4096)) > 0) {
		f2fs_write(sbi, ino, buffer, n, off);
		off += n;
	}

	close(fd);
	if (n < 0)
		return -1;
	return 0;

}

static int f2fs_build_directory(struct f2fs_sb_info *sbi, const char *full_path, const char *dir_path,
		const char *target_out_directory,
		u32 dir_ino, struct selabel_handle *sehnd)
{
	int entries = 0;
	struct dentry *dentries;
	struct dirent **namelist = NULL;
	struct stat stat;

	int i, ret;
	u32 dirs = 0;
	int cur_ino;

	if (full_path) {
		entries = scandir(full_path, &namelist, filter_dot, (void *)alphasort);
		if (entries < 0) {
			ERR_MSG("no entries in %s\n", full_path);
			return -ENOENT;
		}
	}

	dentries = calloc(entries, sizeof(struct dentry));
	if (dentries == NULL) {
		ERR_MSG("Error Nomem\n");
		return -ENOMEM;
	}

	for (i = 0; i < entries; i++) {
		dentries[i].filename = strdup(namelist[i]->d_name);
		if (dentries[i].filename == NULL)
				ERR_MSG("Error strdup\n");

		asprintf(&dentries[i].path, "%s%s", dir_path, namelist[i]->d_name);
		asprintf(&dentries[i].full_path, "%s%s", full_path, namelist[i]->d_name);

		free(namelist[i]);

		ret = lstat(dentries[i].full_path, &stat);
		if (ret < 0) {
			ERR_MSG("Error lstat\n");
			continue;
		}
		dentries[i].size = stat.st_size;
		dentries[i].mode = stat.st_mode & (S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO);
		dentries[i].mtime = stat.st_mtime;

		{
			uint64_t capabilities;
            unsigned int mode = 0;
            unsigned int uid = 0;
            unsigned int gid = 0;
            int dir = S_ISDIR(stat.st_mode);
            fs_config(dentries[i].path, dir, target_out_directory, &uid, &gid, &mode, &capabilities);
            dentries[i].mode = mode;
            dentries[i].uid = uid;
            dentries[i].gid = gid;
            dentries[i].capabilities = capabilities;
		}

		if (sehnd) {
            if (selabel_lookup(sehnd, &dentries[i].secon, dentries[i].path, stat.st_mode) < 0) {
                ERR_MSG("Cannot lookup security context for %s\n", dentries[i].path);
            }
		}

		if (S_ISREG(stat.st_mode)) {
			dentries[i].file_type = F2FS_FT_REG_FILE;
		} else if (S_ISDIR(stat.st_mode)) {
			dentries[i].file_type = F2FS_FT_DIR;
			dirs++;
        } else if (S_ISCHR(stat.st_mode)) {
            dentries[i].file_type = F2FS_FT_CHRDEV;
        } else if (S_ISBLK(stat.st_mode)) {
            dentries[i].file_type = F2FS_FT_BLKDEV;
        } else if (S_ISFIFO(stat.st_mode)) {
            dentries[i].file_type = F2FS_FT_FIFO;
        } else if (S_ISSOCK(stat.st_mode)) {
            dentries[i].file_type = F2FS_FT_SOCK;
        } else if (S_ISLNK(stat.st_mode)) {
            dentries[i].file_type = F2FS_FT_SYMLINK;
			dentries[i].link = calloc(F2FS_BLKSIZE, 1);
			ASSERT(dentries[i].link);
            readlink(dentries[i].full_path, dentries[i].link, F2FS_BLKSIZE - 1);
        } else {
            ERR_MSG("unknown file type on %s", dentries[i].path);
            i--;
            entries--;
        }
	}

	free(namelist);

	cur_ino = f2fs_make_directory(sbi, dir_ino, entries, dentries, dirs);

	for (i = 0; i < entries; i++) {
		if (dentries[i].file_type == F2FS_FT_REG_FILE) {
			f2fs_make_file(sbi, cur_ino, &dentries[i]);
		} else if (dentries[i].file_type == F2FS_FT_DIR) {
			char *subdir_full_path = NULL;
			char *subdir_dir_path;

			if (dentries[i].full_path) {
				ret = asprintf(&subdir_full_path, "%s/", dentries[i].full_path);
				if (ret < 0) {
					ERR_MSG("Error asprintf\n");
				}
			}
			ret = asprintf(&subdir_dir_path, "%s/", dentries[i].path);
			if (ret < 0)
				ERR_MSG("Error asprintf");

			f2fs_build_directory(sbi, subdir_full_path, subdir_dir_path, target_out_directory, dentries[i].ino, sehnd);
			free(subdir_full_path);
			free(subdir_dir_path);
		} else if (dentries[i].file_type == F2FS_FT_SYMLINK) {
			/*
			 * It is already done in f2fs_make_directory
			 * f2fs_make_symlink(sbi, cur_ino, &dentries[i]);
			 */
		} else {
			ERR_MSG("Error unknown file type\n");
		}

		if (dentries[i].secon) {
			inode_set_selinux(sbi, dentries[i].ino, dentries[i].secon);
			MSG(1, "File = %s \n----->SELinux context = %s\n", dentries[i].path, dentries[i].secon);
			MSG(1, "----->mode = 0x%x, uid = 0x%x, gid = 0x%x, "
				"capabilities = 0x%lx \n", dentries[i].mode, dentries[i].uid, dentries[i].gid, dentries[i].capabilities);
		}

		free(dentries[i].path);
		free(dentries[i].full_path);
		free((void *)dentries[i].filename);
		free(dentries[i].secon);
	}

	free(dentries);
	return 0;
}

int f2fs_format_with_source(const char *fromDir, const char *mount_point,
		const char *target_out_directory, struct selabel_handle *sehnd)
{
	struct f2fs_sb_info *sbi;
	nid_t   root_ino;
	int ret = 0;

	sbi = &sbi_global;

	ret = f2fs_do_mount(sbi);
	if (ret == 1) {
		free(sbi->ckpt);
		free(sbi->raw_super);
		goto out;
	} else if (ret < 0)
		return -1;

	f2fs_build_directory(sbi, fromDir, mount_point, target_out_directory, 0, sehnd);

	/* set root inode selinux context */

	root_ino = F2FS_ROOT_INO(sbi);
	if (sehnd) {
		char *secontext = NULL;

		if (selabel_lookup(sehnd, &secontext, mount_point, S_IFDIR) < 0) {
			ERR_MSG("cannot lookup security context for %s\n", mount_point);
		}
		if (secontext) {
			MSG(1, "Labeling %s as %s, root_ino = %d\n", mount_point, secontext, root_ino);
			/* xattr_add for root inode */
			inode_set_selinux(sbi, root_ino, secontext);
		}
		free(secontext);
	}

	f2fs_do_checkpoint(sbi);
	f2fs_do_umount(sbi);

out:

	printf("\nDone.\n");
	return 0;
}

