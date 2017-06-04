/*
 * f2fsdefrag.c - f2fs filesystem defragmenter
 */

#include <ctype.h>
#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <ext2fs/fiemap.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/vfs.h>

#include <sys/statvfs.h>

#include "imonitor.h"

#ifdef USE_ANDROID_LOG
#include "cutils/log.h"
#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "AwareLog:f2fsdefrag"
#endif
#define DFRAG_LOGE ALOGE
#else
#define DFRAG_LOGE printf
#endif
/* Macro functions */
#define PRINT_ERR_MSG(msg)	fprintf(stderr, "%s\n", (msg))
#define IN_FTW_PRINT_ERR_MSG(msg)	\
	fprintf(stderr, "\t%s\t\t[ NG ]\n", (msg))
#define PRINT_FILE_NAME(file)	fprintf(stderr, " \"%s\"\n", (file))
#define PRINT_ERR_MSG_WITH_ERRNO(msg)	\
	fprintf(stderr, "\t%s:%s\t[ NG ]\n", (msg), strerror(errno))
#define STATISTIC_ERR_MSG(msg)	\
	fprintf(stderr, "\t%s\n", (msg))
#define STATISTIC_ERR_MSG_WITH_ERRNO(msg)	\
	fprintf(stderr, "\t%s:%s\n", (msg), strerror(errno))
#define min(x, y) (((x) > (y)) ? (y) : (x))
/* Wrap up the free function */
#define FREE(tmp)				\
	do {					\
		if ((tmp) != NULL)		\
			free(tmp);		\
	} while (0)				\
/* Insert list2 after list1 */
#define insert(list1, list2)			\
	do {					\
		list2->next = list1->next;	\
		list1->next->prev = list2;	\
		list2->prev = list1;		\
		list1->next = list2;		\
	} while (0)

/* To delete unused warning */
#ifdef __GNUC__
#define FS_ATTR(x) __attribute__(x)
#else
#define FS_ATTR(x)
#endif

/* The mode of defrag */
#define DETAIL			0x01
#define STATISTIC		0x02
#define NAT				0x04

#define DEVNAME			0
#define DIRNAME			1
#define FILENAME		2

#define F2FS_NAME_LEN 255
#define F2FS_SUPER_MAGIC	0xF2F52010
#define F2FS_IOCTL_MAGIC	0xf5
#define F2FS_IOC_NAT_FIEMAP		_IOWR(F2FS_IOCTL_MAGIC, 0x32, struct f2fs_fiemap_buf)

#ifndef OPEN_MAX
#define OPEN_MAX 256
#endif
#define FTW_OPEN_FD		OPEN_MAX

#define ROOT_UID		0

#define SHOW_FRAG_FILES		20

/* The following macro is used for ioctl FS_IOC_FIEMAP
 * EXTENT_MAX_COUNT:	the maximum number of extents for exchanging between
 *			kernel-space and user-space per ioctl
 */
#define EXTENT_MAX_COUNT	512

#define DEFAULT_BEST_EXTENT_BLOCKS	(32)
#define FRAG_MESSAGE_LEN		(8192)
#define TMP_MESSAGE_LEN			(256)
#define FREE_EXTENT_KINDS		(10)
#define PROC_INFO_SECTOR		(12)
#define PROC_INFO_SIZE			(512)
#define F2FS_STATUS_INFO		(8192)
#define GET_LAST_N_CHAR(str, n)	(str + (strlen(str) > n ? (strlen(str) - n) : 0))
#define BDEVNAME_SIZE			(32)

enum {
	EVENTID_FS_GENERAL_INFO = 914000000,
	EVENTID_FS_TARGET_INFO = 914001000,
	EVENTID_TOPN_BY_SIZE = 914002000,
	EVENTID_TOPN_BY_SCORE = 914003000
};

enum {
	EVENT_IDX_FS_GENERAL_INFO = 0,
	EVENT_IDX_FS_TARGET_INFO,
	EVENT_IDX_TOPN_BY_SIZE,
	EVENT_IDX_TOPN_BY_SCORE,
	EVENT_CNT
};

/* The following macros are error message */
#define MSG_USAGE		\
"Usage	: f2fsdefrag [-v] [-f device] [-e blocks] [-n files(<=20)]\n"	\
"         -c file...| directory...| device...\n"

#define NGMSG_FILE_EXTENT	"Failed to get file extents"
#define NGMSG_FILE_INFO		"Failed to get file information"
#define NGMSG_FILE_OPEN		"Failed to open"
#define NGMSG_FILE_UNREG	"File is not regular file"
#define NGMSG_LOST_FOUND	"Can not process \"lost+found\""

/* Most of this struct copy from struct fiemap, we add some additional member */
struct f2fs_fiemap_buf {
	__u64 fm_start;		/* logical offset (inclusive) at
				 * which to start mapping (in) */
	__u64 fm_length;	/* logical length of mapping which
				 * userspace wants (in) */
	__u32 fm_flags;		/* FIEMAP_FLAG_* flags for request (in/out) */
	__u32 fm_mapped_extents;/* number of extents that were mapped (out) */
	__u32 fm_extent_count;  /* size of fm_extents array (in) */
	__u32 fm_reserved;
	__u32 nid;
	__u32 total;
	__u32 regular;
	char *file_name;
	struct fiemap_extent *fm_extents; /* array of mapped extents (out) */
};

/* Data type for filesystem-wide blocks number */
typedef unsigned long long fsblk_t;

struct fiemap_extent_data {
	__u64 len;		/* blocks count */
	__u64 logical;		/* start logical block number */
	fsblk_t physical;	/* start physical block number */
};

struct fiemap_extent_list {
	struct fiemap_extent_list *prev;
	struct fiemap_extent_list *next;
	struct fiemap_extent_data data;	/* extent belong to file */
};

struct fiemap_extent_group {
	struct fiemap_extent_group *prev;
	struct fiemap_extent_group *next;
	__u64 len;	/* length of this continuous region */
	struct fiemap_extent_list *start;	/* start ext */
	struct fiemap_extent_list *end;		/* end ext */
};

struct move_extent {
	__s32 reserved;	/* original file descriptor */
	__u32 donor_fd;	/* donor file descriptor */
	__u64 orig_start;	/* logical start offset in block for orig */
	__u64 donor_start;	/* logical start offset in block for donor */
	__u64 len;	/* block length to be moved */
	__u64 moved_len;	/* moved block length */
};

struct frag_statistic_ino {
	int now_count;	/* the file's extents count of before defrag */
	int best_count; /* the best file's extents count */
	__u64 size_per_ext;	/* size(KB) per extent */
	__u64 frag_cnt;	/* the count of the extents shorter than the best extent len */
	__u64 frag_size;	/* the total len of all those extents shorter than the beat extent len */
	__u64 blks;	/* blocks of the file */
	float ratio;	/* the ratio of fragmentation */
	char msg_buffer[PATH_MAX + 1];	/* pathname of the file */
};

static char	lost_found_dir[PATH_MAX + 1];
static int	block_size;
static int	extents_before_defrag;
static int	extents_after_defrag;
static int	mode_flag;
static unsigned int	current_uid;
static unsigned int	defraged_file_count;
static unsigned int	frag_files_before_defrag;
static unsigned int	frag_files_after_defrag;
static unsigned int	regular_count;
static unsigned int	succeed_cnt;
static unsigned int	total_count;
static __u8 log_groups_per_flex;
static __u32 blocks_per_group;
static __u32 feature_incompat;
static fsblk_t	files_block_count;
static struct frag_statistic_ino	frag_rank_ratio[SHOW_FRAG_FILES];
static struct frag_statistic_ino	frag_rank_size[SHOW_FRAG_FILES];
static __u64	total_frag_blks = 0;
static __u64	total_data_blks = 0;
static __u64	total_frag_cnt;
static __u64	total_frag_size;
static __u32	total_free_size = 0;
static __u32	total_free_frag_size = 0;
static __u64 lifetime_write_kbytes = 0;
static int	gc_count = -1;
static int	gc_blks = -1;
static int	top_n_files = SHOW_FRAG_FILES;

static struct imonitor_eventobj *imonitor_obj[EVENT_CNT];

static fsblk_t move_block_count = 0;
struct statvfs s;

static int f2fsdefrag_imonitor_create()
{
	if (!(imonitor_obj[EVENT_IDX_FS_GENERAL_INFO] =
		  imonitor_create_eventobj(EVENTID_FS_GENERAL_INFO)))
		return -EINVAL;

	if (!(imonitor_obj[EVENT_IDX_FS_TARGET_INFO] =
		  imonitor_create_eventobj(EVENTID_FS_TARGET_INFO)))
		return -EINVAL;

	if (!(imonitor_obj[EVENT_IDX_TOPN_BY_SIZE] =
		  imonitor_create_eventobj(EVENTID_TOPN_BY_SIZE)))
		return -EINVAL;

	if (!(imonitor_obj[EVENT_IDX_TOPN_BY_SCORE] =
		  imonitor_create_eventobj(EVENTID_TOPN_BY_SCORE)))
		return -EINVAL;

	return 0;
}

static void f2fsdefrag_imonitor_destroy()
{
	if (imonitor_obj[EVENT_IDX_FS_GENERAL_INFO])
		imonitor_destroy_eventobj(imonitor_obj[EVENT_IDX_FS_GENERAL_INFO]);

	if (imonitor_obj[EVENT_IDX_FS_TARGET_INFO])
		imonitor_destroy_eventobj(imonitor_obj[EVENT_IDX_FS_TARGET_INFO]);

	if (imonitor_obj[EVENT_IDX_TOPN_BY_SIZE])
		imonitor_destroy_eventobj(imonitor_obj[EVENT_IDX_TOPN_BY_SIZE]);

	if (imonitor_obj[EVENT_IDX_TOPN_BY_SCORE])
		imonitor_destroy_eventobj(imonitor_obj[EVENT_IDX_TOPN_BY_SCORE]);
}

static int f2fsdefrag_send_event(int index, char *name, int topn)
{
	struct imonitor_eventobj *obj;
	int ret = 0;

	obj = imonitor_obj[index];

	switch (index) {
	case EVENT_IDX_FS_GENERAL_INFO: {
		float ratio = 0.0;
		float free_ratio = 0.0;

		if (total_data_blks)
			ratio = (float)total_frag_blks * 100 / total_data_blks;
		if (total_free_size)
			free_ratio = (float)total_free_frag_size * 100 / total_free_size;

		ret = imonitor_set_param(obj, E914000000_FS_BLKS_INT, (__u32)s.f_blocks);
		ret |= imonitor_set_param(obj, E914000000_LIFETIME_WB_INT,
									(__u32)lifetime_write_kbytes);
		ret |= imonitor_set_param(obj, E914000000_FREE_BLKS_INT,
									(__u32)total_free_size);
		ret |= imonitor_set_param(obj, E914000000_FRAG_FREE_BLKS_INT,
									(__u32)total_free_frag_size);
		ret |= imonitor_set_param(obj, E914000000_FREE_SCORE_FLOAT, (long)&free_ratio);
		ret |= imonitor_set_param(obj, E914000000_GC_COUNT_INT, gc_count);
		ret |= imonitor_set_param(obj, E914000000_GC_BLKS_INT, gc_blks);
		ret |= imonitor_set_param(obj, E914000000_TOTAL_SCORE_FLOAT, (long)&ratio);
		break;
	}
	case EVENT_IDX_FS_TARGET_INFO:
		ret = imonitor_set_param(obj, E914001000_APP_NAME_VARCHAR, (long)name);
		ret |= imonitor_set_param(obj, E914001000_TARGET_BLKS_INT,
									(__u32)files_block_count);
		ret |= imonitor_set_param(obj, E914001000_FILES_COUNT_INT, regular_count);
		ret |= imonitor_set_param(obj, E914001000_DIR_COUNT_INT,
									total_count - regular_count);
		ret |= imonitor_set_param(obj, E914001000_FRAG_EXTENTS_INT,
									(__u32)total_frag_cnt);
		ret |= imonitor_set_param(obj, E914001000_FRAG_BLKS_INT,
									(__u32)total_frag_size);
		break;
	case EVENT_IDX_TOPN_BY_SIZE:
		ret = imonitor_set_param(obj, E914002000_FILE_NAME_VARCHAR, (long)name);
		ret |= imonitor_set_param(obj, E914002000_INDEX_INT, topn);
		ret |= imonitor_set_param(obj, E914002000_FRAG_EXTENTS_INT,
									frag_rank_size[topn].frag_cnt);
		ret |= imonitor_set_param(obj, E914002000_FRAG_BLKS_INT,
									frag_rank_size[topn].frag_size);
		ret |= imonitor_set_param(obj, E914002000_FILE_BLKS_INT,
									frag_rank_size[topn].blks);
		break;
	case EVENT_IDX_TOPN_BY_SCORE:
		ret = imonitor_set_param(obj, E914003000_FILE_NAME_VARCHAR, (long)name);
		ret |= imonitor_set_param(obj, E914003000_INDEX_INT, topn);
		ret |= imonitor_set_param(obj, E914003000_FRAG_EXTENTS_INT,
									frag_rank_ratio[topn].frag_cnt);
		ret |= imonitor_set_param(obj, E914003000_FRAG_BLKS_INT,
									frag_rank_ratio[topn].frag_size);
		ret |= imonitor_set_param(obj, E914003000_FILE_BLKS_INT,
									frag_rank_ratio[topn].blks);
		break;
	}

	if (ret)
		return ret;

	ret = imonitor_send_event(obj);

	return ret;
}

static void trancate_at_whitespace(char *str)
{
	while (str && *str) {
		if ((*str == '\r') || (*str == '\n') ||
				(*str == ' ') || (*str == '\t')) {
			*str = '\0';
			return;
		}
		str++;
	}
}

static char *skip_whitespace(char *str)
{
	while (str && *str) {
		if ((*str == '\r') || (*str == '\n') ||
				(*str == ' ') || (*str == '\t'))
			str++;
		else
			break;
	}

	return str;
}

/*
 * get_mount_point() -	Get device's mount point.
 *
 * @devname:		the device's name.
 * @mount_point:	the mount point.
 * @dir_path_len:	the length of directory.
 */
#define MOUNT_PROCFS "/proc/mounts"
#define LINE_SIZE 1024
static int get_mount_point(const char *devname, char *mount_point,
		int dir_path_len)
{
	FILE *fp;
	char *p;
	char buf[LINE_SIZE];
	char dev[PATH_MAX];
	char *mntpoint;
	struct stat64	sb;

	if (stat64(devname, &sb) < 0) {
		DFRAG_LOGE("%s: stat %s fail, errno %d, %s\n", __FUNCTION__, devname, errno, strerror(errno));
		return -1;
	}

	fp = fopen(MOUNT_PROCFS, "r");
	if (!fp) {
		DFRAG_LOGE("%s, open %s fail, errno %d, %s\n", __func__, MOUNT_PROCFS, errno, strerror(errno));
		return 0;
	}

	for (;!feof(fp);) {
		struct stat64 ms;
		memset(buf, 0, sizeof(buf));
		if (fgets(buf, sizeof(buf) - 1, fp) == NULL)
			break;

		if (buf[0] != '/') continue;

		trancate_at_whitespace(buf);

		realpath(buf, dev);

		if (stat64(dev, &ms) < 0) continue;
		if (sb.st_rdev != ms.st_rdev) continue;

		/* find the one */
		p = strlen(buf) + buf + 1;
		p = skip_whitespace(p);
		trancate_at_whitespace(p);

		strncpy(mount_point, p,	dir_path_len);

		fclose(fp);
		return 0;
	}
	fclose(fp);

	return -1;
}

/*
 * calc_entry_counts() -	Calculate file counts.
 *
 * @file:		file name.
 * @buf:		file info.
 * @flag:		file type.
 * @ftwbuf:		the pointer of a struct FTW.
 */
static int calc_entry_counts(const char *file FS_ATTR((unused)),
		const struct stat64 *buf, int flag FS_ATTR((unused)),
		struct FTW *ftwbuf FS_ATTR((unused)))
{
	if (S_ISREG(buf->st_mode))
		regular_count++;

	total_count++;

	return 0;
}

/*
 * check_free_size() -	Check if there's enough disk space.
 *
 * @fd:			defrag target file's descriptor.
 * @file:		file name.
 * @blk_count:		file blocks.
 */
static int check_free_size(int fd, const char *file, fsblk_t blk_count)
{
	fsblk_t	free_blk_count;
	struct statfs64	fsbuf;

	if (fstatfs64(fd, &fsbuf) < 0) {
		if (mode_flag & DETAIL) {
			PRINT_FILE_NAME(file);
			PRINT_ERR_MSG_WITH_ERRNO(
				"Failed to get filesystem information");
		}
		return -1;
	}

	/* Compute free space for root and normal user separately */
	if (current_uid == ROOT_UID)
		free_blk_count = fsbuf.f_bfree;
	else
		free_blk_count = fsbuf.f_bavail;

	if (free_blk_count >= blk_count)
		return 0;

	return -ENOSPC;
}

/*
 * insert_extent_by_logical() -	Sequentially insert extent by logical.
 *
 * @ext_list_head:	the head of logical extent list.
 * @ext:		the extent element which will be inserted.
 */
static int insert_extent_by_logical(struct fiemap_extent_list **ext_list_head,
			struct fiemap_extent_list *ext)
{
	struct fiemap_extent_list	*ext_list_tmp = *ext_list_head;

	if (ext == NULL)
		goto out;

	/* First element */
	if (*ext_list_head == NULL) {
		(*ext_list_head) = ext;
		(*ext_list_head)->prev = *ext_list_head;
		(*ext_list_head)->next = *ext_list_head;
		return 0;
	}

	if (ext->data.logical <= ext_list_tmp->data.logical) {
		/* Insert before head */
		if (ext_list_tmp->data.logical <
			ext->data.logical + ext->data.len)
			/* Overlap */
			goto out;
		/* Adjust head */
		*ext_list_head = ext;
	} else {
		/* Insert into the middle or last of the list */
		do {
			if (ext->data.logical < ext_list_tmp->data.logical)
				break;
			ext_list_tmp = ext_list_tmp->next;
		} while (ext_list_tmp != (*ext_list_head));
		if (ext->data.logical <
		    ext_list_tmp->prev->data.logical +
			ext_list_tmp->prev->data.len)
			/* Overlap */
			goto out;

		if (ext_list_tmp != *ext_list_head &&
		    ext_list_tmp->data.logical <
		    ext->data.logical + ext->data.len)
			/* Overlap */
			goto out;
	}
	ext_list_tmp = ext_list_tmp->prev;
	/* Insert "ext" after "ext_list_tmp" */
	insert(ext_list_tmp, ext);
	return 0;
out:
	errno = EINVAL;
	return -1;
}

/*
 * insert_extent_by_physical() -	Sequentially insert extent by physical.
 *
 * @ext_list_head:	the head of physical extent list.
 * @ext:		the extent element which will be inserted.
 */
static int insert_extent_by_physical(struct fiemap_extent_list **ext_list_head,
			struct fiemap_extent_list *ext)
{
	struct fiemap_extent_list	*ext_list_tmp = *ext_list_head;

	if (ext == NULL)
		goto out;

	/* First element */
	if (*ext_list_head == NULL) {
		(*ext_list_head) = ext;
		(*ext_list_head)->prev = *ext_list_head;
		(*ext_list_head)->next = *ext_list_head;
		return 0;
	}

	if (ext->data.physical <= ext_list_tmp->data.physical) {
		/* Insert before head */
		if (ext_list_tmp->data.physical <
					ext->data.physical + ext->data.len)
			/* Overlap */
			goto out;
		/* Adjust head */
		*ext_list_head = ext;
	} else {
		/* Insert into the middle or last of the list */
		do {
			if (ext->data.physical < ext_list_tmp->data.physical)
				break;
			ext_list_tmp = ext_list_tmp->next;
		} while (ext_list_tmp != (*ext_list_head));
		if (ext->data.physical <
		    ext_list_tmp->prev->data.physical +
				ext_list_tmp->prev->data.len)
			/* Overlap */
			goto out;

		if (ext_list_tmp != *ext_list_head &&
		    ext_list_tmp->data.physical <
				ext->data.physical + ext->data.len)
			/* Overlap */
			goto out;
	}
	ext_list_tmp = ext_list_tmp->prev;
	/* Insert "ext" after "ext_list_tmp" */
	insert(ext_list_tmp, ext);
	return 0;
out:
	errno = EINVAL;
	return -1;
}

/*
 * get_file_extents() -	Get file's extent list.
 *
 * @fd:			defrag target file's descriptor.
 * @ext_list_head:	the head of the extent list.
 */
static int get_file_extents(int fd, struct fiemap_extent_list **ext_list_head)
{
	__u32	i;
	int	ret;
	int	ext_buf_size, fie_buf_size;
	__u64	pos = 0;
	struct fiemap	*fiemap_buf = NULL;
	struct fiemap_extent	*ext_buf = NULL;
	struct fiemap_extent_list	*ext_list = NULL;

	/* Convert units, in bytes.
	 * Be careful : now, physical block number in extent is 48bit,
	 * and the blocksize for f2fs is 4K(12bit),
	 * so there is no overflow, but in future it may be changed.
	 */

	/* Alloc space for fiemap */
	ext_buf_size = EXTENT_MAX_COUNT * sizeof(struct fiemap_extent);
	fie_buf_size = sizeof(struct fiemap) + ext_buf_size;

	fiemap_buf = malloc(fie_buf_size);
	if (fiemap_buf == NULL)
		return -1;

	ext_buf = fiemap_buf->fm_extents;
	memset(fiemap_buf, 0, fie_buf_size);
	fiemap_buf->fm_length = FIEMAP_MAX_OFFSET;
	fiemap_buf->fm_extent_count = EXTENT_MAX_COUNT;

	do {
		fiemap_buf->fm_start = pos;
		memset(ext_buf, 0, ext_buf_size);
		ret = ioctl(fd, FS_IOC_FIEMAP, fiemap_buf);
		if (ret < 0 || fiemap_buf->fm_mapped_extents == 0)
			goto out;
		for (i = 0; i < fiemap_buf->fm_mapped_extents; i++) {
			ext_list = NULL;
			ext_list = malloc(sizeof(struct fiemap_extent_list));
			if (ext_list == NULL)
				goto out;

			ext_list->data.physical = ext_buf[i].fe_physical
						/ block_size;
			ext_list->data.logical = ext_buf[i].fe_logical
						/ block_size;
			ext_list->data.len = ext_buf[i].fe_length
						/ block_size;

			/* exent data length may < 4k, e.g inline file */
			if (ext_list->data.len == 0)
				ext_list->data.len = 1;

			ret = insert_extent_by_physical(
					ext_list_head, ext_list);
			if (ret < 0) {
				FREE(ext_list);
				goto out;
			}
		}
		/* Record file's logical offset this time */
		pos = ext_buf[EXTENT_MAX_COUNT-1].fe_logical +
			ext_buf[EXTENT_MAX_COUNT-1].fe_length;
		/*
		 * If fm_extents array has been filled and
		 * there are extents left, continue to cycle.
		 */
	} while (fiemap_buf->fm_mapped_extents
					== EXTENT_MAX_COUNT &&
		!(ext_buf[EXTENT_MAX_COUNT-1].fe_flags
					& FIEMAP_EXTENT_LAST));

	FREE(fiemap_buf);
	return 0;
out:
	FREE(fiemap_buf);
	return -1;
}

static int get_nat_extents(int root_fd, unsigned int *nid,
		struct fiemap_extent_list **ext_list_head, char *buf)
{
	__u32	i;
	int	ret;
	int	ext_buf_size, fie_buf_size;
	__u64	pos = 0;
	struct f2fs_fiemap_buf	*fiemap_buf = NULL;
	struct fiemap_extent	*ext_buf = NULL;
	struct fiemap_extent_list	*ext_list = NULL;

	/* Convert units, in bytes.
	 * Be careful : now, physical block number in extent is 48bit,
	 * and the blocksize for f2fs is 4K(12bit),
	 * so there is no overflow, but in future it may be changed.
	 */

	/* Alloc space for fiemap */
	ext_buf_size = EXTENT_MAX_COUNT * sizeof(struct fiemap_extent);
	fie_buf_size = sizeof(struct f2fs_fiemap_buf) + F2FS_NAME_LEN + ext_buf_size;

	fiemap_buf = malloc(fie_buf_size);
	if (fiemap_buf == NULL)
		return -1;

	memset(fiemap_buf, 0, fie_buf_size);

	fiemap_buf->file_name = (char *)fiemap_buf + sizeof(struct f2fs_fiemap_buf);
	fiemap_buf->fm_extents = (struct fiemap_extent *)(fiemap_buf->file_name + F2FS_NAME_LEN);
	ext_buf = fiemap_buf->fm_extents;
	fiemap_buf->nid = *nid;
	fiemap_buf->fm_length = FIEMAP_MAX_OFFSET;
	fiemap_buf->fm_extent_count = EXTENT_MAX_COUNT;

	do {
		fiemap_buf->total = 0;
		fiemap_buf->regular = 0;
		fiemap_buf->fm_start = pos;
		memset(ext_buf, 0, ext_buf_size);
		ret = ioctl(root_fd, F2FS_IOC_NAT_FIEMAP, fiemap_buf);
		/* save the return nid first, and count total/regular file */
		*nid = fiemap_buf->nid;
		total_count += fiemap_buf->total;
		regular_count += fiemap_buf->regular;
		if (ret < 0 || fiemap_buf->fm_mapped_extents == 0)
			goto out;

		strncpy(buf, fiemap_buf->file_name, strlen(fiemap_buf->file_name));

		for (i = 0; i < fiemap_buf->fm_mapped_extents; i++) {
			ext_list = NULL;
			ext_list = malloc(sizeof(struct fiemap_extent_list));
			if (ext_list == NULL)
				goto out;

			ext_list->data.physical = ext_buf[i].fe_physical
						/ block_size;
			ext_list->data.logical = ext_buf[i].fe_logical
						/ block_size;
			ext_list->data.len = ext_buf[i].fe_length
						/ block_size;

			/* exent data length may < 4k, e.g inline file */
			if (ext_list->data.len == 0)
				ext_list->data.len = 1;

			ret = insert_extent_by_physical(
					ext_list_head, ext_list);
			if (ret < 0) {
				FREE(ext_list);
				goto out;
			}
		}
		/* Record file's logical offset this time */
		pos = ext_buf[EXTENT_MAX_COUNT-1].fe_logical +
			ext_buf[EXTENT_MAX_COUNT-1].fe_length;
		/*
		 * If fm_extents array has been filled and
		 * there are extents left, continue to cycle.
		 */
	} while (fiemap_buf->fm_mapped_extents
					== EXTENT_MAX_COUNT &&
		!(ext_buf[EXTENT_MAX_COUNT-1].fe_flags
					& FIEMAP_EXTENT_LAST));

	FREE(fiemap_buf);
	return 0;
out:
	FREE(fiemap_buf);
	return -1;
}


/*
 * get_logical_count() -	Get the file logical extents count.
 *
 * @logical_list_head:	the head of the logical extent list.
 */
static int get_logical_count(struct fiemap_extent_list *logical_list_head)
{
	int ret = 0;
	struct fiemap_extent_list *ext_list_tmp  = logical_list_head;

	do {
		ret++;
		ext_list_tmp = ext_list_tmp->next;
	} while (ext_list_tmp != logical_list_head);

	return ret;
}

/*
 * get_physical_count() -	Get the file physical extents count.
 *
 * @physical_list_head:	the head of the physical extent list.
 */
static int get_physical_count(struct fiemap_extent_list *physical_list_head)
{
	int ret = 0;
	struct fiemap_extent_list *ext_list_tmp = physical_list_head;

	do {
		if ((ext_list_tmp->data.physical + ext_list_tmp->data.len)
				!= ext_list_tmp->next->data.physical) {
			/* This extent and next extent are not continuous. */
			ret++;
		}

		ext_list_tmp = ext_list_tmp->next;
	} while (ext_list_tmp != physical_list_head);

	return ret;
}

/*
 * change_physical_to_logical() -	Change list from physical to logical.
 *
 * @physical_list_head:	the head of physical extent list.
 * @logical_list_head:	the head of logical extent list.
 */
static int change_physical_to_logical(
			struct fiemap_extent_list **physical_list_head,
			struct fiemap_extent_list **logical_list_head)
{
	int ret;
	struct fiemap_extent_list *ext_list_tmp = *physical_list_head;
	struct fiemap_extent_list *ext_list_next = ext_list_tmp->next;

	while (1) {
		if (ext_list_tmp == ext_list_next) {
			ret = insert_extent_by_logical(
				logical_list_head, ext_list_tmp);
			if (ret < 0)
				return -1;

			*physical_list_head = NULL;
			break;
		}

		ext_list_tmp->prev->next = ext_list_tmp->next;
		ext_list_tmp->next->prev = ext_list_tmp->prev;
		*physical_list_head = ext_list_next;

		ret = insert_extent_by_logical(
			logical_list_head, ext_list_tmp);
		if (ret < 0) {
			FREE(ext_list_tmp);
			return -1;
		}
		ext_list_tmp = ext_list_next;
		ext_list_next = ext_list_next->next;
	}

	return 0;
}

/* get_file_blocks() -  Get total file blocks.
 *
 * @ext_list_head:	the extent list head of the target file
 */
static fsblk_t get_file_blocks(struct fiemap_extent_list *ext_list_head)
{
	fsblk_t blk_count = 0;
	struct fiemap_extent_list *ext_list_tmp = ext_list_head;

	do {
		blk_count += ext_list_tmp->data.len;
		ext_list_tmp = ext_list_tmp->next;
	} while (ext_list_tmp != ext_list_head);

	return blk_count;
}

static void get_file_frag_info(struct fiemap_extent_list *ext_list_head,
			  __u64 *frag_cnt, __u64 *frag_size)
{
	__u64 tmp_blk;
	struct fiemap_extent_list *ext_list_tmp = ext_list_head;

	do {
		tmp_blk = ext_list_tmp->data.len;
		if (tmp_blk < blocks_per_group) {
			*frag_cnt += 1;
			*frag_size += tmp_blk;
		}
		ext_list_tmp = ext_list_tmp->next;
	} while (ext_list_tmp != ext_list_head);
}

/*
 * free_ext() -		Free the extent list.
 *
 * @ext_list_head:	the extent list head of which will be free.
 */
static void free_ext(struct fiemap_extent_list *ext_list_head)
{
	struct fiemap_extent_list	*ext_list_tmp = NULL;

	if (ext_list_head == NULL)
		return;

	while (ext_list_head->next != ext_list_head) {
		ext_list_tmp = ext_list_head;
		ext_list_head->prev->next = ext_list_head->next;
		ext_list_head->next->prev = ext_list_head->prev;
		ext_list_head = ext_list_head->next;
		free(ext_list_tmp);
	}
	free(ext_list_head);
}

/*
 * get_best_count() -	Get the file best extents count.
 *
 * @block_count:		the file's physical block count.
 */
static int get_best_count(fsblk_t block_count)
{
	return ((block_count - 1) / blocks_per_group) + 1;
}

static bool islogfile(const char *name)
{
	char *tmp;

	/* "*.log*" */
	if ((tmp = strstr(name, ".log")))
		return true;

	/* "*log" */
	if (0 == strcmp(name + strlen(name) - 3, "log"))
		return true;

	/* "*log.txt" */
	if (0 == strcmp(name + strlen(name) - 7, "log.txt"))
		return true;

	/* "*log.{0-9}*" */
	if ((tmp = strstr(name, "log."))) {
		if(0 == isdigit(tmp[0]))
			return true;
	}

	/* "*log-{0-9}*" */
	if ((tmp = strstr(name, "log-"))) {
		if(0 == isdigit(tmp[0]))
			return true;
	}

	return false;
}

static void rank_frag_info(struct frag_statistic_ino *stat)
{
	int i,j;

	for (i = 0; i < top_n_files; i++) {
		if (stat->ratio >= frag_rank_ratio[i].ratio) {
			for (j = top_n_files - 1; j > i; j--) {
				memset(&frag_rank_ratio[j], 0,
					sizeof(struct frag_statistic_ino));
				strncpy(frag_rank_ratio[j].msg_buffer,
					frag_rank_ratio[j - 1].msg_buffer,
					strnlen(frag_rank_ratio[j - 1].msg_buffer,
					PATH_MAX));
				frag_rank_ratio[j].now_count =
					frag_rank_ratio[j - 1].now_count;
				frag_rank_ratio[j].best_count =
					frag_rank_ratio[j - 1].best_count;
				frag_rank_ratio[j].size_per_ext =
					frag_rank_ratio[j - 1].size_per_ext;
				frag_rank_ratio[j].blks =
					frag_rank_ratio[j - 1].blks;
				frag_rank_ratio[j].ratio =
					frag_rank_ratio[j - 1].ratio;
				frag_rank_ratio[j].frag_cnt =
					frag_rank_ratio[j - 1].frag_cnt;
				frag_rank_ratio[j].frag_size =
					frag_rank_ratio[j - 1].frag_size;
			}
			memset(&frag_rank_ratio[i], 0,
					sizeof(struct frag_statistic_ino));
			strncpy(frag_rank_ratio[i].msg_buffer, stat->msg_buffer,
						PATH_MAX);
			frag_rank_ratio[i].now_count = stat->now_count;
			frag_rank_ratio[i].best_count = stat->best_count;
			frag_rank_ratio[i].size_per_ext = stat->size_per_ext;
			frag_rank_ratio[i].blks = stat->blks;
			frag_rank_ratio[i].ratio = stat->ratio;
			frag_rank_ratio[i].frag_cnt = stat->frag_cnt;
			frag_rank_ratio[i].frag_size = stat->frag_size;
			break;
		}
	}

	for (i = 0; i < top_n_files; i++) {
		if (stat->frag_size >= frag_rank_size[i].frag_size) {
			for (j = top_n_files - 1; j > i; j--) {
				memset(&frag_rank_size[j], 0,
					sizeof(struct frag_statistic_ino));
				strncpy(frag_rank_size[j].msg_buffer,
					frag_rank_size[j - 1].msg_buffer,
					strnlen(frag_rank_size[j - 1].msg_buffer,
					PATH_MAX));
				frag_rank_size[j].now_count =
					frag_rank_size[j - 1].now_count;
				frag_rank_size[j].best_count =
					frag_rank_size[j - 1].best_count;
				frag_rank_size[j].size_per_ext =
					frag_rank_size[j - 1].size_per_ext;
				frag_rank_size[j].blks =
					frag_rank_size[j - 1].blks;
				frag_rank_size[j].ratio =
					frag_rank_size[j - 1].ratio;
				frag_rank_size[j].frag_cnt =
					frag_rank_size[j - 1].frag_cnt;
				frag_rank_size[j].frag_size =
					frag_rank_size[j - 1].frag_size;
			}
			memset(&frag_rank_size[i], 0,
					sizeof(struct frag_statistic_ino));
			strncpy(frag_rank_size[i].msg_buffer, stat->msg_buffer,
						PATH_MAX);
			frag_rank_size[i].now_count = stat->now_count;
			frag_rank_size[i].best_count = stat->best_count;
			frag_rank_size[i].size_per_ext = stat->size_per_ext;
			frag_rank_size[i].blks = stat->blks;
			frag_rank_size[i].ratio = stat->ratio;
			frag_rank_size[i].frag_cnt = stat->frag_cnt;
			frag_rank_size[i].frag_size = stat->frag_size;
			return;
		}
	}
}

/* return 0 - success, return -1 - fail */
static int count_file_fragments(const char *file, blksize_t blksize,
		struct fiemap_extent_list *logical_list_head)
 {
	struct frag_statistic_ino frag_stat;
	char	msg_buffer[PATH_MAX + 24];
	__u64	frag_cnt = 0;
	__u64	frag_size = 0;

	memset(&frag_stat, 0, sizeof(frag_stat));

	/* Count file fragments before defrag */
	frag_stat.now_count = get_logical_count(logical_list_head);

	if (current_uid == ROOT_UID) {
		/* Calculate the size per extent */
		frag_stat.blks = get_file_blocks(logical_list_head);
		get_file_frag_info(logical_list_head, &frag_cnt, &frag_size);
		frag_cnt = frag_cnt == 1 ? 0 : frag_cnt;
		frag_size = frag_cnt == 0 ? 0 : frag_size;
		total_frag_cnt += frag_cnt;
		total_frag_size += frag_size;

		frag_stat.best_count = get_best_count(frag_stat.blks);
		frag_stat.best_count = frag_stat.best_count > frag_stat.now_count ?
				 frag_stat.now_count : frag_stat.best_count;

		/* f2fsdefrag rounds size_per_ext up to a block size boundary */
		frag_stat.size_per_ext = frag_stat.blks * (blksize / 1024) /
							frag_stat.now_count;

		frag_stat.ratio = (float)(frag_size) * 100 / frag_stat.blks;

		extents_before_defrag += frag_stat.now_count;
		extents_after_defrag += frag_stat.best_count;
		files_block_count += frag_stat.blks;
	}

	if (!(mode_flag & NAT) && total_count == 1 && regular_count == 1) {
		/* File only */
		if (mode_flag & DETAIL) {
			int count = 0;
			struct fiemap_extent_list *ext_list_tmp =
						logical_list_head;

			/* Print extents info */
			do {
				count++;
				DFRAG_LOGE("[ext %d]:\tstart %llu:\tlogical "
						"%llu:\tlen %llu\n", count,
						ext_list_tmp->data.physical,
						ext_list_tmp->data.logical,
						ext_list_tmp->data.len);
				ext_list_tmp = ext_list_tmp->next;
			} while (ext_list_tmp != logical_list_head);

		} else {
			DFRAG_LOGE("%-40s%10s/%-10s%9s\n",
					"<File>", "now", "best", "size/ext");
			if (current_uid == ROOT_UID) {
				if (strlen(file) > 40)
					DFRAG_LOGE("%s\n%50d/%-10d%6llu KB\n",
						file, frag_stat.now_count,
						frag_stat.best_count, frag_stat.size_per_ext);
				else
					DFRAG_LOGE("%-40s%10d/%-10d%6llu KB\n",
						file, frag_stat.now_count,
						frag_stat.best_count, frag_stat.size_per_ext);
			} else {
				if (strlen(file) > 40)
					DFRAG_LOGE("%s\n%50d/%-10s%7s\n",
							file, frag_stat.now_count,
							"-", "-");
				else
					DFRAG_LOGE("%-40s%10d/%-10s%7s\n",
							file, frag_stat.now_count,
							"-", "-");
			}
		}
		succeed_cnt++;
	}

	if (mode_flag & DETAIL) {
		/* Print statistic info */
		snprintf(msg_buffer, sizeof(msg_buffer), "[%u/%u]%s",
				defraged_file_count, total_count, file);
		if (current_uid == ROOT_UID) {
			if (strlen(msg_buffer) > 40)
				DFRAG_LOGE("\033[79;0H\033[K%s\n"
						"%50d/%-10d%6llu KB\n",
						msg_buffer, frag_stat.now_count,
						frag_stat.best_count, frag_stat.size_per_ext);
			else
				DFRAG_LOGE("\033[79;0H\033[K%-40s"
						"%10d/%-10d%6llu KB\n",
						msg_buffer, frag_stat.now_count,
						frag_stat.best_count, frag_stat.size_per_ext);
		} else {
			if (strlen(msg_buffer) > 40)
				DFRAG_LOGE("\033[79;0H\033[K%s\n%50d/%-10s%7s\n",
						msg_buffer, frag_stat.now_count,
							"-", "-");
			else
				DFRAG_LOGE("\033[79;0H\033[K%-40s%10d/%-10s%7s\n",
						msg_buffer, frag_stat.now_count,
							"-", "-");
		}
	}

	if (islogfile(file))
		return -1;

	frag_stat.frag_size = frag_size;
	frag_stat.frag_cnt = frag_cnt;
	strncpy(frag_stat.msg_buffer, file, strnlen(file, PATH_MAX));

	rank_frag_info(&frag_stat);

	return 0;
 }

/*
 * file_statistic() -	Get statistic info of the file's fragments.
 *
 * @file:		the file's name.
 * @buf:		the pointer of the struct stat64.
 * @flag:		file type.
 * @ftwbuf:		the pointer of a struct FTW.
 */
static int file_statistic(const char *file, const struct stat64 *buf,
			int flag FS_ATTR((unused)),
			struct FTW *ftwbuf FS_ATTR((unused)))
{
	struct frag_statistic_ino frag_stat;
	int	fd;
	int	ret;
	int physical_ext_count;
	char	msg_buffer[PATH_MAX + 24];
	struct fiemap_extent_list *physical_list_head = NULL;
	struct fiemap_extent_list *logical_list_head = NULL;

	memset(&frag_stat, 0, sizeof(frag_stat));

	defraged_file_count++;

	if (mode_flag & DETAIL) {
		if (total_count == 1 && regular_count == 1)
			DFRAG_LOGE("<File>\n");
		else {
			DFRAG_LOGE("[%u/%u]", defraged_file_count, total_count);
			fflush(stdout);
		}
	}
	if (lost_found_dir[0] != '\0' &&
	    !memcmp(file, lost_found_dir, strnlen(lost_found_dir, PATH_MAX))) {
		if (mode_flag & DETAIL) {
			PRINT_FILE_NAME(file);
			STATISTIC_ERR_MSG(NGMSG_LOST_FOUND);
		}
			return 0;
	}

	if (!S_ISREG(buf->st_mode)) {
		if (mode_flag & DETAIL) {
			PRINT_FILE_NAME(file);
			STATISTIC_ERR_MSG(NGMSG_FILE_UNREG);
		}
		return 0;
	}

	/* Access authority */
	if (current_uid != ROOT_UID &&
		buf->st_uid != current_uid) {
		if (mode_flag & DETAIL) {
			PRINT_FILE_NAME(file);
			STATISTIC_ERR_MSG(
				"File is not current user's file"
				" or current user is not root");
		}
		return 0;
	}

	/* Empty file */
	if (buf->st_size == 0) {
		if (mode_flag & DETAIL) {
			PRINT_FILE_NAME(file);
			STATISTIC_ERR_MSG("File size is 0");
		}
		return 0;
	}

	/* Has no blocks */
	if (buf->st_blocks == 0) {
		if (mode_flag & DETAIL) {
			PRINT_FILE_NAME(file);
			STATISTIC_ERR_MSG("File has no blocks");
		}
		return 0;
	}

	fd = open64(file, O_RDONLY);
	if (fd < 0) {
		if (mode_flag & DETAIL) {
			PRINT_FILE_NAME(file);
			STATISTIC_ERR_MSG_WITH_ERRNO(NGMSG_FILE_OPEN);
		}
		return 0;
	}

	/* Get file's physical extents  */
	ret = get_file_extents(fd, &physical_list_head);
	if (ret < 0) {
		if (mode_flag & DETAIL) {
			PRINT_FILE_NAME(file);
			STATISTIC_ERR_MSG_WITH_ERRNO(NGMSG_FILE_EXTENT);
		}
		goto out;
	}

	/* Get the count of file's continuous physical region */
	physical_ext_count = get_physical_count(physical_list_head);

	/* Change list from physical to logical */
	ret = change_physical_to_logical(&physical_list_head,
							&logical_list_head);
	if (ret < 0) {
		if (mode_flag & DETAIL) {
			PRINT_FILE_NAME(file);
			STATISTIC_ERR_MSG_WITH_ERRNO(NGMSG_FILE_EXTENT);
		}
		goto out;
	}

	count_file_fragments(file, buf->st_blksize, logical_list_head);
	if (!ret)
		succeed_cnt++;

out:
	close(fd);
	free_ext(physical_list_head);
	free_ext(logical_list_head);
	return 0;
}

static void nat_statistic(char *dir_name, struct stat64 *buf)
{
	int	ret, fd;
	struct fiemap_extent_list *physical_list_head = NULL;
	struct fiemap_extent_list *logical_list_head = NULL;
	char file[F2FS_NAME_LEN + 1];
	struct statfs fbuf;
	unsigned int nid;

	fd = open64(dir_name, O_RDONLY);
	if (fd < 0)
		return;

	fstatfs(fd, &fbuf);
	if (fbuf.f_type != F2FS_SUPER_MAGIC)
		goto out;

	/* We need get total count from kernel in the end, now set it to 0 */
	total_count = regular_count = 0;
	/* 0, 1(node nid), 2(meta nid), 3(root nid)are reserved node id */
	nid = 4;
	while (1) {
		int physical_ext_count = 0;
		physical_list_head = NULL;
		logical_list_head = NULL;
		memset(file, 0, F2FS_NAME_LEN + 1);
		ret = get_nat_extents(fd, &nid, &physical_list_head, file);
		if (ret < 0) {
			/* kernel accessed a invalid inode */
			if (mode_flag & DETAIL) {
				PRINT_FILE_NAME(file);
				STATISTIC_ERR_MSG_WITH_ERRNO(NGMSG_FILE_EXTENT);
			}

			/* (nid == 0) all inodes have been processed */
			if (!nid)
				goto out;

			nid++;
			free_ext(physical_list_head);
			continue;
		}

		nid++;
		/* Get the count of file's continuous physical region */
		physical_ext_count = get_physical_count(physical_list_head);
		/* Change list from physical to logical */
		ret = change_physical_to_logical(&physical_list_head,
								&logical_list_head);
		if (ret < 0) {
			if (mode_flag & DETAIL) {
				PRINT_FILE_NAME(file);
				STATISTIC_ERR_MSG_WITH_ERRNO(NGMSG_FILE_EXTENT);
			}
			free_ext(physical_list_head);
			free_ext(logical_list_head);
			continue;
		}

		defraged_file_count++;
		ret = count_file_fragments(file, buf->st_blksize, logical_list_head);
		if (!ret)
			succeed_cnt++;

		free_ext(physical_list_head);
		free_ext(logical_list_head);
	};

out:
	close(fd);
	return;
}


int fsinfo_get(void)
{
	int rtn = 0;

	memset(&s, 0, sizeof(struct statvfs));

	rtn = statvfs("/data", &s);
	if (rtn < 0) {
		DFRAG_LOGE("fsinfo_get statvfs failed.\n");
		return rtn;
	}

	return rtn;
}

static void show_topn_frag_files(void)
{
	char *file_name;
	int i;

	for (i = 0; i < top_n_files; i++) {
		if(strlen(frag_rank_ratio[i].msg_buffer) <= 0)
			break;
		/* By NAT way, we only have file name */
		file_name = strrchr(frag_rank_ratio[i].msg_buffer,
				'/');
		if (file_name)
			file_name++;
		else
			file_name = frag_rank_ratio[i].msg_buffer;


		f2fsdefrag_send_event(EVENT_IDX_TOPN_BY_SCORE,
						GET_LAST_N_CHAR(file_name, 16), i);
	}

	for (i = 0; i < top_n_files; i++) {
		if(strlen(frag_rank_size[i].msg_buffer) <= 0)
			break;
		/* By NAT way, we only have file name */
		file_name = strrchr(frag_rank_size[i].msg_buffer,
				'/');
		if (file_name)
			file_name++;
		else
			file_name = frag_rank_size[i].msg_buffer;


		f2fsdefrag_send_event(EVENT_IDX_TOPN_BY_SIZE,
						GET_LAST_N_CHAR(file_name, 16), i);
	}
}

static void get_misc_info(char *dev_name, __u32 best_extent_blks)
{
	FILE *fp = NULL;
	char proc_name[PATH_MAX + 1];
	char tmp_sector_info[PROC_INFO_SECTOR + 1];
	char *free_info, *tmp_info;
	__u32 free_blks;
	int ret, i;
	size_t info_len;

	free_info = malloc(PROC_INFO_SIZE);
	if (free_info == NULL)
		return;
	memset(free_info, 0, PROC_INFO_SIZE);

	ret = snprintf(proc_name, PATH_MAX + 1, "/proc/fs/f2fs/%s/misc_info", dev_name);
	if (ret >= (PATH_MAX + 1) || ret < 0)
		goto out;

	fp = fopen(proc_name, "r");
	if (fp == NULL)
		goto out;

	info_len = fread(free_info, 1, PROC_INFO_SIZE - 1, fp);
	if (info_len == 0)
		goto out;

	tmp_info = strstr(free_info, "\n");
	if (!tmp_info)
		goto out;

	tmp_info++;
	info_len -= (tmp_info - free_info);
	for (i = 0; i < FREE_EXTENT_KINDS; i++) {
		if (info_len < PROC_INFO_SECTOR)
			break;

		memset(tmp_sector_info, 0, sizeof(tmp_sector_info));
		strncpy(tmp_sector_info, tmp_info + i * PROC_INFO_SECTOR,
			PROC_INFO_SECTOR);

		info_len -= PROC_INFO_SECTOR;
		free_blks = atoi(tmp_sector_info);
		total_free_size += free_blks;
		if ((unsigned int)(1<<i) < best_extent_blks)
			total_free_frag_size += free_blks;
	}

	tmp_info = strstr(tmp_info, "\n");
	if (!tmp_info)
		goto out;

	tmp_info++;
	info_len -= (tmp_info - free_info);
	if (info_len >= PROC_INFO_SECTOR) {
		memset(tmp_sector_info, 0, sizeof(tmp_sector_info));
		strncpy(tmp_sector_info, tmp_info, PROC_INFO_SECTOR);
		info_len -= PROC_INFO_SECTOR;
		gc_count = atoi(tmp_sector_info);

		if (info_len >= PROC_INFO_SECTOR) {
			memset(tmp_sector_info, 0, sizeof(tmp_sector_info));
			strncpy(tmp_sector_info, tmp_info + PROC_INFO_SECTOR,
				PROC_INFO_SECTOR);
			gc_blks = atoi(tmp_sector_info);
		}
	}

out:
	if (fp)
		fclose(fp);
	free(free_info);
}

static __u64 get_lifetime_write(char *dev_name)
{
	FILE *fp;
	char lifetime_name[PATH_MAX + 1];
	char write_kbytes[20];
	__u64 lifetime_write_kbytes;
	int ret;
	size_t read_len;

	ret = snprintf(lifetime_name, PATH_MAX + 1,
			"/sys/fs/f2fs/%s/lifetime_write_kbytes",
			dev_name);
	if (ret >= (PATH_MAX + 1) || ret < 0)
		return 0;

	fp = fopen(lifetime_name, "r");
	if (fp == NULL)
		return 0;

	memset(write_kbytes, 0, 20);
	read_len = fread(write_kbytes, 1, 20 - 1, fp);
	if (read_len == 0) {
		fclose(fp);
		return 0;
	}

	fclose(fp);

	lifetime_write_kbytes = atoll(write_kbytes);
	return lifetime_write_kbytes;
}

static int get_dev_name(char *mount_point, char *dname)
{
	struct stat mount_stat;
	char *dev_path;
	char *devices_path;
	char *dev_name;
	int ret;

	ret = stat(mount_point, &mount_stat);
	if (ret) {
		DFRAG_LOGE("get stat failed:%d\n", ret);
		return ret;
	}

	dev_path = malloc(PATH_MAX + 1);
	if (!dev_path)
		return -ENOMEM;

	devices_path = malloc(PATH_MAX + 1);
	if (!devices_path) {
		free(dev_path);
		return -ENOMEM;
	}

	memset(dev_path, 0, PATH_MAX + 1);
	memset(devices_path, 0, PATH_MAX + 1);

	snprintf(dev_path, PATH_MAX, "/sys/dev/block/%d:%d",
		 major(mount_stat.st_dev), minor(mount_stat.st_dev));

	ret = readlink(dev_path, devices_path, PATH_MAX);
	if (ret < 0) {
		free(dev_path);
		free(devices_path);
		DFRAG_LOGE("read link failed\n");
		return ret;
	}

	dev_name = strrchr(devices_path, '/');
	if (dev_name == NULL) {
		free(dev_path);
		free(devices_path);
		return -EINVAL;
	}

	strncpy(dname, dev_name + 1, BDEVNAME_SIZE);
	free(dev_path);
	free(devices_path);
	return 0;
}

/*
 * main() -		f2fs online defrag.
 *
 * @argc:		the number of parameter.
 * @argv[]:		the pointer array of parameter.
 */
int main(int argc, char *argv[])
{
	int	opt;
	int	i, j, ret = 0;
	int	flags = FTW_PHYS | FTW_MOUNT;
	int	arg_type = -1;
	int	success_flag = 0;
	char	dir_name[PATH_MAX + 1];
	char	dev_name[PATH_MAX + 1];
	char	mount_point[PATH_MAX + 1];
	char	dname[BDEVNAME_SIZE];
	struct stat64	buf;
	__u32 best_extent_blks = DEFAULT_BEST_EXTENT_BLOCKS;

	DFRAG_LOGE("f2fsdefrag enter.\n");

	return 0;
	memset(imonitor_obj, 0, sizeof(imonitor_obj));

	ret = f2fsdefrag_imonitor_create();
	if (ret) {
		DFRAG_LOGE("f2fsdefrag imonitor create error\n");
		goto out;
	}

	ret = fsinfo_get();
	if (ret < 0)
		goto out;

	/* Parse arguments */
	if (argc == 1)
		goto out;

	memset(mount_point, 0, PATH_MAX + 1);
	memset(dname, 0, BDEVNAME_SIZE);

	while ((opt = getopt(argc, argv, "e:f:vctn:")) != EOF) {
		switch (opt) {
		case 'v':
			mode_flag |= DETAIL;
			break;
		case 'c':
			mode_flag |= STATISTIC;
			break;
		case 'e':
			best_extent_blks = atoi(optarg);
			if (best_extent_blks == 0) {
				best_extent_blks = DEFAULT_BEST_EXTENT_BLOCKS;
				DFRAG_LOGE("illegal best extent blks, set to default:%d\n",
						best_extent_blks);
			}
			break;
		case 'f':
			strncpy(mount_point, optarg, strnlen(optarg, PATH_MAX));
			ret = get_dev_name(mount_point, dname);
			if (ret) {
				DFRAG_LOGE("get device name failed\n");
				goto out;
			}
			break;
		case 'n':
			top_n_files = atoi(optarg);
			if (top_n_files > SHOW_FRAG_FILES)
				goto out;
			break;
		case 't':
			mode_flag |= NAT;
			break;
		default:
			goto out;
		}
	}

	if (mode_flag & NAT) {
		if ((argc - optind) > 1)
			goto out;
	}

	current_uid = getuid();

	memset(frag_rank_ratio, 0,
		sizeof(struct frag_statistic_ino) * SHOW_FRAG_FILES);
	memset(frag_rank_size, 0,
		sizeof(struct frag_statistic_ino) * SHOW_FRAG_FILES);

	/* Main process */
	for (i = optind; i < argc; i++) {
		succeed_cnt = 0;
		total_frag_cnt = 0;
		total_frag_size = 0;
		regular_count = 0;
		total_count = 0;
		frag_files_before_defrag = 0;
		frag_files_after_defrag = 0;
		extents_before_defrag = 0;
		extents_after_defrag = 0;
		defraged_file_count = 0;
		files_block_count = 0;
		blocks_per_group = 0;
		feature_incompat = 0;
		log_groups_per_flex = 0;

		memset(dir_name, 0, PATH_MAX + 1);
		memset(dev_name, 0, PATH_MAX + 1);
		memset(lost_found_dir, 0, PATH_MAX + 1);
		if (mode_flag & DETAIL) {
			memset(frag_rank_ratio, 0,
				sizeof(struct frag_statistic_ino) * SHOW_FRAG_FILES);
			memset(frag_rank_size, 0,
				sizeof(struct frag_statistic_ino) * SHOW_FRAG_FILES);
		}

#if BYTE_ORDER != BIG_ENDIAN && BYTE_ORDER != LITTLE_ENDIAN
		DFRAG_LOGE("%s,%d Endian's type is not big/little endian\n", __func__, __LINE__);
		PRINT_ERR_MSG("Endian's type is not big/little endian");
		PRINT_FILE_NAME(argv[i]);
		continue;
#endif

		if (lstat64(argv[i], &buf) < 0) {
			perror(NGMSG_FILE_INFO);
			PRINT_FILE_NAME(argv[i]);
			DFRAG_LOGE("%s,%d Failed to get file information\n", __func__, __LINE__);
			continue;
		}

		/* Handle i.e. lvm device symlinks */
		if (S_ISLNK(buf.st_mode)) {
			struct stat64	buf2;

			if (stat64(argv[i], &buf2) == 0 &&
			    S_ISBLK(buf2.st_mode))
				buf = buf2;
		}

		if (S_ISBLK(buf.st_mode)) {
			/* Block device */
			strncpy(dev_name, argv[i], strnlen(argv[i], PATH_MAX));
			if (get_mount_point(argv[i], dir_name, PATH_MAX) < 0)
				continue;
			if (lstat64(dir_name, &buf) < 0) {
				perror(NGMSG_FILE_INFO);
				PRINT_FILE_NAME(argv[i]);
				DFRAG_LOGE("%s,%d Failed to get file information\n",__func__,__LINE__);
				continue;
			}
			arg_type = DEVNAME;
			if (!(mode_flag & STATISTIC))
				DFRAG_LOGE("defragmentation for device(%s)\n",
					argv[i]);
		} else if (S_ISDIR(buf.st_mode)) {
			/* Directory */
			if (access(argv[i], R_OK) < 0) {
				perror(argv[i]);
				DFRAG_LOGE("%s,%d Failed to Access DIR.\n",__func__,__LINE__);
				continue;
			}
			arg_type = DIRNAME;
			strncpy(dir_name, argv[i], strnlen(argv[i], PATH_MAX));
		} else if (S_ISREG(buf.st_mode)) {
			/* Regular file */
			arg_type = FILENAME;
		} else {
			/* Irregular file */
			PRINT_ERR_MSG(NGMSG_FILE_UNREG);
			PRINT_FILE_NAME(argv[i]);
			DFRAG_LOGE("%s,%d Irregular file.\n",__func__,__LINE__);
			continue;
		}

		/* Set blocksize */
		block_size = buf.st_blksize;

		/* For device case,
		 * filesystem type checked in get_mount_point()
		 */
		if (arg_type == FILENAME || arg_type == DIRNAME) {
			if (realpath(argv[i], dir_name) == NULL) {
				perror("Couldn't get full path");
				PRINT_FILE_NAME(argv[i]);
				DFRAG_LOGE("%s,%d Couldn't get full path.\n",__func__,__LINE__);
				continue;
			}
		}

		if (current_uid == ROOT_UID) {
			blocks_per_group = best_extent_blks;
			feature_incompat = 0;
		}

		DFRAG_LOGE("%s begin\n", argv[i]);

		switch (arg_type) {
			int mount_dir_len = 0;

		case DIRNAME:
			if (!(mode_flag & STATISTIC))
				DFRAG_LOGE("defragmentation "
					"for directory(%s)\n", argv[i]);

			mount_dir_len = strnlen(lost_found_dir, PATH_MAX);

			strncat(lost_found_dir, "/lost+found",
				PATH_MAX - strnlen(lost_found_dir, PATH_MAX));

			/* Not the case("f2fsdefrag mount_piont_dir") */
			if (dir_name[mount_dir_len] != '\0') {
				/*
				 * "f2fsdefrag mount_piont_dir/lost+found"
				 * or "f2fsdefrag mount_piont_dir/lost+found/"
				 */
				if (strncmp(lost_found_dir, dir_name,
					    strnlen(lost_found_dir,
						    PATH_MAX)) == 0 &&
				    (dir_name[strnlen(lost_found_dir,
						      PATH_MAX)] == '\0' ||
				     dir_name[strnlen(lost_found_dir,
						      PATH_MAX)] == '/')) {
					PRINT_ERR_MSG(NGMSG_LOST_FOUND);
					PRINT_FILE_NAME(argv[i]);
					continue;
				}

				/* "e4defrag mount_piont_dir/else_dir" */
				memset(lost_found_dir, 0, PATH_MAX + 1);
			}
		case DEVNAME:
			if (arg_type == DEVNAME) {
				strncpy(lost_found_dir, dir_name,
					strnlen(dir_name, PATH_MAX));
				strncat(lost_found_dir, "/lost+found/",
					PATH_MAX - strnlen(lost_found_dir,
							   PATH_MAX));
			}

			/* nftw may take a long time to calc, for NAT way, skip it */
			if (!(mode_flag & NAT))
				nftw64(dir_name, calc_entry_counts, FTW_OPEN_FD, flags);


			if (mode_flag & STATISTIC) {
				if (mode_flag & DETAIL)
					DFRAG_LOGE("%-40s%10s/%-10s%9s\n",
					"<File>", "now", "best", "size/ext");

				if (!(mode_flag & DETAIL) &&
						current_uid != ROOT_UID) {
					DFRAG_LOGE(" Done.\n");
					success_flag = 1;
					continue;
				}

				if (mode_flag & NAT)
					nat_statistic(dir_name, &buf);
				else
					nftw64(dir_name, file_statistic,
								FTW_OPEN_FD, flags);

				if (succeed_cnt != 0 &&
					current_uid == ROOT_UID &&
					mode_flag & DETAIL) {
					if (mode_flag & DETAIL)
						DFRAG_LOGE("\n");

					show_topn_frag_files();
				}
				break;
			}
			DFRAG_LOGE("Defragment unsupported\n");
			break;
		case FILENAME:
			total_count = 1;
			regular_count = 1;
			strncat(lost_found_dir, "/lost+found/",
				PATH_MAX - strnlen(lost_found_dir,
						   PATH_MAX));
			if (strncmp(lost_found_dir, dir_name,
				    strnlen(lost_found_dir,
					    PATH_MAX)) == 0) {
				PRINT_ERR_MSG(NGMSG_LOST_FOUND);
				PRINT_FILE_NAME(argv[i]);
				continue;
			}

			if (mode_flag & STATISTIC) {
				if (mode_flag & NAT)
					nat_statistic(argv[i], &buf);
				else
					file_statistic(argv[i], &buf, FTW_F, NULL);

				break;
			}
			DFRAG_LOGE("Defragment unsupported\n");
			break;
		}

		if (succeed_cnt != 0)
			success_flag = 1;
		if (mode_flag & STATISTIC) {
			if (current_uid != ROOT_UID) {
				DFRAG_LOGE(" Done.\n");
				continue;
			}

			if (!succeed_cnt) {
				if (mode_flag & DETAIL)
					DFRAG_LOGE("\n");

				if (arg_type == DEVNAME)
					DFRAG_LOGE(" In this device(%s), "
					"none can be defragmented.\n", argv[i]);
				else if (arg_type == DIRNAME)
					DFRAG_LOGE(" In this directory(%s), "
					"none can be defragmented.\n", argv[i]);
				else
					DFRAG_LOGE(" This file(%s) "
					"can't be defragmented.\n", argv[i]);
			} else {
				f2fsdefrag_send_event(EVENT_IDX_FS_TARGET_INFO,
									GET_LAST_N_CHAR(argv[i], 16), 0);

				total_frag_blks += total_frag_size;
				total_data_blks += files_block_count;
			}
		}

		DFRAG_LOGE("%s end\n", argv[i]);
	}

	if (!(mode_flag & DETAIL) && succeed_cnt)
		show_topn_frag_files();

	if (strlen(mount_point) > 0)
		get_misc_info(dname, best_extent_blks);

	float ratio = 0.0;
	float free_ratio = 0.0;

	if (strlen(mount_point) > 0)
		lifetime_write_kbytes = get_lifetime_write(dname);
	if (total_data_blks)
		ratio = (float)total_frag_blks * 100 / total_data_blks;
	if (total_free_size)
		free_ratio = (float)total_free_frag_size * 100 / total_free_size;

	f2fsdefrag_send_event(EVENT_IDX_FS_GENERAL_INFO, mount_point, 0);

	DFRAG_LOGE("f2fsdefrag exit.\n");

	f2fsdefrag_imonitor_destroy();

	if (success_flag)
		return 0;

	exit(1);

out:
	f2fsdefrag_imonitor_destroy();

	DFRAG_LOGE(MSG_USAGE);
	DFRAG_LOGE("f2fsdefrag exit.\n");
	exit(1);
}
