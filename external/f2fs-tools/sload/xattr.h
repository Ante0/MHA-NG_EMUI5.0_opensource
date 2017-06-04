#ifndef _XATTR_H_
#define _XATTR_H_

#include <f2fs_fs.h>
#include "f2fs.h"

struct f2fs_xattr_header {
	__le32 h_magic; /* magic number for identification */
	__le32 h_refcount; /* reference count */
	__u32 h_sloadd[4]; /* zero right now */
};

struct f2fs_xattr_entry {
	__u8 e_name_index;
	__u8 e_name_len;
	__le16 e_value_size; /* size of attribute value */
	char e_name[0]; /* attribute name */
};

#define XATTR_ROUND	(3)

#define XATTR_SELINUX_SUFFIX "selinux"
#define F2FS_XATTR_INDEX_SECURITY	6
#define IS_XATTR_LAST_ENTRY(entry) (*(__u32 *)(entry) == 0)

#define XATTR_HDR(ptr)	((struct f2fs_xattr_header *)(ptr))
#define XATTR_ENTRY(ptr) 	((struct f2fs_xattr_entry *)(ptr))
#define F2FS_XATTR_MAGIC	0xF2F52011

#define XATTR_NEXT_ENTRY(entry) ((struct f2fs_xattr_entry *) ((char *)(entry) +\
		ENTRY_SIZE(entry)))
#define XATTR_FIRST_ENTRY(ptr)	(XATTR_ENTRY(XATTR_HDR(ptr) + 1))

#define XATTR_ALIGN(size)	((size + XATTR_ROUND) & ~XATTR_ROUND)

#define ENTRY_SIZE(entry) (XATTR_ALIGN(sizeof(struct f2fs_xattr_entry) + \
			entry->e_name_len + le16_to_cpu(entry->e_value_size)))

#define list_for_each_xattr(entry, addr) \
		for (entry = XATTR_FIRST_ENTRY(addr); \
			!IS_XATTR_LAST_ENTRY(entry); \
			entry = XATTR_NEXT_ENTRY(entry))

#define MIN_OFFSET(i)   XATTR_ALIGN(0 + PAGE_SIZE -  \
                sizeof(struct node_footer) - sizeof(__u32))

#define MAX_VALUE_LEN(i) (MIN_OFFSET(i) - \
                sizeof(struct f2fs_xattr_header) -  \
                sizeof(struct f2fs_xattr_entry))

#endif
