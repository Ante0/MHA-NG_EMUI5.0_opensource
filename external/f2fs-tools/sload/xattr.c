#include <f2fs_fs.h>
#include "sload.h"
#include "node.h"
#include "f2fs.h"
#include "xattr.h"
#include "index.h"

#define XATTR_CREATE 0x1
#define XATTR_REPLACE 0x2
static void *read_all_xattrs(struct f2fs_sb_info *sbi, struct f2fs_node *inode)
{
	struct f2fs_xattr_header *header;
	size_t size = PAGE_SIZE;
	void *txattr_addr;
	int ret;

	txattr_addr = calloc(size, 1);
	ASSERT(txattr_addr);
	if (!txattr_addr)
		return NULL;

	/* Read from xattr node block. */
	if (inode->i.i_xattr_nid) {
		struct node_info ni;
		struct f2fs_node *node_block;
		get_node_info(sbi, inode->i.i_xattr_nid, &ni);

		node_block = calloc(BLOCK_SZ, 1);
		ret = dev_read_block(node_block, ni.blk_addr);
		ASSERT(ret >= 0);

		memcpy(txattr_addr, node_block, PAGE_SIZE);
	}

	header = XATTR_HDR(txattr_addr);

	/* Never been allocated xattrs */
	if (le32_to_cpu(header->h_magic) != F2FS_XATTR_MAGIC) {
		header->h_magic = cpu_to_le32(F2FS_XATTR_MAGIC);
		header->h_refcount = cpu_to_le32(1);
	}
	return txattr_addr;

}

static struct f2fs_xattr_entry *__find_xattr(void *base_addr, int index,
				size_t len, const char *name)
{
	struct f2fs_xattr_entry *entry;
	list_for_each_xattr(entry, base_addr) {
		if (entry->e_name_index != index)
			continue;
		if (entry->e_name_len != len)
			continue;
		if (!memcmp(entry->e_name, name, len))
			break;
	}
	return entry;
}

static inline int write_all_xattrs(struct f2fs_sb_info *sbi,
				struct f2fs_node *inode, __u32 hsize, void *txattr_addr)
{
	size_t inline_size = 0; /* No inline_xattr considering */
	void *xattr_addr;
	struct dnode_of_data dn;
	struct node_info ni;
	struct f2fs_node *xattr_node;
	nid_t new_nid = 0;
	block_t blk;
	int ret;

	if (hsize > inline_size && !inode->i.i_xattr_nid) {
		if (!f2fs_alloc_nid(sbi, &new_nid, 1))
			return -ENOSPC;
		set_new_dnode(&dn, inode, NULL, new_nid);
		/* NAT entry would be updated by new_node_page. */
		blk = new_node_page(sbi, &dn, XATTR_NODE_OFFSET);
		ASSERT(dn.node_page);
		xattr_node = dn.node_page;

		inode->i.i_xattr_nid = new_nid;

	} else if (hsize > inline_size && inode->i.i_xattr_nid){
		set_new_dnode(&dn, inode, NULL, inode->i.i_xattr_nid);
		get_node_info(sbi, inode->i.i_xattr_nid, &ni);
		blk = ni.blk_addr;
		xattr_node = calloc(BLOCK_SZ, 1);
		ASSERT(xattr_node);
		ret = dev_read_block(xattr_node, ni.blk_addr);
		ASSERT(ret >= 0);
	} else
		return -1;

	/* write to xattr node block */
	xattr_addr = (void *)xattr_node;
	memcpy(xattr_addr, txattr_addr + inline_size, PAGE_SIZE -
					sizeof(struct node_footer));

	ret = dev_write_block(xattr_node, blk);
	ASSERT(ret >= 0);

	return 0;
}

int f2fs_setxattr(struct f2fs_sb_info *sbi, nid_t ino, int index, const char *name,
				const void *value, size_t size, int flags)
{
	struct f2fs_node *inode;
	void *base_addr;
	struct f2fs_xattr_entry *here, *last;
	struct node_info ni;
	int error = -ENOMEM;
	int len;
	int found, newsize;
	__u32 new_hsize;
	int ret;

	if (name == NULL)
		return -EINVAL;

	if (value == NULL)
		return -EINVAL;

	len = strlen(name);

	if (len > F2FS_NAME_LEN || size > MAX_VALUE_LEN())
		return -ERANGE;

	if (ino < 3)
		return -EINVAL;

	/* Now We just support selinux */
	ASSERT(index == F2FS_XATTR_INDEX_SECURITY);

	get_node_info(sbi, ino, &ni);
	inode = calloc(BLOCK_SZ, 1);
	ASSERT(inode);
	ret = dev_read_block(inode, ni.blk_addr);
	ASSERT(ret >= 0);

	base_addr = read_all_xattrs(sbi, inode);

	if (!base_addr)
		goto exit;

	here = __find_xattr(base_addr, index, len, name);

	found = IS_XATTR_LAST_ENTRY(here) ? 0 : 1;

	if ((flags & XATTR_REPLACE) && !found) {
		error = -ENODATA;
		goto exit;
	} else if ((flags & XATTR_CREATE) && found) {
		error = -EEXIST;
		goto exit;
	}

	last = here;
	while (!IS_XATTR_LAST_ENTRY(last))
		last = XATTR_NEXT_ENTRY(last);

	newsize = XATTR_ALIGN(sizeof(struct f2fs_xattr_entry) + len + size);

	/* 1. Check space */
	if (value) {
		int free;
		/*
		 * If value is NULL, it is remove operation.
		 * In case of update operation, we calculate free.
		 */
		free = MIN_OFFSET(inode) - ((char *)last - (char *)base_addr);
		if (found)
			free = free + ENTRY_SIZE(here);
		if (free < newsize) {
			error = -ENOSPC;
			goto exit;
		}
	}

	/* 2. Remove old entry */
	if (found) {
		/*
		 * If entry if sound, remove old entry.
		 * If not found, remove operation is not needed
		 */
		struct f2fs_xattr_entry *next = XATTR_NEXT_ENTRY(here);
		int oldsize = ENTRY_SIZE(here);

		memmove(here, next, (char *)last - (char *)next);
		last = (struct f2fs_xattr_entry *)((char *)last - oldsize);
		memset(last, 0, oldsize);

	}

	new_hsize = (char *)last - (char *)base_addr;

	/* 3. Write new entry */
	if (value) {
		char *pval;
		/*
		 * Before we come here, old entry is removed.
		 * We just write new entry.
		 */
		memset(last, 0, newsize);
		last->e_name_index = index;
		last->e_name_len = len;
		memcpy(last->e_name, name, len);
		pval = last->e_name + len;
		memcpy(pval, value, size);
		last->e_value_size = cpu_to_le16(size);
		new_hsize += newsize;
	}

	error = write_all_xattrs(sbi, inode, new_hsize, base_addr);
	if (error)
		goto exit;

	/* inode need update */
	ret = dev_write_block(inode, ni.blk_addr);
	ASSERT(ret >= 0);
exit:
	free(inode);
	free(base_addr);
	return error;
}


int inode_set_selinux(struct f2fs_sb_info *sbi, u32 inode_num, const char *secon)
{
    if (!secon)
        return 0;

    return f2fs_setxattr(sbi, inode_num, F2FS_XATTR_INDEX_SECURITY,
        XATTR_SELINUX_SUFFIX, secon, strlen(secon), 1);
}
