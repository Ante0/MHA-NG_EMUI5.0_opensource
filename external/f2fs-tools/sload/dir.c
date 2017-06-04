#include <f2fs_fs.h>
#include "sload.h"
#include "f2fs.h"
#include "node.h"
#include "index.h"
#include "segment.h"
#include "bit_operations.h"

static unsigned int dir_buckets(unsigned int level)
{
    if (level < MAX_DIR_HASH_DEPTH / 2)
        return 1 << level;
    else
        return MAX_DIR_BUCKETS;
}

static unsigned int bucket_blocks(unsigned int level)
{
    if (level < MAX_DIR_HASH_DEPTH / 2)
        return 2;
    else
        return 4;
}

static unsigned long dir_block_index(unsigned int level,
				int dir_level, unsigned int idx)
{
	unsigned long i;
	unsigned long bidx = 0;

	for (i = 0; i < level; i++)
		bidx += dir_buckets(i + dir_level) * bucket_blocks(i);
	bidx += idx * bucket_blocks(level);
	return bidx;
}

int room_for_filename(const void *bitmap, int slots, int max_slots)
{
	int bit_start = 0;
	int zero_start, zero_end;
next:
	zero_start = find_next_zero_bit_le_sload(bitmap, max_slots, bit_start);
	if (zero_start >= max_slots)
		return max_slots;

	zero_end = find_next_bit_le_sload(bitmap, max_slots, zero_start + 1);

	if (zero_end - zero_start >= slots)
			return zero_start;
	bit_start = zero_end;
	goto next;

}
static inline void make_dentry_ptr(struct f2fs_dentry_ptr *d,
				void *src, int type)
{
	if (type == 1) {
		struct f2fs_dentry_block *t = (struct f2fs_dentry_block *)src;
		d->max = NR_DENTRY_IN_BLOCK;
		d->bitmap = &t->dentry_bitmap;
		d->dentry = t->dentry;
		d->filename = t->filename;
	} else {
		struct f2fs_inline_dentry *t = (struct f2fs_inline_dentry *)src;
		d->max = NR_INLINE_DENTRY;
		d->bitmap = &t->dentry_bitmap;
		d->dentry = t->dentry;
		d->filename = t->filename;
	}
}

#define S_SHIFT 12
static unsigned char f2fs_type_by_mode[S_IFMT >> S_SHIFT] = {
    [S_IFREG >> S_SHIFT]    = F2FS_FT_REG_FILE,
    [S_IFDIR >> S_SHIFT]    = F2FS_FT_DIR,
    [S_IFCHR >> S_SHIFT]    = F2FS_FT_CHRDEV,
    [S_IFBLK >> S_SHIFT]    = F2FS_FT_BLKDEV,
    [S_IFIFO >> S_SHIFT]    = F2FS_FT_FIFO,
    [S_IFSOCK >> S_SHIFT]   = F2FS_FT_SOCK,
    [S_IFLNK >> S_SHIFT]    = F2FS_FT_SYMLINK,
};

static void set_de_type(struct f2fs_dir_entry *de, umode_t mode)
{
    de->file_type = f2fs_type_by_mode[(mode & S_IFMT) >> S_SHIFT];
}

void f2fs_update_dentry(nid_t ino, umode_t mode, struct f2fs_dentry_ptr *d,
				const unsigned char *name, int len, f2fs_hash_t name_hash,
				unsigned int bit_pos)
{
	struct f2fs_dir_entry *de;
	int slots = GET_DENTRY_SLOTS(len);
	int i;

	de = &d->dentry[bit_pos];
	de->name_len = len;
	de->hash_code = name_hash;
	memcpy(d->filename[bit_pos], name, len);
	d->filename[bit_pos][len] = 0;
	de->ino = cpu_to_le32(ino);
	set_de_type(de, mode);
	for (i = 0; i < slots; i++)  {
		set_bit(bit_pos + i, (void *)d->bitmap);
	}

}

/*
 * f2fs_add_link - Add a new file(dir) to parent dir.
 */
int f2fs_add_link(struct f2fs_sb_info *sbi, struct f2fs_node *parent,
				struct f2fs_node *child)
{
	int level = 0, current_depth, bit_pos;
	int nbucket, nblock, bidx, block;
	const unsigned char *name = child->i.i_name;
	int name_len = child->i.i_namelen;
	int slots = GET_DENTRY_SLOTS(name_len);
	unsigned int dentry_hash = f2fs_dentry_hash(name, name_len);
	struct f2fs_dentry_block * dentry_blk;
	struct f2fs_dentry_ptr d;
	struct dnode_of_data dn = {0};
	bool need_new_block = 0;
	block_t blk;
	nid_t pino = parent->footer.ino;
	nid_t ino = child->footer.ino;
	umode_t mode = child->i.i_mode;
	int ret;

	if (parent == NULL || child == NULL)
		return -EINVAL;

	if (!pino) {
		ERR_MSG("Wrong parent ino:%d \n", pino);
		return -EINVAL;
	}

	memset(&d, 0, sizeof(struct f2fs_dentry_ptr));
	dentry_blk = calloc(BLOCK_SZ, 1);
	if (dentry_blk == NULL) {
		ERR_MSG("\tError: Calloc Failed!\n");
		return -1;
	}
	current_depth = parent->i.i_current_depth;
start:
	if (current_depth == MAX_DIR_HASH_DEPTH) {
		ret = -ENOSPC;
		ERR_MSG("\tError: MAX_DIR_HASH\n");
		goto free_dentry_blk;
	}

	if (level == current_depth) { /* Need a new dentry block */
		++current_depth;
	}

	nbucket = dir_buckets(level);
	nblock = bucket_blocks(level);
	bidx = dir_block_index(level, 0, le32_to_cpu(dentry_hash % nbucket));

	set_new_dnode(&dn, parent, NULL, pino);

	for (block = bidx; block <= (bidx + nblock - 1); block++) {

		/* Firstly, we should know the direct node of target data page */
		get_dnode_of_data(sbi, &dn, pino, block, ALLOC_NODE);
		blk = dn.data_blkaddr;

		if (blk == NULL_ADDR) {
			need_new_block = 1;
			goto new_dentry_page;
		}
		ret = dev_read_block(dentry_blk, blk);
		if (ret < 0) {
			ERR_MSG("\tError: Fail to Write block\n");
			goto free_node_page;
		}
		bit_pos = room_for_filename(dentry_blk->dentry_bitmap,
						slots, NR_DENTRY_IN_BLOCK);

		if (bit_pos < NR_DENTRY_IN_BLOCK)
				goto add_dentry;

		if (dn.node_page && dn.node_page != dn.inode_page) {
			free(dn.node_page);
		}
		dn.node_page = NULL;
	}
	level ++;
	goto start;

new_dentry_page:

	memset(dentry_blk, 0, BLOCK_SZ);
	blk = allocate_data_block(sbi, &dn, NULL, CURSEG_HOT_DATA);

	/* Update the direct node's index */
	ASSERT(dn.node_page);
	dn.data_blkaddr = blk;
	set_data_blkaddr(&dn);
	ret = dev_write_block(dn.node_page, dn.node_blkaddr);
	if (ret < 0) {
		ERR_MSG("\tError: Fail to Write block\n");
		goto free_node_page;
	}

	if (dn.node_page && dn.node_page != dn.inode_page) {
		free(dn.node_page);
		dn.node_page = NULL;
	}

	bit_pos = 0;

add_dentry:
	make_dentry_ptr(&d, (void *)dentry_blk, 1);
	f2fs_update_dentry(ino, mode, &d, name, name_len, dentry_hash, bit_pos);

	ret = dev_write_block(dentry_blk, blk);
    if (ret < 0) {
        ERR_MSG("\tError: Fail to Write block\n");
        goto free_node_page;
    }
	/* Parent inode needs updating, because its inode info may be changed.
	 * such as i_current_depth and i_blocks.
	 */
	parent->i.i_current_depth = current_depth;
	if (need_new_block) {
		if ((block + 1) * F2FS_BLKSIZE > parent->i.i_size)
			parent->i.i_size = (block + 1) * F2FS_BLKSIZE;
	}
free_node_page:
	if (dn.node_page && dn.node_page != dn.inode_page)
		free(dn.node_page);
free_dentry_blk:
	free(dentry_blk);
	return 0;
}

struct f2fs_dir_entry *find_target_dentry(const char *name,
				unsigned int len, unsigned int namehash, int *max_slots,
				struct f2fs_dentry_ptr *d)
{
	struct f2fs_dir_entry *de;
	unsigned long bit_pos = 0;
	int max_len = 0;

	if (max_slots)
		*max_slots = 0;
	while (bit_pos < d->max) {
		if (!test_bit(bit_pos, d->bitmap)) {
			bit_pos++;
			max_len++;
			continue;
		}

		de = &d->dentry[bit_pos];
		if (le16_to_cpu(de->name_len) == len &&
			de->hash_code == namehash &&
			!memcmp(d->filename[bit_pos], name, len)) {
			goto found;
		}

		if (max_slots && max_len > *max_slots)
				*max_slots = max_len;
		max_len = 0;
		bit_pos += GET_DENTRY_SLOTS(le16_to_cpu(de->name_len));
	}
	de = NULL;
found:
	if (max_slots && max_len > *max_slots)
		*max_slots = max_len;
	return de;
}

static struct f2fs_dir_entry *find_in_block(void *dentry_page,
				const char *name, f2fs_hash_t namehash,
				int *max_slots)
{
	struct f2fs_dentry_block *dentry_blk;
	struct f2fs_dir_entry *de;
	struct f2fs_dentry_ptr d;
	int len = strlen((const char *)name);

	dentry_blk = (struct f2fs_dentry_block *)dentry_page;
	make_dentry_ptr(&d, (void *)dentry_blk, 1);
	de = find_target_dentry(name, len, namehash, max_slots, &d);
	return de;
}
/*
 * find_in_level - if the file exists in this level.
 * @return -1: error
 			0: not exist
			1: exist
 */
static int find_in_level(struct f2fs_sb_info *sbi,struct f2fs_node *dir,
				unsigned int level,	const char *fname, int len)
{
	unsigned int nbucket, nblock;
	unsigned int bidx, end_block;
	struct f2fs_dir_entry *de = NULL;
	struct dnode_of_data dn = {0};
	void *dentry_page;
	int max_slots = 214;
	nid_t ino = dir->footer.ino;
	f2fs_hash_t namehash;
	int ret = 0;

	namehash = f2fs_dentry_hash((unsigned char *)fname, len);

	nbucket = dir_buckets(level);
	nblock = bucket_blocks(level);

	bidx = dir_block_index(level, 0, le32_to_cpu(namehash) % nbucket);
	end_block = bidx + nblock;

	dentry_page = calloc(BLOCK_SZ, 1);
	if (dentry_page == NULL) {
		ERR_MSG("\tError: Calloc Failed!\n");
		return -1;
	}

	set_new_dnode(&dn, dir, NULL, ino);

	for (; bidx < end_block; bidx++) {

		if (dn.node_page && dn.node_page != dn.inode_page)
			free(dn.node_page);
		dn.node_page = NULL;

		get_dnode_of_data(sbi, &dn, ino, bidx, LOOKUP_NODE);
		if (dn.data_blkaddr == NULL_ADDR)
			continue;
		ret = dev_read_block(dentry_page, dn.data_blkaddr);
		if (ret < 0) {
			ERR_MSG("\tError: Fail to Read block\n");
			goto free_node_page;
		}

		de = find_in_block(dentry_page, fname, namehash, &max_slots);
		if (de) {
			ret = 1;
			break;
		}
	}
free_node_page:
	if (dn.node_page && dn.node_page != dn.inode_page)
		free(dn.node_page);
	free(dentry_page);

	return ret;
}

bool f2fs_find_entry(struct f2fs_sb_info *sbi, struct f2fs_node *dir,
				const char *name, int len)
{
	unsigned int max_depth;
	unsigned int level;
	bool ret = false;

	max_depth = dir->i.i_current_depth;
	for (level = 0; level < max_depth; level ++) {
		ret = find_in_level(sbi, dir, level, name, len);
		if (ret)
			break;
	}
	return ret;
}

int make_empty_dir(struct f2fs_sb_info *sbi, struct f2fs_node *inode)
{
	struct f2fs_dentry_block *dent_blk;
	nid_t ino = inode->footer.ino;
	nid_t pino = inode->i.i_pino;
	block_t blk;
	struct dnode_of_data dn;
	int ret;

	dent_blk = calloc(BLOCK_SZ, 1);
	if (dent_blk == NULL) {
		ERR_MSG("\tError: Calloc Failed!\n");
		return -1;
	}

	dent_blk->dentry[0].hash_code = 0;
	dent_blk->dentry[0].ino = ino;
	dent_blk->dentry[0].name_len = cpu_to_le16(1);
	dent_blk->dentry[0].file_type = F2FS_FT_DIR;
	memcpy(dent_blk->filename[0], ".", 1);

    dent_blk->dentry[1].hash_code = 0;
    dent_blk->dentry[1].ino = pino;
    dent_blk->dentry[1].name_len = cpu_to_le16(2);
    dent_blk->dentry[1].file_type = F2FS_FT_DIR;
    memcpy(dent_blk->filename[1], "..", 2);

	dent_blk->dentry_bitmap[0] = (1 << 1) | (1 << 0);

	set_new_dnode(&dn, inode, NULL, ino);
	blk = allocate_data_block(sbi, &dn, NULL, CURSEG_HOT_DATA);

	ret = dev_write_block(dent_blk, blk);
	if (ret < 0) {
		ERR_MSG("\tError: Fail to Write block\n");
		free(dent_blk);
		return ret;
	}

	inode->i.i_addr[0] = blk;
	return 0;

}

int page_symlink(struct f2fs_sb_info *sbi, struct f2fs_node *inode,
				const char *symname, int symlen)
{
	struct dnode_of_data dn;
	char *data_page;
	block_t blk;
	nid_t ino = inode->footer.ino;
	int ret;

	data_page = calloc(BLOCK_SZ, 1);
	if (data_page == NULL) {
		ERR_MSG("\tError: Calloc Failed!\n");
		return -1;
	}
	memcpy(data_page, symname, symlen);

	set_new_dnode(&dn, inode, NULL, ino);
	blk = allocate_data_block(sbi, &dn, NULL, CURSEG_WARM_DATA);

	ret = dev_write_block(data_page, blk);

	if (ret < 0) {
        ERR_MSG("\tError: Fail to Write block\n");
		free(data_page);
		return ret;
    }
	inode->i.i_addr[0] = blk;
	return 0;
}

int init_inode_page(struct f2fs_sb_info *sbi, struct f2fs_node *node_page,
				int ino, int pino, const char *name, int len, umode_t mode,
				u16 uid, u16 gid, u32 mtime, const char *symname)
{
	int err = -1, symlen;
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);

    node_page->i.i_mode = mode;
    node_page->i.i_advise = 0;
    node_page->i.i_uid = uid;
    node_page->i.i_gid = gid;
    node_page->i.i_links = 1;
    node_page->i.i_size = 0;
    node_page->i.i_blocks = 0;
    node_page->i.i_atime = mtime;
    node_page->i.i_ctime = mtime;
    node_page->i.i_mtime = mtime;
    node_page->i.i_atime_nsec = 0;
    node_page->i.i_ctime_nsec = 0;
    node_page->i.i_mtime_nsec = 0;
    node_page->i.i_generation = 0;
    node_page->i.i_current_depth = 1;
    node_page->i.i_xattr_nid = 0;
    node_page->i.i_flags = 0;
    node_page->i.i_inline = 0;
    node_page->i.i_pino = pino;
    node_page->i.i_namelen = len;
    memcpy(node_page->i.i_name, name, len);
    node_page->i.i_name[len] = 0;
    node_page->footer.ino = ino;
    node_page->footer.nid = ino;
	node_page->footer.flag = cpu_to_le32(0);
	node_page->footer.cp_ver = le64_to_cpu(ckpt->checkpoint_ver);

	if (S_ISDIR(mode)) {
		node_page->i.i_size = 4096;
		node_page->i.i_links ++;
		err = make_empty_dir(sbi, node_page);
	} else if (S_ISLNK(mode)) {
		ASSERT(symname);
		symlen = strlen(symname);
		node_page->i.i_size = symlen;
		err = page_symlink(sbi, node_page, symname, symlen);
	}
	return err;
}

int f2fs_mkdir(struct f2fs_sb_info *sbi, nid_t pino, umode_t mode,
				const char *name, int len, u16 uid, u16 gid, u32 mtime)
{
	block_t node_blk;
	nid_t ino = -1;
	struct dnode_of_data dn;
	struct f2fs_node *parent, *child;
	struct node_info ni;
	int ret;

	/* Find if there is a */
	get_node_info(sbi, pino, &ni);
	parent = calloc(BLOCK_SZ, 1);
    if (parent == NULL) {
        ERR_MSG("\tError: Calloc Failed!\n");
        return -1;
    }
	ret = dev_read_block(parent, ni.blk_addr);
    if (ret < 0) {
        ERR_MSG("\tError: Fail to Read block\n");
        ino = -1;
        goto free_parent_dir;
    }

	ret = f2fs_find_entry(sbi, parent, name, len);
	if (ret != 0) {
		ino = -1;
		goto free_parent_dir;
	}

	child = calloc(BLOCK_SZ, 1);
    if (child == NULL) {
        ERR_MSG("\tError: Calloc Failed!\n");
        ino = -1;
        goto free_parent_dir;
    }

	f2fs_alloc_nid(sbi, &ino, 1);

	init_inode_page(sbi, child, ino, parent->footer.ino,
					name, len, mode | S_IFDIR, uid, gid, mtime, NULL);

	if (f2fs_add_link(sbi, parent, child)) {
		MSG(0, "Link fail.\n");
        ino = -1;
        goto free_child_dir;
	}

	/* Update parent's i_links info*/
    parent->i.i_links += 1;

	set_new_dnode(&dn, child, NULL, ino);
	node_blk = allocate_data_block(sbi, &dn, child, CURSEG_HOT_NODE);

	ret = dev_write_block(child, node_blk); /* Write the child inode info */
    if (ret < 0) {
        ERR_MSG("\tError: Fail to Write block\n");
        ino = -1;
        goto free_child_dir;
    }
	update_nat(sbi, ino, ino, node_blk); /* Update the child inode nat info */

	/* After f2fs_add_link, parent may be changed, so update it */
	ret = dev_write_block(parent, ni.blk_addr);
    if (ret < 0) {
        ERR_MSG("\tError: Fail to Write block\n");
        ino = -1;
        goto free_child_dir;
    }
free_child_dir:
	free(child);
free_parent_dir:
	free(parent);
	return ino;
}

int f2fs_create(struct f2fs_sb_info *sbi, nid_t pino, umode_t mode,
                const char *name, int len, u16 uid, u16 gid, u32 mtime)
{
    nid_t ino;
    block_t node_blk;
    struct dnode_of_data dn;
    struct f2fs_node *child, *parent;
    struct node_info ni;
	int ret;

    get_node_info(sbi, pino, &ni);
    parent = calloc(BLOCK_SZ, 1);
    if (parent == NULL) {
        ERR_MSG("\tError: Calloc Failed!\n");
	    return -1;
    }

    ret = dev_read_block(parent, ni.blk_addr);
    if (ret < 0) {
        ERR_MSG("\tError: Fail to Read block\n");
        ino = -1;
        goto free_parent_reg;
    }

	ret = f2fs_find_entry(sbi, parent, name, len);
    if (ret != 0) {
		ino = -1;
		goto free_parent_reg;
    }

    f2fs_alloc_nid(sbi, &ino, 1);
    child = calloc(BLOCK_SZ, 1);
    if (child == NULL) {
        ERR_MSG("\tError: Calloc Failed!\n");
        ino = -1;
        goto free_parent_reg;
    }
    init_inode_page(sbi, child, ino, parent->footer.ino,
                    name, len, mode | S_IFREG, uid, gid, mtime, NULL);

    if (f2fs_add_link(sbi, parent, child)) {
        ERR_MSG("Link fail.\n");
		ino = -1;
        goto free_child_reg;
    }

    set_new_dnode(&dn, child, NULL, ino);
    node_blk = allocate_data_block(sbi, &dn, child, CURSEG_WARM_NODE);

    ret = dev_write_block(child, node_blk);
    if (ret < 0) {
        ERR_MSG("\tError: Fail to Write block\n");
        ino = -1;
        goto free_child_reg;
    }

    update_nat(sbi, ino, ino, node_blk);

    ret = dev_write_block(parent, ni.blk_addr);
    if (ret < 0) {
        ERR_MSG("\tError: Fail to Write block\n");
        ino = -1;
        goto free_child_reg;
    }

free_child_reg:
    free(child);
free_parent_reg:
    free(parent);
    return ino;
}

int f2fs_symlink(struct f2fs_sb_info *sbi, nid_t pino, umode_t mode,
                const char *name, int len, u16 uid, u16 gid,
				u32 mtime, const char *symname)
{
    nid_t ino;
    block_t node_blk;
    struct dnode_of_data dn;
    struct f2fs_node *child, *parent;
    struct node_info ni;
	int ret;

    get_node_info(sbi, pino, &ni);
    parent = calloc(BLOCK_SZ, 1);
	if (parent == NULL) {
		ERR_MSG("\tError: Calloc Failed!\n");
		return -1;
	}

    ret = dev_read_block(parent, ni.blk_addr);
	if (ret < 0) {
		ERR_MSG("\tError: Fail to Read block\n");
		ino = -1;
		goto free_parent_lnk;
	}

	ret = f2fs_find_entry(sbi, parent, name, len);
    if (ret != 0) {
		ino = -1;
		goto free_parent_lnk;
    }

    f2fs_alloc_nid(sbi, &ino, 1);
    child = calloc(BLOCK_SZ, 1);
	if (child == NULL) {
		ERR_MSG("\tError: Calloc Failed!\n");
		ino = -1;
		goto free_parent_lnk;
	}
    init_inode_page(sbi, child, ino, parent->footer.ino,
                    name, len, mode | S_IFLNK, uid, gid, mtime, symname);

    if (f2fs_add_link(sbi, parent, child)) {
        ERR_MSG("Link fail.\n");
		ino = -1;
		goto free_child_lnk;
    }

    set_new_dnode(&dn, child, NULL, ino);
    node_blk = allocate_data_block(sbi, &dn, child, CURSEG_WARM_NODE);

    ret = dev_write_block(child, node_blk);
    if (ret < 0) {
        ERR_MSG("\tError: Fail to Write block\n");
		ino = -1;
        goto free_child_lnk;
    }

    update_nat(sbi, ino, ino, node_blk);

    ret = dev_write_block(parent, ni.blk_addr);
    if (ret < 0) {
        ERR_MSG("\tError: Fail to Write block\n");
		ino = -1;
        goto free_child_lnk;
    }

free_child_lnk:
    free(child);
free_parent_lnk:
    free(parent);
    return ino;
}
